# frozen_string_literal: true

require "json"
require "net/http"
require "securerandom"

module Signingflow
  class Requestor
    MAX_RESPONSE_BYTES = 8 * 1024 * 1024
    UUID = /\A[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\z/i

    def initialize(config)
      @config = config
    end

    def call(operation:, path_params: nil, query: nil, body: nil, idempotency_key: nil)
      key = operation["idempotent"] ? key_for(idempotency_key, body) : nil
      payload = operation["http"] == "GET" ? nil : (body || {}).dup
      payload["idempotencyKey"] = key if payload && key
      begin
        path = Path.fill(operation["path"], path_params || {})
        uri = Path.resolve(@config.base_url, path, query)
      rescue InvalidRequestError => e
        raise InvalidRequestError.new(e.message, idempotency_key: key)
      end
      if uri.query.to_s.include?(@config.api_key)
        raise InvalidRequestError.new("The API key must not be sent in the query string.", idempotency_key: key)
      end

      retries = operation["http"] == "GET" || operation["idempotent"] ? @config.max_network_retries : 0
      attempt = 0
      loop do
        begin
          response = once(uri, operation["http"], payload)
          status = response.code.to_i
          return parse_success(response) if status >= 200 && status < 300
          if attempt < retries && retryable_status?(status)
            attempt += 1
            sleep_ms(Path.retry_delay_ms(response["rate-limit-retry-after"], response["rate-limit-reset-after"]))
            next
          end
          raise failure(response, operation["capability"], key)
        rescue Error
          raise
        rescue StandardError => e
          if attempt < retries
            attempt += 1
            next
          end
          aborted = timeout_error?(e)
          raise ConnectionError.new(
            aborted ? "The API timed out." : "The API could not be reached.",
            status_code: aborted ? 408 : 0,
            idempotency_key: key
          )
        end
      end
    end

    def put_bytes(uri, bytes, content_type)
      retries = @config.max_network_retries
      attempt = 0
      loop do
        begin
          response = perform(uri, "PUT", bytes, {
            "Content-Type" => content_type,
            "x-goog-if-generation-match" => "0"
          })
          status = response.code.to_i
          return if (status >= 200 && status < 300) || status == 412
          if attempt < retries && status >= 500
            attempt += 1
            next
          end
          raise APIError.new("Uploading the file to storage failed.", status_code: status)
        rescue Error
          raise
        rescue StandardError
          if attempt < retries
            attempt += 1
            next
          end
          raise ConnectionError.new("The upload could not be reached.", status_code: 0)
        end
      end
    end

    def self.assemble(status:, content_length:, chunks:)
      if content_length.is_a?(Numeric) && content_length > MAX_RESPONSE_BYTES
        raise APIError.new("The API response is larger than 8 MB.", status_code: status)
      end

      consume(status: status, chunks: chunks)
    end

    def self.sleep_ms(ms)
      return if ms <= 0

      Kernel.sleep(ms / 1000.0)
    end

    private

    def sleep_ms(ms)
      self.class.sleep_ms(ms)
    end

    def key_for(supplied, body)
      raw = supplied.to_s.strip
      raw = body["idempotencyKey"].to_s.strip if raw.empty? && body.is_a?(Hash)
      return SecureRandom.uuid if raw.empty?
      raise InvalidRequestError, "idempotencyKey must be a UUID." unless UUID.match?(raw)

      raw
    end

    def once(uri, method, payload)
      headers = {
        "Authorization" => "Bearer #{@config.api_key}",
        "X-Request-Workspace-Id" => @config.workspace_id,
        "X-Request-Env" => @config.env,
        "X-Request-Source" => @config.source,
        "Accept" => "application/json",
        "User-Agent" => @config.source
      }
      headers["X-Request-Channel"] = @config.channel if @config.channel
      headers["X-Request-Funnel"] = @config.funnel if @config.funnel
      headers["Content-Type"] = "application/json" unless method == "GET"
      body = method == "GET" ? nil : JSON.generate(payload || {})
      perform(uri, method, body, headers)
    end

    def perform(uri, method, body, headers)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      timeout = @config.timeout / 1000.0
      http.open_timeout = timeout
      http.read_timeout = timeout
      http.write_timeout = timeout if http.respond_to?(:write_timeout=)
      http.max_retries = 0
      # Pass Accept-Encoding in the constructor so Net::HTTP leaves
      # decode_content false and does not inflate gzip before the cap.
      request = request_class(method).new(uri, headers.merge("Accept-Encoding" => "identity"))
      request.body = body unless body.nil?
      http.request(request) do |response|
        response.body = read_capped(response)
      end
    end

    def request_class(method)
      case method
      when "GET" then Net::HTTP::Get
      when "POST" then Net::HTTP::Post
      when "PATCH" then Net::HTTP::Patch
      when "PUT" then Net::HTTP::Put
      else
        raise InvalidRequestError, "invalid path"
      end
    end

    def parse_success(response)
      type = response["content-type"].to_s
      text = response.body.to_s
      return {} if text.empty?
      if !type.empty? && !type.include?("json") && !type.include?("text/")
        raise APIError.new("The API returned a non-JSON body.", status_code: response.code.to_i)
      end

      JSON.parse(text)
    rescue JSON::ParserError
      raise APIError.new("The API returned invalid JSON.", status_code: response.code.to_i)
    end

    def failure(response, capability, idempotency_key)
      text = response.body.to_s
      parsed = text
      if !text.empty?
        begin
          parsed = JSON.parse(text)
        rescue JSON::ParserError
          parsed = text
        end
      end
      message = Redact.message(Status.server_message(parsed).empty? ? (text.empty? ? "Request failed with status #{response.code}." : text) : Status.server_message(parsed))
      fields = {
        status_code: response.code.to_i,
        grpc_code: Status.grpc_code(parsed),
        trace_code: Status.trace_code(parsed),
        request_id: response["x-request-id"],
        idempotency_key: idempotency_key,
        capability: capability,
        field_violations: Redact.violations(Status.field_violations(parsed)),
        retry_after: response["rate-limit-retry-after"] || response["rate-limit-reset-after"]
      }
      status = response.code.to_i
      return AuthenticationError.new(message, **fields) if status == 401
      return PermissionError.new(message, **fields) if status == 403
      if status == 409 && Status.mentions_idempotency?(parsed)
        return IdempotencyError.new(message, **fields, resource_name: Status.resource_name(parsed))
      end
      return RateLimitError.new(message, **fields) if status == 429
      return InvalidRequestError.new(message, **fields) if status >= 400 && status < 500

      APIError.new(message, **fields)
    end

    def read_capped(response)
      declared = response["content-length"]
      length = declared.nil? || declared.to_s.empty? ? nil : Integer(declared, exception: false)
      if length && length > MAX_RESPONSE_BYTES
        raise APIError.new("The API response is larger than 8 MB.", status_code: response.code.to_i)
      end

      self.class.consume(status: response.code.to_i, chunks: body_chunks(response))
    end

    def body_chunks(response)
      Enumerator.new do |yielder|
        response.read_body { |chunk| yielder << chunk }
      end
    end

    def self.consume(status:, chunks:)
      body = +""
      body.force_encoding(Encoding::ASCII_8BIT)
      chunks.each do |chunk|
        next if chunk.nil? || chunk.bytesize.zero?

        if body.bytesize + chunk.bytesize > MAX_RESPONSE_BYTES
          raise APIError.new("The API response is larger than 8 MB.", status_code: status)
        end

        body << chunk
      end
      body.force_encoding(Encoding::UTF_8)
    end

    def retryable_status?(status)
      status == 408 || status == 429 || status >= 500
    end

    def timeout_error?(error)
      error.is_a?(Net::OpenTimeout) || error.is_a?(Net::ReadTimeout) || error.is_a?(Timeout::Error)
    end
  end
end
