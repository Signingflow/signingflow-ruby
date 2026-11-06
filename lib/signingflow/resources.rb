# frozen_string_literal: true

require "securerandom"

module Signingflow
  module Resources
    UUID_BODY = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    UUID = /\A#{UUID_BODY}\z/i
    ENVELOPE = /\Aenvelopes\/#{UUID_BODY}\z/i
    TEMPLATE = /\Atemplates\/#{UUID_BODY}\z/i
    WEBHOOK_URL = /\AwebhookUrls\/#{UUID_BODY}\z/i
    DELIVERY = /\Awebhooks\/#{UUID_BODY}\z/i
    EMAIL = /\A[^\s@]+@[^\s@]+\z/
    MAX_UPLOAD_BYTES = 25 * 1024 * 1024
    SEND_RECOVERY_WINDOW_MS = 120_000
    SEND_RECOVERY_SKEW_MS = 60_000
    MIME = {
      "pdf" => "application/pdf",
      "png" => "image/png",
      "jpg" => "image/jpeg",
      "jpeg" => "image/jpeg",
      "txt" => "text/plain",
      "json" => "application/json"
    }.freeze

    module PageSize
      module_function

      def of(value)
        size = value.nil? ? 10 : value
        unless size.is_a?(Integer) && size.between?(1, 1000)
          raise InvalidRequestError, "pageSize must be a whole number from 1 to 1000."
        end
        size
      end
    end

    class Files
      def initialize(requestor, config)
        @requestor = requestor
        @config = config
      end

      def create(file: nil, path: nil, filename: nil, mime_type: nil, idempotency_key: nil)
        loaded = load_file(file: file, path: path, filename: filename, mime_type: mime_type)
        added = @requestor.call(
          operation: Signingflow.operation("StorageService_BatchAddStorage"),
          idempotency_key: idempotency_key,
          body: {
            "storages" => [{
              "originalName" => loaded[:filename],
              "displayName" => loaded[:filename],
              "size" => loaded[:bytes].bytesize.to_s,
              "extension" => loaded[:extension],
              "mimeType" => loaded[:mime_type]
            }]
          }
        )
        storage = find_storage(added)
        raise APIError, "Storage did not return an upload URL." unless storage

        begin
          upload_url = Path.allowed_upload_url(storage[:url], @config.upload_hosts)
        rescue Error => e
          raise InvalidRequestError, e.message
        end
        @requestor.put_bytes(upload_url, loaded[:bytes], loaded[:mime_type])
        @requestor.call(
          operation: Signingflow.operation("StorageService_BatchAcknowledgeUpload"),
          body: { "names" => [storage[:name]] }
        )
        ResourceObject.new("name" => storage[:name], "id" => storage[:id])
      end

      private

      def load_file(file:, path:, filename:, mime_type:)
        raise InvalidRequestError, "Pass file bytes or a path, not both." if !file.nil? && !path.nil?

        bytes = if path
                  read_bytes(path)
                elsif file
                  raise InvalidRequestError, "file must be the raw bytes." unless file.is_a?(String)
                  file.b
                else
                  raise InvalidRequestError, "file is required."
                end
        raise InvalidRequestError, "The file is larger than 25 MB." if bytes.bytesize > MAX_UPLOAD_BYTES

        name = filename.to_s.strip
        name = File.basename(path.to_s) if name.empty? && path
        raise InvalidRequestError, "filename is required when file is not a path." if name.empty?

        extension = File.extname(name).sub(/\A\./, "").downcase
        type = mime_type.to_s.strip
        type = MIME[extension] || "application/octet-stream" if type.empty?
        { bytes: bytes, filename: name, extension: extension, mime_type: type }
      end

      def read_bytes(path)
        raise InvalidRequestError, "A filesystem path requires upload_root." if @config.upload_root.nil?

        begin
          Jail.read(@config.upload_root, path, MAX_UPLOAD_BYTES)
        rescue Error => e
          case e.message
          when "too large" then raise InvalidRequestError, "The file is larger than 25 MB."
          when "outside root" then raise InvalidRequestError, "The path is outside upload_root."
          when "hard link" then raise InvalidRequestError, "The file must not be a hard link."
          else raise InvalidRequestError, "The file could not be read."
          end
        rescue StandardError
          raise InvalidRequestError, "The file could not be read."
        end
      end

      def find_storage(body)
        found = []
        walk_storage(body, found)
        found.first
      end

      def walk_storage(value, found)
        return unless value.is_a?(Hash) || value.is_a?(Array)

        if value.is_a?(Array)
          value.each { |item| walk_storage(item, found) }
          return
        end

        url = text(value["pre_signed_url"]).empty? ? text(value["preSignedUrl"]) : text(value["pre_signed_url"])
        name = text(value["name"])
        id = name.split("/").last.to_s
        found << { name: name, id: id, url: url } if name.start_with?("storages/") && UUID.match?(id) && !url.empty?
        value.each_value { |child| walk_storage(child, found) }
      end

      def text(value)
        value.is_a?(String) ? value : ""
      end
    end

    class Templates
      def initialize(requestor)
        @requestor = requestor
      end

      def use(name, idempotency_key: nil)
        template = require_template(name)
        used = @requestor.call(
          operation: Signingflow.operation("TemplateService_UseTemplate"),
          path_params: { "name" => template },
          idempotency_key: idempotency_key,
          body: {}
        )
        ResourceObject.new(created_envelope(used))
      end
    end

    class Envelopes
      def initialize(requestor, files, templates)
        @requestor = requestor
        @files = files
        @templates = templates
      end

      def create(display_name:, storage_id:, description: nil, idempotency_key: nil)
        title = display_name.to_s.strip
        raise InvalidRequestError, "Name the draft title." if title.empty?
        raise InvalidRequestError, "storage_id is required." if storage_id.to_s.strip.empty?

        created = @requestor.call(
          operation: Signingflow.operation("EnvelopeService_AddEnvelope"),
          idempotency_key: idempotency_key,
          body: {
            "envelope" => {
              "display_name" => title,
              "description" => description.to_s.strip,
              "documents" => [{
                "display_name" => title,
                "attachments" => [{ "storage_id" => storage_id.to_s.strip }],
                "supplemental" => false
              }]
            }
          }
        )
        ResourceObject.new(created_envelope(created))
      end

      def retrieve(name, read_mask: nil)
        ResourceObject.new(retrieve_hash(name, read_mask: read_mask))
      end

      def update(name, body)
        envelope = require_envelope(name)
        payload = stringify(body)
        payload["name"] = text(payload["name"]).empty? ? envelope : text(payload["name"])
        ResourceObject.new(unwrap_envelope(@requestor.call(
          operation: Signingflow.operation("EnvelopeService_UpdateEnvelope"),
          path_params: { "name" => envelope },
          body: payload
        )))
      end

      def send(name, idempotency_key: nil)
        envelope = require_envelope(name)
        sent = unwrap_envelope(@requestor.call(
          operation: Signingflow.operation("EnvelopeService_SendEnvelope"),
          path_params: { "name" => envelope },
          idempotency_key: idempotency_key,
          body: {}
        ))
        sent["name"] = envelope if text(sent["name"]).empty?
        ResourceObject.new(sent)
      end

      def list(directory:, page_size: nil, page_token: nil, read_mask: nil)
        folder = directory.to_s.strip
        raise InvalidRequestError, "directory is required." if folder.empty?

        size = PageSize.of(page_size)
        loader = lambda do |token|
          page = list_page(directory: folder, page_size: size, page_token: token, read_mask: read_mask)
          List.new(data: page[:data], next_page_token: page[:next_page_token], loader: nil)
        end
        first = list_page(directory: folder, page_size: size, page_token: page_token, read_mask: read_mask)
        List.new(data: first[:data], next_page_token: first[:next_page_token], loader: loader)
      end

      def remind(name)
        envelope = require_envelope(name)
        reminded = unwrap_envelope(@requestor.call(
          operation: Signingflow.operation("EnvelopeService_RemindEnvelopeSigners"),
          path_params: { "name" => envelope },
          body: {}
        ))
        reminded["name"] = envelope if text(reminded["name"]).empty?
        ResourceObject.new(reminded)
      end

      def download(name)
        envelope = require_envelope(name)
        downloaded = @requestor.call(
          operation: Signingflow.operation("EnvelopeService_DownloadEnvelope"),
          path_params: { "name" => envelope }
        )
        ResourceObject.new(
          "uri" => text(downloaded["uri"]),
          "download_time" => text(downloaded["download_time"]).empty? ? text(downloaded["downloadTime"]) : text(downloaded["download_time"]),
          "etag" => text(downloaded["etag"])
        )
      end

      def prepare_draft(title:, file: nil, path: nil, message: nil, filename: nil)
        heading = title.to_s.strip
        raise InvalidRequestError, "Name the PDF and the draft title." if heading.empty?

        stored = @files.create(file: file, path: path, filename: filename)
        create(display_name: heading, description: message, storage_id: stored.id)
      end

      def send_document(title:, recipients:, file: nil, path: nil, message: nil, filename: nil)
        heading = title.to_s.strip
        raise InvalidRequestError, "Name the PDF, the title, and the recipients." if heading.empty?

        people = clean_recipients(recipients)
        stored = @files.create(file: file, path: path, filename: filename)
        created = create(display_name: heading, description: message, storage_id: stored.id)
        ResourceObject.new(finish_send(created.to_h, people, message, heading))
      end

      def send_from_template(template:, recipients:, message: nil)
        name = require_template(template)
        people = clean_recipients(recipients)
        created = @templates.use(name)
        ResourceObject.new(finish_send(created.to_h, people, message, name))
      end

      def download_completed(name)
        envelope = require_envelope(name)
        viewed = retrieve_hash(envelope)
        unless envelope_state(viewed).strip.upcase == "COMPLETED"
          raise InvalidRequestError.new("The signed file is not ready.", envelope_name: envelope)
        end

        download(envelope)
      end

      private

      def retrieve_hash(name, read_mask: nil)
        envelope = require_envelope(name)
        viewed = unwrap_envelope(@requestor.call(
          operation: Signingflow.operation("EnvelopeService_ViewEnvelope"),
          path_params: { "name" => envelope },
          query: { "readMask" => read_mask }
        ))
        viewed["name"] = envelope if text(viewed["name"]).empty?
        viewed
      end

      def list_page(directory:, page_size:, page_token:, read_mask:)
        body = @requestor.call(
          operation: Signingflow.operation("EnvelopeService_ListEnvelopes"),
          path_params: { "parent" => "envelopes" },
          query: {
            "directory" => directory,
            "pageSize" => page_size.to_s,
            "pageToken" => page_token,
            "readMask" => read_mask
          }
        )
        { data: list_items(body, "envelopes"), next_page_token: next_token(body) }
      end

      def finish_send(created, people, message, label)
        name = text(created["name"])
        raise APIError, "#{label} was saved without an envelope name." unless envelope_name?(name)

        begin
          viewed = retrieve_hash(name, read_mask: "documents,compliance")
          patched = with_recipients(viewed, people, message)
          raise InvalidRequestError.new("The draft has no document to address.", envelope_name: name) unless patched

          update(name, patched)
          send_or_view(name)
        rescue StandardError => e
          Error.attach_envelope(e, name)
        end
      end

      def send_or_view(name)
        started = now_ms
        send(name).to_h
      rescue IdempotencyError => e
        if e.resource_name == name
          begin
            return retrieve_hash(name)
          rescue StandardError
            Error.attach_envelope(e, name)
          end
        end
        Error.attach_envelope(e, name)
      rescue ConnectionError => e
        begin
          viewed = retrieve_hash(name)
          sent = sent_millis(viewed)
          return viewed if sent && sent_during?(sent, started, now_ms)
        rescue StandardError
          Error.attach_envelope(e, name)
        end
        Error.attach_envelope(e, name)
      rescue Error => e
        Error.attach_envelope(e, name)
      end

      def with_recipients(envelope, people, message)
        documents = envelope["documents"].is_a?(Array) ? envelope["documents"] : []
        refs = documents.filter_map do |item|
          next unless item.is_a?(Hash)

          uid = text(item["uid"]).empty? ? text(item["id"]) : text(item["uid"])
          next if uid.empty?

          { "uid" => uid, "display_name" => text(item["display_name"]).empty? ? text(item["displayName"]) : text(item["display_name"]) }
        end
        return nil if refs.empty?

        participants = people.each_with_index.map do |person, index|
          {
            "uid" => SecureRandom.uuid,
            "display_name" => person["name"],
            "alternate_email" => person["email"],
            "role" => "SIGNER",
            "type" => "PERSONAL",
            "action_order_type" => "SERIAL",
            "action_order_number" => index + 1
          }
        end
        compliance = envelope["compliance"].is_a?(Hash) ? envelope["compliance"] : nil
        profile = compliance && !text(compliance["profile"]).empty? ? text(compliance["profile"]) : "STANDARD"
        {
          "name" => text(envelope["name"]),
          "display_name" => text(envelope["display_name"]).empty? ? text(envelope["displayName"]) : text(envelope["display_name"]),
          "description" => message.to_s.strip.empty? ? text(envelope["description"]) : message.to_s.strip,
          "compliance" => { "profile" => profile },
          "documents" => refs.each_with_index.map { |document, index|
            row = { "uid" => document["uid"], "display_name" => document["display_name"] }
            row["participants"] = participants if index.zero?
            row
          }
        }
      end

      def sent_during?(sent, started, now)
        sent >= started && sent <= started + SEND_RECOVERY_WINDOW_MS && sent <= now + SEND_RECOVERY_SKEW_MS
      end

      def now_ms
        (Time.now.to_r * 1000).round
      end
    end

    class WebhookUrls
      def initialize(requestor)
        @requestor = requestor
      end

      def create(display_name:, http_request_uri:, events:, idempotency_key: nil, http_config: nil)
        label = display_name.to_s.strip
        raise InvalidRequestError, "displayName must be 1 to 100 characters." if label.empty? || label.length > 100

        begin
          uri = URI.parse(http_request_uri.to_s)
        rescue URI::InvalidURIError
          raise InvalidRequestError, "httpRequestUri must be an https URL."
        end
        raise InvalidRequestError, "httpRequestUri must be an https URL." unless uri.is_a?(URI::HTTPS)
        raise InvalidRequestError, "events is required." if !events.is_a?(Array) || events.empty?

        auth = http_config.is_a?(Hash) ? (http_config[:auth] || http_config["auth"]).to_s : ""
        if auth.upcase == "NONE"
          raise InvalidRequestError, "auth NONE has no signature. Leave http_config empty."
        end
        raise InvalidRequestError, "Leave http_config empty so the destination uses HMAC." if http_config

        ResourceObject.new(@requestor.call(
          operation: Signingflow.operation("WebhookUrlService_AddWebhookUrl"),
          idempotency_key: idempotency_key,
          body: {
            "webhookUrl" => {
              "displayName" => label,
              "httpRequestUri" => http_request_uri,
              "events" => events
            }
          }
        ))
      end

      def retrieve(name)
        destination = require_name(name, WEBHOOK_URL, "webhook url must look like webhookUrls/{id}.")
        viewed = @requestor.call(
          operation: Signingflow.operation("WebhookUrlService_ViewWebhookUrl"),
          path_params: { "name" => destination }
        )
        record = viewed.is_a?(Hash) ? viewed.dup : {}
        record.delete("signing_secret")
        record.delete("signingSecret")
        ResourceObject.new(record)
      end

      def test(name)
        destination = require_name(name, WEBHOOK_URL, "webhook url must look like webhookUrls/{id}.")
        ResourceObject.new(@requestor.call(
          operation: Signingflow.operation("WebhookUrlService_TestWebhookUrl"),
          path_params: { "name" => destination },
          body: {}
        ))
      end
    end

    class WebhookDeliveries
      def initialize(requestor)
        @requestor = requestor
      end

      def list(page_size: nil, page_token: nil)
        size = PageSize.of(page_size)
        loader = lambda do |token|
          page = list_page(size, token)
          List.new(data: page[:data], next_page_token: page[:next_page_token], loader: nil)
        end
        first = list_page(size, page_token)
        List.new(data: first[:data], next_page_token: first[:next_page_token], loader: loader)
      end

      def retrieve(name)
        delivery = require_name(name, DELIVERY, "webhook delivery must look like webhooks/{id}.")
        ResourceObject.new(@requestor.call(
          operation: Signingflow.operation("WebhookService_ViewWebhook"),
          path_params: { "name" => delivery }
        ))
      end

      private

      def list_page(page_size, page_token)
        body = @requestor.call(
          operation: Signingflow.operation("WebhookService_ListWebhooks"),
          path_params: { "parent" => "webhooks" },
          query: { "pageSize" => page_size.to_s, "pageToken" => page_token }
        )
        { data: list_items(body, "webhooks"), next_page_token: next_token(body) }
      end
    end

    module_function

    def require_envelope(name)
      trimmed = name.to_s.strip
      raise InvalidRequestError, "envelope must look like envelopes/{id}." unless ENVELOPE.match?(trimmed)

      trimmed
    end

    def require_template(name)
      trimmed = name.to_s.strip
      raise InvalidRequestError, "template must look like templates/{id}." unless TEMPLATE.match?(trimmed)

      trimmed
    end

    def require_name(name, pattern, message)
      trimmed = name.to_s.strip
      raise InvalidRequestError, message unless pattern.match?(trimmed)

      trimmed
    end

    def envelope_name?(name)
      ENVELOPE.match?(name.to_s)
    end

    def clean_recipients(recipients)
      people = Array(recipients).map do |person|
        source = person.is_a?(Hash) ? person : {}
        {
          "name" => (source["name"] || source[:name]).to_s.strip,
          "email" => (source["email"] || source[:email]).to_s.strip
        }
      end
      if people.empty? || people.any? { |person| person["name"].empty? || !EMAIL.match?(person["email"]) }
        raise InvalidRequestError, "Each recipient needs a name and an email."
      end
      people
    end

    def envelope_name_of(body)
      record = body.is_a?(Hash) ? body : nil
      return "" unless record

      nested = record["envelope"].is_a?(Hash) ? record["envelope"] : nil
      name = text(nested && nested["name"]).empty? ? text(record["name"]) : text(nested["name"])
      return name if name.start_with?("envelopes/")

      uid = text(nested && nested["uid"]).empty? ? text(record["uid"]) : text(nested["uid"])
      uid.empty? ? "" : "envelopes/#{uid}"
    end

    def unwrap_envelope(body)
      return {} unless body.is_a?(Hash)

      nested = body["envelope"]
      (nested.is_a?(Hash) ? nested : body).dup
    end

    def created_envelope(body)
      unwrapped = unwrap_envelope(body)
      name = envelope_name_of(body)
      name = text(unwrapped["name"]) if name.empty?
      unwrapped["name"] = name unless name.empty?
      unwrapped
    end

    def envelope_state(envelope)
      progress = envelope["progress"].is_a?(Hash) ? envelope["progress"] : nil
      from_progress = text(progress && progress["state"])
      return from_progress unless from_progress.empty?

      [envelope["progress_status"], envelope["progressStatus"], envelope["state"], envelope["condition"]].each do |value|
        return value if value.is_a?(String) && !value.empty?
      end
      ""
    end

    def sent_millis(envelope)
      time_of(envelope["sent_time"]) || time_of(envelope["sentTime"])
    end

    def time_of(value)
      return nil unless value.is_a?(String) && !value.strip.empty?

      (Time.iso8601(value).to_r * 1000).round
    rescue ArgumentError
      nil
    end

    def text(value)
      value.is_a?(String) ? value : ""
    end

    def stringify(body)
      return {} unless body.is_a?(Hash)

      body.each_with_object({}) do |(key, value), copy|
        copy[key.to_s] = value.is_a?(Hash) ? stringify(value) : value
      end
    end

    def list_items(body, key)
      list = body.is_a?(Hash) ? body[key] : nil
      return [] unless list.is_a?(Array)

      list.filter_map { |item| ResourceObject.new(item) if item.is_a?(Hash) }
    end

    def next_token(body)
      return nil unless body.is_a?(Hash)

      value = body["next_page_token"] || body["nextPageToken"]
      value.is_a?(String) && !value.empty? ? value : nil
    end

    def signing_secret_of(body)
      return "" unless body.is_a?(Hash) || body.is_a?(ResourceObject)

      record = body.is_a?(ResourceObject) ? body.to_h : body
      secret = text(record["signing_secret"])
      secret.empty? ? text(record["signingSecret"]) : secret
    end

    [Files, Templates, Envelopes, WebhookUrls, WebhookDeliveries].each { |klass| klass.include self }
  end
end
