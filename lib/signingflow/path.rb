# frozen_string_literal: true

require "cgi"
require "uri"

module Signingflow
  module Path
    SEGMENT = /\A[A-Za-z0-9_-]+\z/
    MAX_DELAY_MS = 60_000

    module_function

    def fill(template, params)
      template.gsub(/\{([^}]+)\}/) do
        token = Regexp.last_match(1)
        name = token.split("=").first.to_s
        short = name.split(".").last.to_s
        value = params[name].to_s
        value = params[short].to_s if value.empty?
        value = params["name"].to_s if value.empty? && (short == "name" || short.start_with?("name_"))
        raise InvalidRequestError, "missing path param #{short}" if value.empty?

        segments = value.split("/")
        if segments.empty? || segments.any? { |segment| !SEGMENT.match?(segment) }
          raise InvalidRequestError, "invalid path param #{short}"
        end
        segments.map { |segment| CGI.escape(segment).gsub("+", "%20") }.join("/")
      end
    end

    def resolve(base_url, path, query = nil)
      base = base_url.end_with?("/") ? base_url : "#{base_url}/"
      uri = URI.join(base, path)
      origin = URI(base)
      raise InvalidRequestError, "invalid path" if uri.scheme != origin.scheme || uri.host != origin.host

      parts = []
      (query || {}).each do |key, value|
        next if value.nil? || value.to_s.empty?

        parts << "#{CGI.escape(key.to_s)}=#{CGI.escape(value.to_s)}"
      end
      uri.query = parts.join("&") unless parts.empty?
      uri
    end

    # A raw substring misses a key once CGI.escape percent-encodes it.
    def query_contains_secret(raw_query, secret)
      query = raw_query.to_s.sub(/\A\?/, "")
      key = secret.to_s
      return false if key.empty? || query.empty?
      escaped = CGI.escape(key)
      return true if query.include?(key) || query.include?(escaped)
      return true if broken_percent?(query)

      URI.decode_www_form(query).any? { |_name, value| value.include?(key) }
    rescue ArgumentError
      true
    end

    def broken_percent?(query)
      index = 0
      while index < query.length
        unless query[index] == "%"
          index += 1
          next
        end
        digits = query[index + 1, 2].to_s
        return true if digits.length < 2 || digits.match?(/[^0-9a-f]/i)

        index += 3
      end
      false
    end

    def allowed_upload_url(raw, hosts)
      begin
        uri = URI.parse(raw)
      rescue URI::InvalidURIError
        raise Error, "upload url rejected"
      end
      raise Error, "upload url rejected" if uri.host.nil?
      raise Error, "upload url must be https" unless uri.scheme == "https"
      raise Error, "upload url rejected" if uri.user || uri.password

      host = uri.host.downcase
      allowed = hosts.any? { |item| host == item || host.end_with?(".#{item}") }
      raise Error, "upload host rejected" unless allowed

      uri
    end

    def retry_delay_ms(retry_after, reset_after, now_ms = (Time.now.to_r * 1000).round)
      when_ms = parse_time(retry_after) || parse_time(reset_after)
      return 0 if when_ms.nil?

      [[when_ms - now_ms, 0].max, MAX_DELAY_MS].min
    end

    def parse_time(value)
      text = value.to_s.strip
      return nil if text.empty?

      parsed = Time.iso8601(text)
      (parsed.to_r * 1000).round
    rescue ArgumentError
      nil
    end
  end
end
