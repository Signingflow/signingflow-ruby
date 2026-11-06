# frozen_string_literal: true

module Signingflow
  module Redact
    SECRET_KEY = /df_sk_[A-Za-z0-9_-]+/
    BEARER = /Bearer\s+\S+/i
    SIGNED_QUERY = /([?&](?:X-Goog-Signature|Signature|sig|token)=)[^&\s"]+/i

    module_function

    def redact(value)
      value.to_s
           .gsub(SECRET_KEY, "df_sk_redacted")
           .gsub(BEARER, "Bearer [redacted]")
           .gsub(SIGNED_QUERY, "\\1[redacted]")
    end

    def message(value, limit = 500)
      cleaned = redact(value)
      cleaned.length > limit ? "#{cleaned[0, limit]}…" : cleaned
    end

    def violations(list)
      return nil if list.nil?

      list.map do |item|
        { "field" => message(item["field"]), "description" => message(item["description"]) }
      end
    end
  end
end
