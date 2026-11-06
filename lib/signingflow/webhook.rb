# frozen_string_literal: true

require "json"
require "openssl"

module Signingflow
  module Webhook
    Result = Data.define(:payload, :body_sha256)

    module_function

    def construct_event(payload, signature, secret, previous_secret: nil, previous_signature: nil)
      body = raw_bytes(payload)
      raise SignatureVerificationError, "Webhook secret is required." if secret.to_s.empty?

      current = !signature.to_s.empty? && safe_equal?(signature, mac(secret, body))
      previous = !previous_secret.to_s.empty? && !previous_signature.to_s.empty? &&
                 safe_equal?(previous_signature, mac(previous_secret, body))
      raise SignatureVerificationError, "Webhook signature did not match." unless current || previous

      parsed = JSON.parse(body)
      Result.new(payload: parsed, body_sha256: OpenSSL::Digest::SHA256.hexdigest(body))
    rescue JSON::ParserError
      raise InvalidRequestError, "The webhook body is not JSON."
    end

    def raw_bytes(payload)
      return payload.b if payload.is_a?(String)
      raise SignatureVerificationError, "Pass the raw request body."
    end

    def mac(secret, body)
      OpenSSL::HMAC.hexdigest("SHA256", secret.to_s, body)
    end

    def safe_equal?(left, right)
      a = left.to_s.downcase.b
      b = right.to_s.downcase.b
      if a.bytesize != b.bytesize
        OpenSSL.fixed_length_secure_compare(a, a)
        return false
      end
      OpenSSL.fixed_length_secure_compare(a, b)
    end
  end
end
