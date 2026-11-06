# frozen_string_literal: true

module Signingflow
  class Error < StandardError
    attr_reader :status_code, :grpc_code, :trace_code, :request_id, :idempotency_key,
                :capability, :resource_name, :retry_after, :field_violations
    attr_accessor :envelope_name

    def initialize(message = nil, status_code: nil, grpc_code: nil, trace_code: nil, request_id: nil,
                   idempotency_key: nil, capability: nil, resource_name: nil, envelope_name: nil,
                   retry_after: nil, field_violations: nil)
      super(message)
      @status_code = status_code
      @grpc_code = grpc_code
      @trace_code = trace_code
      @request_id = request_id
      @idempotency_key = idempotency_key
      @capability = capability
      @resource_name = resource_name
      @envelope_name = envelope_name
      @retry_after = retry_after
      @field_violations = field_violations
    end

    def self.attach_envelope(error, envelope_name)
      error.envelope_name = envelope_name if error.is_a?(Error)
      raise error
    end
  end

  class AuthenticationError < Error; end
  class PermissionError < Error; end
  class IdempotencyError < Error; end
  class RateLimitError < Error; end
  class InvalidRequestError < Error; end
  class APIError < Error; end
  class ConnectionError < Error; end
  class SignatureVerificationError < Error; end
end
