# frozen_string_literal: true

require_relative "signingflow/version"
require_relative "signingflow/errors"
require_relative "signingflow/allowlist"
require_relative "signingflow/config"
require_relative "signingflow/redact"
require_relative "signingflow/status"
require_relative "signingflow/path"
require_relative "signingflow/jail"
require_relative "signingflow/object"
require_relative "signingflow/requestor"
require_relative "signingflow/webhook"
require_relative "signingflow/resources"
require_relative "signingflow/client"

module Signingflow
  def self.construct_event(payload, signature, secret, previous_secret: nil, previous_signature: nil)
    Webhook.construct_event(payload, signature, secret, previous_secret: previous_secret, previous_signature: previous_signature)
  end

  def self.signing_secret_of(body)
    Resources.signing_secret_of(body)
  end
end
