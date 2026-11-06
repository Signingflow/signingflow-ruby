# frozen_string_literal: true

require "json"

module Signingflow
  ALLOWLIST_PATH = File.expand_path("../../resources/allowlist.json", __dir__)
  OPERATIONS = JSON.parse(File.read(ALLOWLIST_PATH)).fetch("operations").freeze
  OPERATIONS_BY_ID = OPERATIONS.to_h { |operation| [operation.fetch("operationId"), operation] }.freeze

  def self.operation(operation_id)
    OPERATIONS_BY_ID.fetch(operation_id)
  end
end
