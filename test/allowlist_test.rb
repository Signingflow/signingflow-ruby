# frozen_string_literal: true

require "test_helper"

class AllowlistTest < Minitest::Test
  def test_operations_match_the_pinned_file
    raw = JSON.parse(File.read(Signingflow::ALLOWLIST_PATH))
    assert_equal 15, raw.fetch("operations").length
    assert_equal raw.fetch("operations").map { |item| item.fetch("operationId") }, Signingflow::OPERATIONS.map { |item| item.fetch("operationId") }
    send_op = Signingflow.operation("EnvelopeService_SendEnvelope")
    update_op = Signingflow.operation("EnvelopeService_UpdateEnvelope")
    remind_op = Signingflow.operation("EnvelopeService_RemindEnvelopeSigners")
    assert_equal true, send_op["idempotent"]
    assert_equal false, update_op["idempotent"]
    assert_equal false, remind_op["idempotent"]
    assert_equal "POST", send_op["http"]
    assert_equal "/v1/{name}:send", send_op["path"]
  end
end
