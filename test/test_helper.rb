# frozen_string_literal: true

require "simplecov"
SimpleCov.start do
  enable_coverage :branch
  add_filter "/test/"
  minimum_coverage line: 80, branch: 80
end

require "minitest/autorun"
require "webmock/minitest"
require "signingflow"

WebMock.disable_net_connect!
