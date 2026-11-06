# frozen_string_literal: true

module Signingflow
  class Client
    attr_reader :files, :envelopes, :templates, :webhook_urls, :webhook_deliveries

    def initialize(api_key, workspace_id:, env:, **options)
      config = ConfigResolver.resolve(api_key, workspace_id: workspace_id, env: env, **options)
      requestor = Requestor.new(config)
      @files = Resources::Files.new(requestor, config)
      @templates = Resources::Templates.new(requestor)
      @envelopes = Resources::Envelopes.new(requestor, @files, @templates)
      @webhook_urls = Resources::WebhookUrls.new(requestor)
      @webhook_deliveries = Resources::WebhookDeliveries.new(requestor)
    end
  end
end
