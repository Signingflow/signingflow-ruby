# frozen_string_literal: true

module Signingflow
  Config = Data.define(
    :api_key, :workspace_id, :env, :base_url, :timeout, :max_network_retries,
    :channel, :funnel, :upload_hosts, :upload_root, :source
  )

  module ConfigResolver
    DEFAULT_UPLOAD_HOSTS = ["storage.googleapis.com"].freeze
    OFFICIAL_HOST = "api.signingflow.com"

    module_function

    def resolve(api_key, workspace_id:, env:, base_url: nil, allow_custom_base_url: false, timeout: 30_000,
                max_network_retries: 2, channel: nil, funnel: nil, upload_hosts: nil, upload_root: nil)
      key = api_key.to_s.strip
      raise Error, "API key is required." if key.empty?
      workspace = workspace_id.to_s.strip
      raise Error, "workspace_id is required." if workspace.empty?

      raw_base = base_url.to_s.strip
      raw_base = "https://api.signingflow.com" if raw_base.empty?
      raw_base = raw_base.sub(%r{/+\z}, "")
      begin
        parsed = URI.parse(raw_base)
      rescue URI::InvalidURIError
        raise Error, "base_url must be an absolute URL."
      end
      raise Error, "base_url must be an absolute URL." if parsed.host.nil? || parsed.scheme.nil?
      raise Error, "base_url must be https." unless parsed.scheme == "https"
      raise Error, "base_url must not include a username or password." if parsed.user || parsed.password
      if parsed.host != OFFICIAL_HOST && !allow_custom_base_url
        raise Error, "base_url host must be api.signingflow.com, or set allow_custom_base_url."
      end
      unless timeout.is_a?(Numeric) && timeout.positive?
        raise Error, "timeout must be a positive number of milliseconds."
      end
      unless max_network_retries.is_a?(Integer) && max_network_retries >= 0
        raise Error, "max_network_retries must be a whole number of zero or more."
      end

      Config.new(
        api_key: key,
        workspace_id: workspace,
        env: normalize_env(env),
        base_url: raw_base,
        timeout: timeout,
        max_network_retries: max_network_retries,
        channel: blank(channel),
        funnel: blank(funnel),
        upload_hosts: upload_hosts_of(upload_hosts),
        upload_root: blank(upload_root),
        source: SOURCE
      )
    end

    def normalize_env(env)
      value = env.to_s
      return "SANDBOX" if value == "sandbox" || value == "SANDBOX"
      return "LIVE" if value == "live" || value == "LIVE"

      raise Error, "env must be sandbox or live."
    end

    def upload_hosts_of(hosts)
      list = (hosts || DEFAULT_UPLOAD_HOSTS).map { |host| host.to_s.strip.downcase }.reject(&:empty?)
      list.each do |host|
        dots = host.count(".")
        if dots < 2 || host.start_with?(".") || host.end_with?(".") || host.include?("..")
          raise Error, "Each upload_hosts entry must be a specific host, not a public suffix."
        end
      end
      list.freeze
    end

    def blank(value)
      trimmed = value.to_s.strip
      trimmed.empty? ? nil : trimmed
    end
  end
end
