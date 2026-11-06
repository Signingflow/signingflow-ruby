# frozen_string_literal: true

module Signingflow
  module Status
    module_function

    def grpc_code(body)
      return nil unless body.is_a?(Hash)

      code = body["code"]
      code.is_a?(Numeric) ? code : nil
    end

    def server_message(body)
      return body if body.is_a?(String)
      return "" unless body.is_a?(Hash)

      message = body["message"]
      message.is_a?(String) ? message : ""
    end

    def trace_code(body)
      found = find_meta(body, "trace_code")
      found.empty? ? nil : found
    end

    def resource_name(body)
      url = find_meta(body, "resource_url")
      return url unless url.empty?

      id = find_meta(body, "resource_id")
      id.empty? ? nil : id
    end

    def field_violations(body)
      found = []
      walk(body) do |record|
        list = record["fieldViolations"] || record["field_violations"]
        next unless list.is_a?(Array)

        list.each do |item|
          next unless item.is_a?(Hash)

          field = item["field"].is_a?(String) ? item["field"] : ""
          description = item["description"].is_a?(String) ? item["description"] : ""
          found << { "field" => field, "description" => description } if !field.empty? || !description.empty?
        end
      end
      found.empty? ? nil : found
    end

    def mentions_idempotency?(body)
      JSON.generate(body.nil? ? "" : body).downcase.include?("idempotency")
    end

    def find_meta(body, key)
      found = +""
      walk(body) do |record|
        next unless found.empty?

        metadata = record["metadata"]
        next unless metadata.is_a?(Hash)

        value = metadata[key]
        found = value if value.is_a?(String) && !value.empty?
      end
      found
    end

    def walk(value, &visit)
      return unless value.is_a?(Hash) || value.is_a?(Array)

      if value.is_a?(Array)
        value.each { |item| walk(item, &visit) }
        return
      end

      visit.call(value)
      value.each_value { |child| walk(child, &visit) }
    end
  end
end
