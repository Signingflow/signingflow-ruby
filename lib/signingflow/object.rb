# frozen_string_literal: true

module Signingflow
  class ResourceObject
    def initialize(data)
      @data = data.is_a?(Hash) ? data : {}
    end

    def [](key)
      lookup(key.to_s)
    end

    def []=(key, value)
      @data[key.to_s] = value
    end

    def to_h
      @data
    end

    def key?(name)
      !lookup(name.to_s).nil? || @data.key?(name.to_s) || @data.key?(camel(name.to_s))
    end

    def method_missing(name, *args)
      return super if !args.empty? || name.to_s.end_with?("=")

      lookup(name.to_s)
    end

    def respond_to_missing?(name, include_private = false)
      key?(name) || super
    end

    private

    def lookup(key)
      return @data[key] if @data.key?(key)

      camel_key = camel(key)
      return @data[camel_key] if @data.key?(camel_key)

      nil
    end

    def camel(key)
      key.gsub(/_([a-z])/) { Regexp.last_match(1).upcase }
    end
  end

  class List
    MAX_PAGES = 100

    attr_reader :data, :next_page_token

    def initialize(data:, next_page_token:, loader:)
      @data = data
      @next_page_token = next_page_token
      @loader = loader
    end

    def auto_paging_each
      page_data = @data
      token = @next_page_token
      seen = {}
      pages = 0
      loop do
        page_data.each do |item|
          keep = yield item
          return if keep == false
        end
        return if token.nil? || token.empty? || seen[token]

        pages += 1
        raise InvalidRequestError, "Too many pages." if pages > MAX_PAGES

        seen[token] = true
        page = @loader.call(token)
        page_data = page.data
        token = page.next_page_token
      end
    end

    def auto_paging_to_array(limit: nil)
      items = []
      auto_paging_each do |item|
        break false if !limit.nil? && items.length >= limit

        items << item
        limit.nil? || items.length < limit
      end
      items
    end
  end
end
