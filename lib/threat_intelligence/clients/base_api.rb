# frozen_string_literal: true

module ThreatIntelligence
  module Clients
    class BaseAPI
      def initialize
        @cache = Cache.new
        @rate_limiter = RateLimiter.new(ThreatIntelligence.configuration.rate_limit_per_minute)
        @timeout = ThreatIntelligence.configuration.timeout
      end

      private

      def fetch_with_cache(cache_key)
        cached = @cache.get(cache_key)
        return cached if cached

        result = yield
        @cache.set(cache_key, result) if result
        result
      end

      def make_request(uri, headers = {})
        @rate_limiter.wait_if_needed

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == "https"
        http.open_timeout = @timeout
        http.read_timeout = @timeout

        request = Net::HTTP::Get.new(uri.request_uri)
        headers.each { |key, value| request[key] = value }

        response = http.request(request)

        case response.code.to_i
        when 200..299
          JSON.parse(response.body)
        when 429
          raise RateLimitError, "Rate limit exceeded"
        when 401, 403
          raise AuthenticationError, "Authentication failed: #{response.code}"
        else
          raise APIError, "API request failed: #{response.code} - #{response.body}"
        end
      rescue JSON::ParserError => e
        raise APIError, "Invalid JSON response: #{e.message}"
      rescue Timeout::Error
        raise APIError, "Request timeout"
      rescue StandardError => e
        raise APIError, "Request failed: #{e.message}"
      end
    end

    class APIError < StandardError; end
    class RateLimitError < APIError; end
    class AuthenticationError < APIError; end
  end
end
