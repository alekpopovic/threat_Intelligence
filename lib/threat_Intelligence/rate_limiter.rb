# frozen_string_literal: true

module ThreatIntelligence
  class RateLimiter
    def initialize(max_requests_per_minute)
      @max_requests = max_requests_per_minute
      @requests = Concurrent::Array.new
      @mutex = Mutex.new
    end

    def wait_if_needed
      @mutex.synchronize do
        now = Time.now
        @requests.reject! { |timestamp| now - timestamp > 60 }

        if @requests.size >= @max_requests
          sleep_time = 60 - (now - @requests.first)
          sleep(sleep_time) if sleep_time.positive?
          @requests.clear
        end

        @requests << now
      end
    end
  end
end
