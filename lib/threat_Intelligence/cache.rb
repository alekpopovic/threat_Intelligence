# frozen_string_literal: true

module ThreatIntelligence
  class Cache
    def initialize
      @redis = Redis.new(url: ThreatIntelligence.configuration.redis_url)
      @ttl = ThreatIntelligence.configuration.cache_ttl
    rescue StandardError => e
      ThreatIntelligence.logger.warn("Redis connection failed: #{e.message}. Operating without cache.")
      @redis = nil
    end

    def get(key)
      return unless @redis

      value = @redis.get(key)
      JSON.parse(value) if value
    rescue StandardError => e
      ThreatIntelligence.logger.error("Cache get error: #{e.message}")
      nil
    end

    def set(key, value)
      return unless @redis

      @redis.setex(key, @ttl, value.to_json)
    rescue StandardError => e
      ThreatIntelligence.logger.error("Cache set error: #{e.message}")
    end

    def delete(key)
      return unless @redis

      @redis.del(key)
    rescue StandardError => e
      ThreatIntelligence.logger.error("Cache delete error: #{e.message}")
    end
  end
end
