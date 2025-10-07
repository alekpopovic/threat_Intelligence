# frozen_string_literal: true

module ThreatIntelligence
  class Configuration
    attr_accessor :virustotal_api_key,
      :abuseipdb_api_key,
      :urlscan_api_key,
      :shodan_api_key,
      :redis_url,
      :cache_ttl,
      :timeout,
      :rate_limit_per_minute,
      :log_level

    def initialize
      @virustotal_api_key = ENV["VIRUSTOTAL_API_KEY"]
      @abuseipdb_api_key = ENV["ABUSEIPDB_API_KEY"]
      @urlscan_api_key = ENV["URLSCAN_API_KEY"]
      @shodan_api_key = ENV["SHODAN_API_KEY"]
      @redis_url = ENV["REDIS_URL"] || "redis://localhost:6379/0"
      @cache_ttl = 3600 # 1 hour
      @timeout = 10
      @rate_limit_per_minute = 60
      @log_level = Logger::INFO
    end
  end

  class << self
    attr_writer :configuration

    def configuration
      @configuration ||= Configuration.new
    end

    def configure
      yield(configuration)
    end

    def logger
      @logger ||= Logger.new($stdout).tap do |log|
        log.level = configuration.log_level
      end
    end
  end
end
