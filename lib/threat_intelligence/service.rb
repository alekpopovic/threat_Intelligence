# frozen_string_literal: true

module ThreatIntelligence
  class Service
    def initialize
      @domain_checker = DomainReputationChecker.new
      @ip_checker = IPReputationChecker.new
      @url_classifier = URLClassifier.new
    end

    def analyze(target)
      case detect_target_type(target)
      when :ip
        @ip_checker.check(target)
      when :domain
        @domain_checker.check(target)
      when :url
        analyze_url(target)
      else
        { error: "Unable to determine target type" }
      end
    end

    def analyze_url(url)
      parsed_url = URI.parse(url)
      domain = parsed_url.host

      {
        url: url,
        timestamp: Time.now.iso8601,
        classification: @url_classifier.classify(url),
        domain_reputation: domain ? @domain_checker.check(domain) : nil,
        virustotal: VirusTotalClient.new.analyze_url(url),
      }
    rescue URI::InvalidURIError => e
      { error: "Invalid URL: #{e.message}" }
    end

    def bulk_analyze(targets, max_concurrency: 5)
      pool = Concurrent::FixedThreadPool.new(max_concurrency)
      promises = targets.map do |target|
        Concurrent::Promise.execute(executor: pool) { analyze(target) }
      end

      results = promises.map(&:value)
      pool.shutdown
      pool.wait_for_termination

      results
    end

    private

    def detect_target_type(target)
      target = target.to_s.strip

      return :ip if valid_ip?(target)
      return :url if target.match?(%r{^https?://})
      return :domain if valid_domain?(target)

      nil
    end

    def valid_ip?(ip)
      IPAddr.new(ip)
      true
    rescue IPAddr::InvalidAddressError
      false
    end

    def valid_domain?(domain)
      domain.match?(/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i)
    end
  end
end
