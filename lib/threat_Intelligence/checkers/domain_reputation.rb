# frozen_string_literal: true

module ThreatIntelligence
  module Checkers
    class DomainReputation
      def initialize
        @vt_client = VirusTotalClient.new
        @url_classifier = URLClassifier.new
      end

      def check(domain)
        domain = sanitize_domain(domain)

        return { error: "Invalid domain format" } unless valid_domain?(domain)

        {
          domain: domain,
          timestamp: Time.now.iso8601,
          reputation: aggregate_reputation(domain),
          dns_info: get_dns_info(domain),
          virustotal: @vt_client.analyze_domain(domain),
          classification: @url_classifier.classify("https://#{domain}"),
        }
      rescue StandardError => e
        ThreatIntelligence.logger.error("Domain check failed: #{e.message}")
        { error: e.message, domain: domain }
      end

      private

      def sanitize_domain(domain)
        domain.to_s.strip.downcase.gsub(%r{^https?://}, "").split("/").first
      end

      def valid_domain?(domain)
        domain.match?(/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i)
      end

      def get_dns_info(domain)
        resolver = Resolv::DNS.new

        {
          a_records: resolver.getaddresses(domain).map(&:to_s),
          mx_records: resolver.getresources(domain, Resolv::DNS::Resource::IN::MX).map { |r| r.exchange.to_s },
        }
      rescue StandardError => e
        { error: e.message }
      end

      def aggregate_reputation(domain)
        vt_data = @vt_client.analyze_domain(domain)

        {
          overall_score: vt_data[:reputation_score] || 0,
          risk_level: determine_risk_level(vt_data[:reputation_score]),
          malicious_detections: vt_data[:malicious] || 0,
          suspicious_detections: vt_data[:suspicious] || 0,
        }
      end

      def determine_risk_level(score)
        return "unknown" if score.nil?

        case score
        when 80..100 then "low"
        when 50..79 then "medium"
        when 20..49 then "high"
        else "critical"
        end
      end
    end
  end
end
