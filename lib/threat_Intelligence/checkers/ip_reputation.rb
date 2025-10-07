# frozen_string_literal: true

module ThreatIntelligence
  module Checkers
    class IPReputation
      def initialize
        @vt_client = VirusTotalClient.new
        @abuseipdb_client = AbuseIPDBClient.new
      end

      def check(ip)
        ip = ip.to_s.strip

        return { error: "Invalid IP address format" } unless valid_ip?(ip)

        {
          ip: ip,
          timestamp: Time.now.iso8601,
          reputation: aggregate_reputation(ip),
          is_private: private_ip?(ip),
          virustotal: @vt_client.analyze_ip(ip),
          abuseipdb: @abuseipdb_client.check_ip(ip),
          geolocation: get_geolocation(ip),
        }
      rescue StandardError => e
        ThreatIntelligence.logger.error("IP check failed: #{e.message}")
        { error: e.message, ip: ip }
      end

      private

      def valid_ip?(ip)
        IPAddr.new(ip)
        true
      rescue IPAddr::InvalidAddressError
        false
      end

      def private_ip?(ip)
        addr = IPAddr.new(ip)
        addr.private?
      rescue StandardError
        false
      end

      def get_geolocation(ip)
        vt_data = @vt_client.analyze_ip(ip)
        abuse_data = @abuseipdb_client.check_ip(ip)

        {
          country: vt_data[:country] || abuse_data[:country_code],
          asn: vt_data[:asn],
          isp: abuse_data[:isp],
        }
      end

      def aggregate_reputation(ip)
        vt_data = @vt_client.analyze_ip(ip)
        abuse_data = @abuseipdb_client.check_ip(ip)

        vt_score = vt_data[:reputation_score] || 50
        abuse_score = 100 - (abuse_data[:abuse_confidence_score] || 0)

        overall_score = (vt_score + abuse_score) / 2.0

        {
          overall_score: overall_score.round(2),
          risk_level: determine_risk_level(overall_score),
          malicious_detections: vt_data[:malicious] || 0,
          abuse_reports: abuse_data[:total_reports] || 0,
          is_tor: abuse_data[:is_tor] || false,
        }
      end

      def determine_risk_level(score)
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
