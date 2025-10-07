# frozen_string_literal: true

module ThreatIntelligence
  class AbuseIPDBClient < BaseAPIClient
    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def check_ip(ip)
      return { error: "API key not configured" } unless api_key_configured?

      fetch_with_cache("abuseipdb:#{ip}") do
        uri = URI("#{BASE_URL}/check")
        uri.query = URI.encode_www_form({ ipAddress: ip, maxAgeInDays: 90 })
        headers = { "Key" => ThreatIntelligence.configuration.abuseipdb_api_key }

        result = make_request(uri, headers)
        parse_response(result)
      end
    end

    private

    def api_key_configured?
      !ThreatIntelligence.configuration.abuseipdb_api_key.nil?
    end

    def parse_response(response)
      data = response["data"] || {}

      {
        abuse_confidence_score: data["abuseConfidenceScore"] || 0,
        country_code: data["countryCode"],
        usage_type: data["usageType"],
        isp: data["isp"],
        domain: data["domain"],
        total_reports: data["totalReports"] || 0,
        is_whitelisted: data["isWhitelisted"] || false,
        is_tor: data["isTor"] || false,
      }
    end
  end
end
