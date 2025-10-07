# frozen_string_literal: true

module ThreatIntelligence
  module Clients
    class VirusTotal < BaseAPI
      BASE_URL = "https://www.virustotal.com/api/v3"

      def analyze_domain(domain)
        return { error: "API key not configured" } unless api_key_configured?

        fetch_with_cache("vt:domain:#{domain}") do
          uri = URI("#{BASE_URL}/domains/#{domain}")
          headers = { "x-apikey" => ThreatIntelligence.configuration.virustotal_api_key }

          result = make_request(uri, headers)
          parse_domain_response(result)
        end
      end

      def analyze_ip(ip)
        return { error: "API key not configured" } unless api_key_configured?

        fetch_with_cache("vt:ip:#{ip}") do
          uri = URI("#{BASE_URL}/ip_addresses/#{ip}")
          headers = { "x-apikey" => ThreatIntelligence.configuration.virustotal_api_key }

          result = make_request(uri, headers)
          parse_ip_response(result)
        end
      end

      def analyze_url(url)
        return { error: "API key not configured" } unless api_key_configured?

        url_id = Base64.urlsafe_encode64(url).tr("=", "")
        fetch_with_cache("vt:url:#{url_id}") do
          uri = URI("#{BASE_URL}/urls/#{url_id}")
          headers = { "x-apikey" => ThreatIntelligence.configuration.virustotal_api_key }

          result = make_request(uri, headers)
          parse_url_response(result)
        end
      end

      private

      def api_key_configured?
        !ThreatIntelligence.configuration.virustotal_api_key.nil?
      end

      def parse_domain_response(response)
        data = response.dig("data", "attributes") || {}
        stats = data.dig("last_analysis_stats") || {}

        {
          reputation_score: calculate_reputation_score(stats),
          malicious: stats["malicious"] || 0,
          suspicious: stats["suspicious"] || 0,
          harmless: stats["harmless"] || 0,
          categories: data["categories"] || {},
          creation_date: data["creation_date"],
          last_analysis_date: data["last_analysis_date"],
        }
      end

      def parse_ip_response(response)
        data = response.dig("data", "attributes") || {}
        stats = data.dig("last_analysis_stats") || {}

        {
          reputation_score: calculate_reputation_score(stats),
          malicious: stats["malicious"] || 0,
          suspicious: stats["suspicious"] || 0,
          harmless: stats["harmless"] || 0,
          country: data["country"],
          asn: data["asn"],
          network: data["network"],
        }
      end

      def parse_url_response(response)
        data = response.dig("data", "attributes") || {}
        stats = data.dig("last_analysis_stats") || {}

        {
          reputation_score: calculate_reputation_score(stats),
          malicious: stats["malicious"] || 0,
          suspicious: stats["suspicious"] || 0,
          harmless: stats["harmless"] || 0,
          categories: data["categories"] || {},
          last_analysis_date: data["last_analysis_date"],
        }
      end

      def calculate_reputation_score(stats)
        total = stats.values.sum
        return 100 if total.zero?

        malicious = stats["malicious"] || 0
        suspicious = stats["suspicious"] || 0

        100 - ((malicious + suspicious * 0.5) / total * 100).round(2)
      end
    end
  end
end
