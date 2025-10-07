# frozen_string_literal: true

module ThreatIntelligence
  class CLI
    class << self
      def run(args)
        if args.empty?
          print_usage
          exit(1)
        end

        command = args.shift

        case command
        when "check"
          handle_check(args)
        when "bulk"
          handle_bulk(args)
        when "config"
          handle_config
        else
          puts "Unknown command: #{command}"
          print_usage
          exit(1)
        end
      end

      def handle_check(args)
        if args.empty?
          puts "Error: No target specified"
          exit(1)
        end

        target = args.first
        service = Service.new
        result = service.analyze(target)

        report = ReportGenerator.new.generate(result)
        puts report
      end

      def handle_bulk(args)
        if args.empty?
          puts "Error: No targets specified"
          exit(1)
        end

        service = Service.new
        results = service.bulk_analyze(args)

        report = ReportGenerator.new.generate(results)
        puts report
      end

      def handle_config
        config = ThreatIntelligence.configuration

        puts "Current Configuration:"
        puts "  VirusTotal API Key: #{config.virustotal_api_key ? "[SET]" : "[NOT SET]"}"
        puts "  AbuseIPDB API Key: #{config.abuseipdb_api_key ? "[SET]" : "[NOT SET]"}"
        puts "  URLScan API Key: #{config.urlscan_api_key ? "[SET]" : "[NOT SET]"}"
        puts "  Shodan API Key: #{config.shodan_api_key ? "[SET]" : "[NOT SET]"}"
        puts "  Redis URL: #{config.redis_url}"
        puts "  Cache TTL: #{config.cache_ttl} seconds"
        puts "  Timeout: #{config.timeout} seconds"
        puts "  Rate Limit: #{config.rate_limit_per_minute} requests/minute"
      end

      def print_usage
        puts <<~USAGE
          Threat Intelligence - Domain/IP Reputation & URL Classification Tool

          Usage:
            threat_intelligence check <target>     Check a single domain, IP, or URL
            threat_intelligence bulk <targets...>  Check multiple targets
            threat_intelligence config             Show current configuration

          Examples:
            threat_intelligence check google.com
            threat_intelligence check 8.8.8.8
            threat_intelligence check https://example.com/path
            threat_intelligence bulk google.com 8.8.8.8 malicious-site.com

          Environment Variables:
            VIRUSTOTAL_API_KEY    - VirusTotal API key
            ABUSEIPDB_API_KEY     - AbuseIPDB API key
            URLSCAN_API_KEY       - URLScan.io API key
            SHODAN_API_KEY        - Shodan API key
            REDIS_URL             - Redis connection URL (default: redis://localhost:6379/0)
        USAGE
      end
    end
  end
end
