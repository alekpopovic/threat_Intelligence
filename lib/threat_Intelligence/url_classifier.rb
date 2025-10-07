# frozen_string_literal: true

module ThreatIntelligence
  class URLClassifier
    MALICIOUS_PATTERNS = [
      /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, # IP addresses in URLs
      /[a-z0-9]{20,}/, # Long random strings
      /\.(tk|ml|ga|cf|gq)$/, # Suspicious TLDs
      /(phish|hack|crack|virus|malware|trojan)/i,
      /@/i, # @ symbol in URL
    ].freeze

    SUSPICIOUS_PATTERNS = [
      /bit\.ly|tinyurl|goo\.gl/, # URL shorteners
      /\d{5,}/, # Many numbers
      /-{3,}/, # Multiple dashes
    ].freeze

    def classify(url)
      parsed_url = URI.parse(url)

      {
        url: url,
        classification: determine_classification(url, parsed_url),
        risk_score: calculate_risk_score(url, parsed_url),
        indicators: detect_indicators(url, parsed_url),
        domain: parsed_url.host,
        protocol: parsed_url.scheme,
        path_segments: parsed_url.path.split("/").reject(&:empty?).size,
      }
    rescue URI::InvalidURIError => e
      {
        url: url,
        classification: "invalid",
        risk_score: 100,
        error: e.message,
      }
    end

    private

    def determine_classification(url, parsed_url)
      return "malicious" if MALICIOUS_PATTERNS.any? { |pattern| url.match?(pattern) }
      return "suspicious" if SUSPICIOUS_PATTERNS.any? { |pattern| url.match?(pattern) }
      return "suspicious" if parsed_url.host.nil?
      return "suspicious" if parsed_url.host.count(".") > 4

      "clean"
    end

    def calculate_risk_score(url, parsed_url)
      score = 0

      score += 50 if MALICIOUS_PATTERNS.any? { |pattern| url.match?(pattern) }
      score += 25 if SUSPICIOUS_PATTERNS.any? { |pattern| url.match?(pattern) }
      score += 10 if parsed_url.host && parsed_url.host.count(".") > 4
      score += 15 if url.length > 100
      score += 10 if parsed_url.path && parsed_url.path.length > 50

      [score, 100].min
    end

    def detect_indicators(url, parsed_url)
      indicators = []

      indicators << "IP address in URL" if url.match?(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/)
      indicators << "Suspicious TLD" if parsed_url.host&.match?(/\.(tk|ml|ga|cf|gq)$/)
      indicators << "URL shortener" if url.match?(/bit\.ly|tinyurl|goo\.gl/)
      indicators << "Long URL" if url.length > 100
      indicators << "Multiple subdomains" if parsed_url.host && parsed_url.host.count(".") > 4
      indicators << "Suspicious keywords" if url.match?(/(phish|hack|crack|virus|malware|trojan)/i)
      indicators << "Non-standard port" if parsed_url.port && ![80, 443].include?(parsed_url.port)

      indicators
    end
  end
end
