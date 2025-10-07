# frozen_string_literal: true

module ThreatIntelligence
  class ReportGenerator
    def generate(analysis_result)
      case analysis_result
      when Hash
        generate_single_report(analysis_result)
      when Array
        generate_bulk_report(analysis_result)
      end
    end

    def generate_single_report(result)
      report = {
        generated_at: Time.now.iso8601,
        summary: generate_summary(result),
        details: result,
        recommendations: generate_recommendations(result),
      }

      format_report(report)
    end

    def generate_bulk_report(results)
      {
        generated_at: Time.now.iso8601,
        total_analyzed: results.size,
        summary: {
          critical: count_by_risk(results, "critical"),
          high: count_by_risk(results, "high"),
          medium: count_by_risk(results, "medium"),
          low: count_by_risk(results, "low"),
        },
        results: results,
      }
    end

    private

    def generate_summary(result)
      return { status: "error", message: result[:error] } if result[:error]

      risk_level = result.dig(:reputation, :risk_level) || "unknown"
      score = result.dig(:reputation, :overall_score) || 0

      {
        risk_level: risk_level,
        reputation_score: score,
        target: result[:domain] || result[:ip] || result[:url],
        threat_detected: risk_level.in?(["high", "critical"]),
      }
    end

    def generate_recommendations(result)
      return [] if result[:error]

      risk_level = result.dig(:reputation, :risk_level)
      recommendations = []

      case risk_level
      when "critical"
        recommendations << "BLOCK: Immediate action required - high threat detected"
        recommendations << "Add to blocklist and monitor related infrastructure"
      when "high"
        recommendations << "ALERT: Suspicious activity detected - proceed with caution"
        recommendations << "Additional investigation recommended"
      when "medium"
        recommendations << "MONITOR: Elevated risk level - increased monitoring suggested"
      when "low"
        recommendations << "ALLOW: Low risk detected - normal monitoring sufficient"
      end

      recommendations
    end

    def count_by_risk(results, risk_level)
      results.count { |r| r.dig(:reputation, :risk_level) == risk_level }
    end

    def format_report(report)
      JSON.pretty_generate(report)
    end
  end
end
