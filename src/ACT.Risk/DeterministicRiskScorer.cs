using ACT.Contracts;

namespace ACT.Risk;

/// <summary>
/// Pure, deterministic additive risk scorer producing a 0..100 priority score.
/// <para>Additive weight table (exact, no other components contribute):</para>
/// <list type="table">
/// <item><term>TechnicalSeverity base</term><description>Informational=0, Low=10, Medium=20, High=30, Critical=40 (0..40 points)</description></item>
/// <item><term>Confidence</term><description>Low=5, Medium=12, High=20 (5..20 points)</description></item>
/// <item><term>ExploitabilityIndicator</term><description>true adds 15 (else 0)</description></item>
/// <item><term>ExposedToNetwork</term><description>true adds 10 (else 0)</description></item>
/// <item><term>Recurring</term><description>true adds 10 (else 0)</description></item>
/// <item><term>RemediationAvailable</term><description>true adds a bonus of 5 (else 0)</description></item>
/// </list>
/// <para>
/// The total is clamped to [0, 100]. The theoretical maximum is exactly 100 (40+20+15+10+10+5)
/// and the theoretical minimum is 5. <see cref="BusinessImpactLevel"/> intentionally scores zero:
/// business impact stays separate from technical prioritization by contract.
/// </para>
/// </summary>
public static class DeterministicRiskScorer
{
    /// <summary>Scores the input deterministically; identical inputs always yield an identical score.</summary>
    public static double Score(RiskInput input)
    {
        ArgumentNullException.ThrowIfNull(input);

        double score = input.TechnicalSeverity switch
        {
            Severity.Informational => 0,
            Severity.Low => 10,
            Severity.Medium => 20,
            Severity.High => 30,
            Severity.Critical => 40,
            _ => 0
        };

        score += input.Confidence switch
        {
            ConfidenceLevel.High => 20,
            ConfidenceLevel.Medium => 12,
            ConfidenceLevel.Low => 5,
            _ => 0
        };

        if (input.ExploitabilityIndicator)
        {
            score += 15;
        }

        if (input.ExposedToNetwork)
        {
            score += 10;
        }

        if (input.Recurring)
        {
            score += 10;
        }

        if (input.RemediationAvailable)
        {
            score += 5;
        }

        return Math.Clamp(score, 0d, 100d);
    }
}
