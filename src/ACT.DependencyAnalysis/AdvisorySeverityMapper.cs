
using ACT.Contracts;

namespace ACT.DependencyAnalysis;

/// <summary>Maps textual advisory severities from feeds onto the contract severity scale.</summary>
public static class AdvisorySeverityMapper
{
    /// <summary>Returns the mapped severity, or null when the feed text is absent or unrecognized.</summary>
    public static Severity? Map(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        return raw.Trim().ToUpperInvariant() switch
        {
            "LOW" => Severity.Low,
            "MODERATE" or "MEDIUM" => Severity.Medium,
            "HIGH" => Severity.High,
            "CRITICAL" => Severity.Critical,
            _ => (Severity?)null
        };
    }
}

