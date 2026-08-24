using ACT.Contracts;

namespace ACT.Risk;

/// <summary>
/// Deterministic, stable finding ordering: PriorityScore descending, then TechnicalSeverity
/// descending, then ConfidenceScore descending, then Title ascending by ordinal comparison.
/// Ties on every key keep their input order.
/// </summary>
public static class FindingPrioritizer
{
    /// <summary>Returns the findings ordered by the stable priority relation.</summary>
    public static IReadOnlyList<Finding> Prioritize(IEnumerable<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);
        return findings
            .OrderByDescending(static f => f.PriorityScore)
            .ThenByDescending(static f => f.TechnicalSeverity)
            .ThenByDescending(static f => f.ConfidenceScore)
            .ThenBy(static f => f.Title, StringComparer.Ordinal)
            .ToArray();
    }
}
