using ACT.Contracts;

namespace ACT.Reporting;

/// <summary>A finding paired with the evidence items collected for it.</summary>
public sealed record FindingWithEvidence(Finding Finding, IReadOnlyList<EvidenceItem> EvidenceItems);

/// <summary>Honest per-state verification counts for everything an assessment attempted.</summary>
public readonly record struct VerificationCoverage(
    int Tested,
    int NotTested,
    int Inaccessible,
    int Inconclusive,
    int Confirmed,
    int Inferred);

/// <summary>Complete input required to render one assessment report.</summary>
public sealed record ReportInput(
    AssessmentRecord Assessment,
    ScopeDefinition Scope,
    IReadOnlyList<FindingWithEvidence> Items,
    ScanMetricsRecord? Metrics,
    VerificationCoverage Coverage,
    string? Limitations,
    DateTimeOffset GeneratedUtc,
    string ToolVersion)
{
    /// <summary>Tool identity stamped into every report unless overridden.</summary>
    public const string DefaultToolVersion = "Artemis 1.0.0";

    /// <summary>Creates a report input, filling generation time and tool version defaults.</summary>
    public static ReportInput Create(
        AssessmentRecord assessment,
        ScopeDefinition scope,
        IReadOnlyList<FindingWithEvidence> items,
        ScanMetricsRecord? metrics = null,
        VerificationCoverage coverage = default,
        string? limitations = null,
        DateTimeOffset? generatedUtc = null,
        string? toolVersion = null)
        => new(
            assessment,
            scope,
            items,
            metrics,
            coverage,
            limitations,
            generatedUtc ?? DateTimeOffset.UtcNow,
            toolVersion ?? DefaultToolVersion);
}
