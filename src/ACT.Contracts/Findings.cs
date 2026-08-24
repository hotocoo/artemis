
namespace ACT.Contracts;

/// <summary>Technical severity of a finding. Never conflated with confidence or business impact.</summary>
public enum Severity
{
    Informational = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

/// <summary>How sure the engine is that the observation is real.</summary>
public enum ConfidenceLevel
{
    Low = 0,
    Medium = 1,
    High = 2
}

/// <summary>Lifecycle state of one deduplicated finding.</summary>
public enum FindingStatus
{
    New,
    Confirmed,
    AcceptedRisk,
    FalsePositive,
    Remediated,
    Regressed,
    Reopened
}

/// <summary>Business-impact band kept separate from technical severity.</summary>
public enum BusinessImpactLevel
{
    Unknown = 0,
    Negligible = 1,
    Limited = 2,
    Significant = 3,
    Severe = 4
}

/// <summary>Deterministic fingerprint: identical finding classes on identical resources collide.</summary>
public readonly record struct FindingFingerprint(string Hash)
{
    public override string ToString() => Hash;
}

/// <summary>Structured remediation guidance attached to findings and reports.</summary>
public sealed record RemediationGuidance(
    string Summary,
    IReadOnlyList<string> Steps,
    IReadOnlyList<string> References);

/// <summary>
/// The stable finding schema. One row per deduplicated issue; evidence hangs off FindingId.
/// </summary>
public sealed record Finding(
    Guid FindingId,
    Guid AssessmentId,
    CheckId CheckId,
    string TargetDisplay,
    string? AssetReference,
    CheckCategory Category,
    string Title,
    string Description,
    Severity TechnicalSeverity,
    ConfidenceLevel Confidence,
    double ConfidenceScore,
    bool ExploitabilityIndicator,
    BusinessImpactLevel BusinessImpact,
    string WhyItMatters,
    string TechnicalExplanation,
    RemediationGuidance Remediation,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    FindingStatus Status,
    FindingFingerprint Fingerprint,
    Guid? RegressionTestId,
    string? CvssVector,
    double? CvssBaseScore)
{
    /// <summary>Prioritization score assigned by the risk engine (0..100); persisted separately from severity.</summary>
    public double PriorityScore { get; init; }
}

/// <summary>Input used to compute a deterministic fingerprint.</summary>
public sealed record FingerprintComponents(
    CheckId CheckId,
    string NormalizedTarget,
    string RelevantResource,
    string FindingClass);

/// <summary>
/// The operator triage decision recorded against one finding: the status, who decided it, when,
/// and why. Null fields mean the finding has never been triaged.
/// </summary>
public sealed record FindingTriage(
    FindingStatus Status,
    string? Note,
    string? TriagedBy,
    DateTimeOffset? TriagedUtc);

/// <summary>
/// The deterministic finding triage lifecycle. Every operator status change must follow an edge
/// in this graph; anything else fails closed. Terminal decisions (FalsePositive, AcceptedRisk,
/// Remediated) survive reobservation by design, so reversing one is always an explicit Reopened
/// step, never a silent side effect.
/// </summary>
public static class FindingTransitions
{
    /// <summary>Returns every status a finding currently in 'from' may move to.</summary>
    public static IReadOnlyList<FindingStatus> AllowedTargets(FindingStatus from) => from switch
    {
        FindingStatus.New or FindingStatus.Reopened =>
            [FindingStatus.Confirmed, FindingStatus.AcceptedRisk, FindingStatus.FalsePositive, FindingStatus.Remediated],
        FindingStatus.Confirmed =>
            [FindingStatus.Remediated, FindingStatus.AcceptedRisk, FindingStatus.FalsePositive],
        FindingStatus.Regressed =>
            [FindingStatus.Confirmed, FindingStatus.Remediated, FindingStatus.AcceptedRisk, FindingStatus.FalsePositive],

        // Terminal states open onto exactly one edge: explicit reopen for re-evaluation.
        _ => [FindingStatus.Reopened]
    };

    /// <summary>Whether the transition from -> to is part of the documented lifecycle.</summary>
    public static bool CanTransition(FindingStatus from, FindingStatus to) => AllowedTargets(from).Contains(to);
}

/// <summary>Statuses a report must be able to express honestly.</summary>
public enum VerificationState
{
    Tested,
    NotTested,
    Inaccessible,
    Inconclusive,
    Confirmed,
    Inferred
}
