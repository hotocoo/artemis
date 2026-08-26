using ACT.Contracts;

namespace ACT.Persistence;

/// <summary>
/// A stored re-verification recipe that proves whether one known finding has returned after
/// remediation. <see cref="RecipeJson"/> carries the serialized machine-executable replay
/// (ACT.Core GeneratedRegression); null on rows captured before recipes were persisted, which are
/// listed honestly as "manual" rather than silently replayed.
/// </summary>
public sealed record RegressionTestRecord(
    Guid RegressionTestId,
    Guid OriginAssessmentId,
    Guid FindingId,
    string Name,
    string Description,
    Severity SuggestedSeverity,
    TimeSpan Cadence,
    bool Enabled,
    DateTimeOffset CreatedUtc,
    DateTimeOffset? LastRunUtc,
    DateTimeOffset NextRunUtc,
    string? RecipeJson = null);

/// <summary>One executed regression verification and its verdict.</summary>
public sealed record RegressionTestRunRecord(
    long TestRunId,
    Guid RegressionTestId,
    DateTimeOffset RanAtUtc,
    VerificationState Result,
    string Detail);

/// <summary>
/// One recorded execution of a security check within an assessment, exactly as the engine reported
/// it - including skips, fail-closed containment, and timeouts. This ledger is the factual basis
/// of every honest coverage statement: coverage numbers may only count executions that were
/// actually recorded here, never estimates or findings relabeled as tests.
/// </summary>
public sealed record CheckRunRecord(
    Guid CheckRunId,
    Guid AssessmentId,
    string CheckId,
    CheckExecutionStatus Status,
    DateTimeOffset StartedUtc,
    DateTimeOffset CompletedUtc,
    string? FailureSummarySafe,
    long RequestCount,
    int TargetsExamined);

/// <summary>A configured advisory-feed source as persisted locally.</summary>
public sealed record FeedRecord(
    string Name,
    AdvisoryFeedKind Kind,
    string EndpointOrPath,
    bool Enabled,
    DateTimeOffset UpdatedUtc);

/// <summary>One retrieval generation of an advisory feed with its honesty metadata.</summary>
public sealed record FeedVersionRecord(
    string FeedName,
    DateTimeOffset RetrievedUtc,
    string MetadataHash,
    bool IsCurrent,
    string Note);

/// <summary>
/// One scope's evidence-retention outlook: its configured window, the cutoff that window implies
/// right now, and how many of its stored evidence rows have already outlived it.
/// </summary>
public sealed record RetentionPreviewRow(
    Guid ScopeId,
    TimeSpan RetentionPeriod,
    DateTimeOffset CutoffUtc,
    long ExpiredCount);

/// <summary>What one sweep removed for a single scope under that scope's own configured window.</summary>
public sealed record RetentionScopeDeletion(
    Guid ScopeId,
    TimeSpan RetentionPeriod,
    long DeletedCount);

/// <summary>The outcome of one retention sweep, honest down to zero deletions.</summary>
public sealed record RetentionSweepResult(
    long TotalDeleted,
    IReadOnlyList<RetentionScopeDeletion> Scopes,
    bool SecureWipe,
    DateTimeOffset SweptAtUtc);

/// <summary>
/// The full outcome of walking the audit hash chain. Verification names the FIRST broken link so
/// an operator knows where tampering begins instead of only that it happened.
/// </summary>
public sealed record AuditChainVerification(
    bool Verified,
    long EventCount,
    long? FirstBrokenSequence,
    string? Reason);
