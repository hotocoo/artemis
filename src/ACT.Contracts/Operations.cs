
namespace ACT.Contracts;

/// <summary>Expected state of one service in a security baseline.</summary>
public sealed record ServiceBaselineEntry(int Port, ProtocolKind Protocol, BaselineServiceStatus Status);

public enum BaselineServiceStatus
{
    Expected,
    Prohibited
}

/// <summary>A stored security baseline used for drift detection.</summary>
public sealed record SecurityBaseline(
    Guid BaselineId,
    Guid ScopeId,
    string Name,
    IReadOnlyList<ServiceBaselineEntry> ExpectedServices,
    IReadOnlyList<string> AcceptedFindingFingerprints,
    DateTimeOffset CreatedUtc);

/// <summary>One drift observation produced by comparing current state against a baseline.</summary>
public sealed record DriftObservation(
    string Kind,
    string Detail,
    Severity SuggestedSeverity,
    string FingerprintSuffix);

public enum ScheduleTriggerKind
{
    Manual,
    Scheduled,
    ContinuousIntegration
}

/// <summary>A stored schedule. Schedules always reference a persisted scope and can never widen it.</summary>
public sealed record ScheduleDefinition(
    Guid ScheduleId,
    string Name,
    Guid ScopeId,
    string CronExpression,
    ScheduleTriggerKind Trigger,
    bool Enabled,
    DateTimeOffset CreatedUtc,
    DateTimeOffset? LastRunUtc);

/// <summary>Counters captured for one assessment run.</summary>
public sealed record ScanMetricsRecord(
    Guid AssessmentId,
    long RequestsSent,
    long ChecksExecuted,
    long ChecksFailed,
    long FindingsEmitted,
    TimeSpan TotalDuration,
    long BytesReceived);

/// <summary>Dashboard aggregates computed exclusively from persisted rows.</summary>
public sealed record DashboardMetricsSnapshot(
    int AssessmentsTotal,
    int AssetsAssessed,
    int ServicesObserved,
    int FindingsOpen,
    int FindingsCriticalOrHigh,
    int FindingsConfirmed,
    int FindingsRemediated,
    int RegressionsDetected,
    long ChecksExecuted,
    long ChecksFailed,
    int FalsePositives,
    double AverageScanDurationMinutes,
    long RequestCount,
    double CurrentRiskScore,
    DateTimeOffset ComputedUtc);

/// <summary>CI gate decision inputs and outcome.</summary>
public sealed record CiGateDecision(
    bool ShouldFailBuild,
    IReadOnlyList<string> Reasons,
    IReadOnlyList<Finding> TriggeringFindings);
