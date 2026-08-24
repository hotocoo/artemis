
using Microsoft.Extensions.Logging;

namespace ACT.Contracts;

/// <summary>Safety classification of a check's actions against targets.</summary>
public enum SafetyLevel
{
    /// <summary>No target contact at all (local analysis).</summary>
    LocalOnly,

    /// <summary>Reads protocol metadata without sending application payloads where possible.</summary>
    Passive,

    /// <summary>Sends only harmless, idempotent requests (GET/HEAD/OPTIONS, benign TLS handshakes).</summary>
    SafeRequestOnly,

    /// <summary>Active but non-destructive verification using operator-supplied fixtures only.</summary>
    ActiveNonDestructive
}

/// <summary>Permissions a check declares it needs; policy can deny each one.</summary>
[Flags]
public enum PermissionRequirement
{
    None = 0,

    /// <summary>Open outbound connections to allowlisted local targets only.</summary>
    OutboundNetworkToLocalTargets = 1 << 0,

    /// <summary>Read files inside the operator-provided repository path.</summary>
    ReadRepositoryFiles = 1 << 1,

    /// <summary>Read the local ACT database.</summary>
    ReadLocalDatabase = 1 << 2,

    /// <summary>Use credentials explicitly supplied as test fixtures.</summary>
    UseProvidedTestCredentials = 1 << 3
}

/// <summary>Declares the network footprint a check expects to make.</summary>
public sealed record NetworkBehaviorProfile(
    int MinRequestsPerTarget,
    int MaxRequestsPerTarget,
    bool OpensConnections,
    bool SendsAuthenticationHeaders,
    bool MutatesTargetState);

/// <summary>Self-describing metadata every check must declare before it can ever run.</summary>
public sealed record SecurityCheckMetadata(
    CheckId Id,
    string Name,
    string Version,
    CheckCategory Category,
    Severity MaxEmittingSeverity,
    SafetyLevel SafetyLevel,
    PermissionRequirement RequiredPermissions,
    IReadOnlySet<ProtocolKind> RequiredProtocols,
    IReadOnlySet<TargetTypeKind> SupportedTargetTypes,
    NetworkBehaviorProfile NetworkBehavior,
    IReadOnlyList<EvidenceKind> EvidenceTypesProduced,
    bool SupportsRemediation,
    bool SupportsRegressionTest,
    string Description)
{
    public void Validate()
    {
        var problems = new List<string>();
        if (string.IsNullOrWhiteSpace(Id.Value)) problems.Add("Check id missing.");
        if (!char.IsAsciiLetter(Id.Value.FirstOrDefault())) problems.Add("Check id should start with an ascii letter.");
        if (MaxEmittingSeverity > Severity.Critical) problems.Add("Severity out of range.");
        if (NetworkBehavior.MaxRequestsPerTarget < NetworkBehavior.MinRequestsPerTarget)
            problems.Add("Network behavior request bounds inverted.");
        if (MutatesTargets && SafetyLevel != SafetyLevel.ActiveNonDestructive)
            problems.Add("Only ActiveNonDestructive checks may mutate target state.");
        if (problems.Count > 0)
        {
            throw ActException.FailClosed(ErrorCategory.SecurityCheck,
                $"Security check '{Id.Value}' declared invalid metadata.",
                "Metadata validation failed: " + string.Join(" | ", problems));
        }
    }

    private bool MutatesTargets => NetworkBehavior.MutatesTargetState;
}

/// <summary>Bounded resource envelope enforced around every assessment and every check.</summary>
public sealed record ResourceBudget(
    int MaxConcurrency,
    long MaxRequests,
    long MaxResponseBytes,
    long MaxBodyBytes,
    long MaxFileBytes,
    long MemoryBudgetBytes,
    TimeSpan PerOperationTimeout,
    TimeSpan TotalRuntime,
    int MaxConnectionsPerHost,
    int MaxRedirects)
{
    public static ResourceBudget FromScope(ScopeDefinition scope, EngineDefaults defaults) => new(
        Math.Min(scope.ConcurrencyLimit, defaults.MaxConcurrency),
        Math.Min(scope.MaxRequests, defaults.MaxRequestsPerAssessment),
        defaults.MaxResponseBytes,
        defaults.MaxBodyBytes,
        defaults.MaxFileBytes,
        defaults.MemoryBudgetBytes,
        defaults.PerOperationTimeout,
        scope.MaxRuntime,
        defaults.MaxConnectionsPerHost,
        defaults.MaxRedirects);
}

/// <summary>Conservative engine-wide default limits. Config may tighten, never loosen silently.</summary>
public sealed record EngineDefaults(
    int MaxConcurrency,
    long MaxRequestsPerAssessment,
    long MaxResponseBytes,
    long MaxBodyBytes,
    long MaxFileBytes,
    long MemoryBudgetBytes,
    TimeSpan PerOperationTimeout,
    int MaxConnectionsPerHost,
    int MaxRedirects)
{
    public static EngineDefaults Conservative { get; } = new(
        MaxConcurrency: 8,
        MaxRequestsPerAssessment: 10_000,
        MaxResponseBytes: 4 * 1024 * 1024,
        MaxBodyBytes: 2 * 1024 * 1024,
        MaxFileBytes: 20 * 1024 * 1024,
        MemoryBudgetBytes: 768L * 1024 * 1024,
        PerOperationTimeout: TimeSpan.FromSeconds(15),
        MaxConnectionsPerHost: 4,
        MaxRedirects: 5);
}

/// <summary>Token-bucket admission control shared by all network work for an assessment.</summary>
public interface IRateLimiter
{
    /// <summary>Waits until one token is available or cancellation fires.</summary>
    ValueTask WaitForTokenAsync(CancellationToken cancellationToken);
}

/// <summary>A safe HTTP engine that enforces scope after redirects, size limits, timeouts, and rate limits.</summary>
public interface ISafeHttpEngine : IAsyncDisposable
{
    /// <summary>Executes a request under full safety controls. Redirect hops are individually re-authorized.</summary>
    Task<SafeHttpResponse> SendAsync(SafeHttpRequest request, CancellationToken cancellationToken);
}

/// <summary>Request description handed to the safe HTTP engine.</summary>
public sealed record SafeHttpRequest(
    HttpMethod Method,
    Uri Url,
    IReadOnlyDictionary<string, string> Headers,
    ReadOnlyMemory<byte>? Body,
    CorrelationId Correlation,
    TimeSpan? TimeoutOverride = null)
{
    public static SafeHttpRequest Get(Uri url, CorrelationId correlation) =>
        new(HttpMethod.Get, url, new Dictionary<string, string>(), null, correlation);
}

/// <summary>Response produced by the safe engine. Body already size-limited and fully buffered within budget.</summary>
public sealed record SafeHttpResponse(
    int StatusCode,
    IReadOnlyDictionary<string, string[]> Headers,
    byte[] BodyBytes,
    Uri FinalUri,
    IReadOnlyList<RedirectHop> RedirectTrail,
    TimeSpan Elapsed,
    CorrelationId Correlation,
    bool TruncatedDueToLimits,
    string? ContentType)
{
    public string BodyAsText() =>
        System.Text.Encoding.UTF8.GetString(BodyBytes.AsSpan(0, BodyBytes.Length));

    public string? HeaderSingle(string name) =>
        Headers.TryGetValue(name, out var values) && values.Length > 0 ? values[0] : null;
}

/// <summary>One followed redirect hop recorded as evidence.</summary>
public sealed record RedirectHop(Uri From, Uri To, int StatusCode);

/// <summary>Cancellation-aware execution context passed into every check.</summary>
public sealed record SecurityCheckContext(
    AssessmentContext Assessment,
    AssetRecord Asset,
    ServiceObservation? Service,
    Uri? BaseUrl)
{
    public CancellationToken CancellationToken => Assessment.CancellationToken;
}

/// <summary>Ledger where checks register discovered assets and services for persistence.</summary>
public interface IAssessmentLedger
{
    /// <summary>Registers an asset if new; returns its stable id.</summary>
    Task<AssetRecord> RecordAssetAsync(AssetRecord asset, CancellationToken cancellationToken);

    /// <summary>Registers a service observation on an asset.</summary>
    Task<ServiceObservation> RecordServiceAsync(ServiceObservation service, CancellationToken cancellationToken);

    /// <summary>All services observed so far in this assessment.</summary>
    IReadOnlyList<ServiceObservation> ObservedServices();
}

/// <summary>Shared per-assessment services and guardrails available to checks.</summary>
public sealed record AssessmentContext(
    Guid AssessmentId,
    ScopeDefinition Scope,
    IScopeValidator ScopeValidator,
    ISafeHttpEngine Http,
    IRateLimiter RateLimiter,
    IEvidenceFactory Evidence,
    ILogger Logger,
    AuthorizationFixtureSet Fixtures,
    ResourceBudget Budget,
    IAssessmentLedger Ledger,
    ILanguageModelProvider? LanguageModel)
{
    public CancellationToken CancellationToken { get; init; }
}

/// <summary>Result contract every check returns.</summary>
public enum CheckExecutionStatus
{
    Completed,
    CompletedWithWarnings,
    Skipped_NotApplicable,
    Skipped_PolicyDenied,
    Skipped_OutOfScope,
    Failed_FailedClosed,
    TimedOut
}

/// <summary>The single result object produced by one executed security check.</summary>
public sealed record SecurityCheckResult(
    CheckId CheckId,
    CheckExecutionStatus Status,
    DateTimeOffset StartedUtc,
    DateTimeOffset CompletedUtc,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<EvidenceItem> StandaloneEvidence,
    string? FailureSummarySafe,
    long RequestCount,
    int TargetsExamined)
{
    public static SecurityCheckResult Empty(SecurityCheckMetadata meta, DateTimeOffset started,
        CheckExecutionStatus status, string? note = null) =>
        new(meta.Id, status, started, DateTimeOffset.UtcNow, [], [], note, 0, 0);
}

/// <summary>
/// A security check. Implementations must be pure with respect to global state: everything they
/// need arrives through the context, everything they produce leaves through typed results.
/// </summary>
public interface ISecurityCheck
{
    SecurityCheckMetadata Metadata { get; }

    Task<SecurityCheckResult> ExecuteAsync(SecurityCheckContext context, CancellationToken cancellationToken);
}
