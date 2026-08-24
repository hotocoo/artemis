
namespace ACT.Contracts;

/// <summary>Kinds of targets an assessment may explicitly authorize.</summary>
public enum TargetTypeKind
{
    Localhost,
    PrivateIp,
    PrivateSubnet,
    Hostname,
    Domain,
    Url,
    LocalSourceRepository,
    LocalContainer,
    TestEnvironment
}

/// <summary>Application-level protocols a scope may permit.</summary>
public enum ProtocolKind
{
    Tcp,
    Tls,
    Http,
    Https
}

/// <summary>Inclusive port range; bounds validated to 1..65535.</summary>
public sealed record PortRange(int First, int Last)
{
    public static PortRange Single(int port) => new(port, port);

    public bool Contains(int port) => port >= First && port <= Last;

    public void Validate()
    {
        if (First is < 1 or > 65535 || Last is < 1 or > 65535 || First > Last)
        {
            throw ActException.FailClosed(ErrorCategory.Scope,
                "A permitted port range in the scope configuration is invalid.",
                $"Invalid PortRange [{First}-{Last}].");
        }
    }

    public override string ToString() => First == Last ? First.ToString() : $"{First}-{Last}";
}

/// <summary>Deterministic redaction strength applied before evidence persistence.</summary>
public enum RedactionPolicy
{
    /// <summary>Known credential headers and secret-like values are redacted.</summary>
    Standard,

    /// <summary>All headers except an allowlist are redacted; secret-like values redacted everywhere.</summary>
    Strict
}

/// <summary>Categories of checks; scopes enable/disable whole categories.</summary>
public enum CheckCategory
{
    Network,
    Tls,
    Http,
    Api,
    Authorization,
    Source,
    Dependency,
    Configuration
}

/// <summary>
/// The hard authorization boundary for one assessment. Every field must be explicit.
/// Nothing about this object may be inferred from DNS, redirects, or discovery results.
/// </summary>
public sealed record ScopeDefinition(
    Guid ScopeId,
    Guid AssessmentId,
    string OperatorIdentity,
    string Organization,
    TargetTypeKind TargetType,
    IReadOnlyList<string> AllowlistedTargets,
    IReadOnlyList<string> ExcludedTargets,
    IReadOnlyList<ProtocolKind> PermittedProtocols,
    IReadOnlyList<PortRange> PermittedPorts,
    double RequestsPerSecond,
    int ConcurrencyLimit,
    TimeSpan MaxRuntime,
    long MaxRequests,
    IReadOnlyList<CheckCategory> AllowedCategories,
    IReadOnlyList<CheckCategory> ProhibitedCategories,
    bool EmergencyStopEnabled,
    TimeSpan EvidenceRetentionPeriod,
    RedactionPolicy DataRedactionPolicy,
    string AuthorizationStatement)
{
    /// <summary>Fails closed when any structural invariant of the scope is violated.</summary>
    public void Validate()
    {
        var problems = new List<string>();
        if (ScopeId == Guid.Empty) problems.Add("ScopeId missing.");
        if (string.IsNullOrWhiteSpace(OperatorIdentity)) problems.Add("Operator identity missing.");
        if (string.IsNullOrWhiteSpace(Organization)) problems.Add("Organization missing.");
        if (AllowlistedTargets.Count == 0) problems.Add("Allowlist empty: no target may ever be tested.");
        if (PermittedPorts.Count == 0 && TargetType is not (TargetTypeKind.LocalSourceRepository or TargetTypeKind.LocalContainer))
            problems.Add("No permitted ports configured.");
        foreach (var range in PermittedPorts)
        {
            try { range.Validate(); }
            catch (ActException ex) { problems.Add(ex.DiagnosticDetail); }
        }
        if (RequestsPerSecond <= 0) problems.Add("Rate limit must be positive.");
        if (ConcurrencyLimit <= 0) problems.Add("Concurrency limit must be positive.");
        if (MaxRuntime <= TimeSpan.Zero) problems.Add("Maximum runtime must be positive.");
        if (MaxRequests <= 0) problems.Add("Maximum requests must be positive.");
        if (ProhibitedCategories.Contains(CheckCategory.Network) && PermittedPorts.Count > 0 && TargetType != TargetTypeKind.LocalSourceRepository)
            problems.Add("Network category prohibited but ports permitted: contradictory scope.");
        if (ProhibitedCategories.Count + AllowedCategories.Count == 0) problems.Add("No category policy configured.");
        foreach (var allowed in AllowedCategories)
        {
            if (ProhibitedCategories.Contains(allowed))
                problems.Add($"Category {allowed} appears in both allowed and prohibited lists.");
        }
        if (!EmergencyStopEnabled) problems.Add("Emergency stop cannot be disabled.");
        if (EvidenceRetentionPeriod <= TimeSpan.Zero) problems.Add("Evidence retention period must be positive.");
        if (string.IsNullOrWhiteSpace(AuthorizationStatement)) problems.Add("Signed authorization statement required.");

        if (problems.Count > 0)
        {
            throw ActException.FailClosed(ErrorCategory.Scope,
                "The scope configuration is invalid.",
                "Scope validation failed: " + string.Join(" | ", problems));
        }
    }
}

/// <summary>Structured verdict of a single authorization question about one candidate target.</summary>
public sealed record ScopeDecision(
    bool Allowed,
    string ReasonCode,
    string SafeMessage,
    string DiagnosticDetail,
    string? MatchedAllowlistEntry,
    string? MatchedExclusionEntry)
{
    public static ScopeDecision Allow(string matched, string detail) =>
        new(true, "ALLOWLIST_MATCH", "Target is within the authorized scope.", detail, matched, null);

    public static ScopeDecision Deny(string reasonCode, string safeMessage, string diagnosticDetail,
        string? matchedExclusion = null) =>
        new(false, reasonCode, safeMessage, diagnosticDetail, null, matchedExclusion);
}

/// <summary>Validates candidate hosts, URLs, IPs, and redirect hops against a scope.</summary>
public interface IScopeValidator
{
    /// <summary>Decides whether the exact target (host + optional port + optional scheme) may be contacted.</summary>
    ScopeDecision Evaluate(TargetCandidate candidate);

    /// <summary>Decides whether a redirect hop may be followed. Redirects never inherit trust.</summary>
    ScopeDecision EvaluateRedirect(Uri originalUri, Uri redirectTarget);

    /// <summary>Resolves and verifies that every resolved address of host stays within scope.</summary>
    Task<ScopeDecision> EvaluateResolvedAsync(string host, int port, CancellationToken cancellationToken);
}

/// <summary>A specific contactable endpoint candidate.</summary>
public sealed record TargetCandidate(string Host, int Port, ProtocolKind Protocol, Uri? Url)
{
    public static TargetCandidate FromUri(Uri uri)
    {
        var protocol = uri.Scheme switch
        {
            "https" => ProtocolKind.Https,
            "http" => ProtocolKind.Http,
            _ => ProtocolKind.Tcp
        };
        return new TargetCandidate(uri.Host, uri.IsDefaultPort ? DefaultPort(protocol) : uri.Port, protocol, uri);
    }

    public static int DefaultPort(ProtocolKind protocol) => protocol switch
    {
        ProtocolKind.Https => 443,
        ProtocolKind.Http => 80,
        _ => throw ActException.FailClosed(ErrorCategory.Scope,
            "Protocol has no default port.", "DefaultPort requested for non-web protocol.")
    };
}
