using System.Runtime.CompilerServices;
using ACT.Contracts;

namespace ACT.Web.Checks;

/// <summary>
/// Shared plumbing for HTTP-response-header checks: performs exactly one safe GET of the scoped
/// base URL per check-context (cached on the context instance and reused by every derived
/// analysis), skips cleanly when no applicable web target is configured, and centralizes
/// finding, evidence, and request-accounting construction. Derived checks send GET, HEAD,
/// or OPTIONS requests only; authentication material is never attached.
/// </summary>
public abstract class HttpHeaderCheckBase : ISecurityCheck
{
    private static readonly ConditionalWeakTable<SecurityCheckContext, ResponseSlot> ResponseCache = new();

    /// <inheritdoc />
    public abstract SecurityCheckMetadata Metadata { get; }

    /// <summary>
    /// Runs the check: validates applicability preconditions, fetches (or reuses) the target
    /// response once, then delegates analysis to the derived class.
    /// </summary>
    public virtual async Task<SecurityCheckResult> ExecuteAsync(SecurityCheckContext context, CancellationToken cancellationToken)
    {
        var startedUtc = DateTimeOffset.UtcNow;
        if (context.BaseUrl is not { } baseUrl || !IsWebScheme(baseUrl.Scheme) || !AppliesTo(baseUrl))
        {
            return SkipNotApplicable(startedUtc);
        }

        var response = await FetchAsync(context, baseUrl, cancellationToken).ConfigureAwait(false);
        return await AnalyzeAsync(context, baseUrl, response, startedUtc, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Analyzes the fetched response and produces the check result.</summary>
    protected abstract Task<SecurityCheckResult> AnalyzeAsync(
        SecurityCheckContext context,
        Uri baseUrl,
        SafeHttpResponse response,
        DateTimeOffset startedUtc,
        CancellationToken cancellationToken);

    /// <summary>Pre-flight applicability test evaluated before any request is sent.</summary>
    protected virtual bool AppliesTo(Uri baseUrl) => true;

    /// <summary>
    /// Fetches the URL with one safe GET, reusing a response previously fetched for the same
    /// context instance so co-located analyses never duplicate traffic. Concurrent callers may
    /// race benignly: the request is idempotent and scope-enforced by the safe engine.
    /// </summary>
    protected virtual async Task<SafeHttpResponse> FetchAsync(
        SecurityCheckContext context, Uri url, CancellationToken cancellationToken)
    {
        var slot = ResponseCache.GetOrCreateValue(context);
        if (slot.Response is { } cached && slot.Url is { } cachedUrl && cachedUrl.Equals(url))
        {
            return cached;
        }

        var response = await context.Assessment.Http
            .SendAsync(SafeHttpRequest.Get(url, CorrelationId.New()), cancellationToken).ConfigureAwait(false);
        slot.Url = url;
        slot.Response = response;
        return response;
    }

    /// <summary>Builds the standard honest metadata block shared by all web header checks.</summary>
    protected static SecurityCheckMetadata DefineMetadata(
        CheckId id,
        string name,
        Severity maxEmittingSeverity,
        int minRequestsPerTarget,
        int maxRequestsPerTarget,
        string description)
        => new(
            Id: id,
            Name: name,
            Version: "1.0.0",
            Category: CheckCategory.Http,
            MaxEmittingSeverity: maxEmittingSeverity,
            SafetyLevel: SafetyLevel.SafeRequestOnly,
            RequiredPermissions: PermissionRequirement.OutboundNetworkToLocalTargets,
            RequiredProtocols: new HashSet<ProtocolKind> { ProtocolKind.Http, ProtocolKind.Https },
            SupportedTargetTypes: new HashSet<TargetTypeKind> { TargetTypeKind.Url },
            NetworkBehavior: new NetworkBehaviorProfile(
                minRequestsPerTarget, maxRequestsPerTarget,
                OpensConnections: true, SendsAuthenticationHeaders: false, MutatesTargetState: false),
            EvidenceTypesProduced: [EvidenceKind.HttpResponseMetadata, EvidenceKind.HttpHeaders],
            SupportsRemediation: true,
            SupportsRegressionTest: true,
            Description: description);

    /// <summary>Returns the first value of the named header, matched case-insensitively.</summary>
    protected static string? FirstHeader(SafeHttpResponse response, string headerName)
        => RawValues(response, headerName) is { Length: > 0 } values ? values[0] : null;

    /// <summary>True when the named header is present with at least one value.</summary>
    protected static bool HasHeader(SafeHttpResponse response, string headerName)
        => RawValues(response, headerName) is { Length: > 0 };

    /// <summary>Every raw value of the named header across duplicate entries.</summary>
    protected static string[] HeaderValues(SafeHttpResponse response, string headerName)
        => RawValues(response, headerName) ?? [];

    /// <summary>All values of the named header joined with "; ", or null when absent.</summary>
    protected static string? JoinedHeader(SafeHttpResponse response, string headerName)
        => RawValues(response, headerName) is { Length: > 0 } values ? string.Join("; ", values) : null;

    private static string[]? RawValues(SafeHttpResponse response, string headerName)
        => response.Headers.FirstOrDefault(h => h.Key.Equals(headerName, StringComparison.OrdinalIgnoreCase)).Value;

    /// <summary>Scheme + host + explicit port: the stable identity used in fingerprints.</summary>
    protected static string NormalizeOrigin(Uri uri)
        => uri.IsDefaultPort
            ? $"{uri.Scheme}://{uri.Host}"
            : $"{uri.Scheme}://{uri.Host}:{uri.Port}";

    /// <summary>Absolute path of the URL, always rooted ('/' for bare origins).</summary>
    protected static string ResourcePathOf(Uri uri)
    {
        var path = uri.AbsolutePath;
        return path.Length == 0 ? "/" : path;
    }

    /// <summary>True for the only URL schemes this check family ever contacts.</summary>
    protected static bool IsWebScheme(string scheme)
        => scheme.Equals("http", StringComparison.OrdinalIgnoreCase)
           || scheme.Equals("https", StringComparison.OrdinalIgnoreCase);

    /// <summary>True when the URL uses https.</summary>
    protected static bool IsSecureScheme(Uri uri) => uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);

    /// <summary>Constructs a deduplicated finding anchored to check + origin + path + class.</summary>
    protected static Finding BuildFinding(
        SecurityCheckContext context,
        CheckId checkId,
        string origin,
        string resourcePath,
        string findingClass,
        string title,
        string description,
        Severity severity,
        ConfidenceLevel confidence,
        bool exploitabilityIndicator,
        string whyItMatters,
        string technicalExplanation,
        RemediationGuidance remediation)
        => FindingFactory.Create(
            context.Assessment.AssessmentId,
            checkId,
            origin,
            CheckCategory.Http,
            title,
            description,
            severity,
            confidence,
            exploitabilityIndicator,
            ImpactFor(severity),
            whyItMatters,
            technicalExplanation,
            remediation,
            new FingerprintComponents(checkId, origin, resourcePath, findingClass),
            assetReference: context.Asset.CanonicalTarget);

    /// <summary>Creates a redacted evidence item for the finding and appends it to the sink.</summary>
    protected EvidenceItem CollectEvidence(
        List<EvidenceItem> sink,
        AssessmentContext assessment,
        Guid findingId,
        EvidenceKind kind,
        string key,
        string value,
        CorrelationId correlation)
    {
        var item = assessment.Evidence.Create(findingId, kind, key, value, Metadata.Id, correlation);
        sink.Add(item);
        return item;
    }

    /// <summary>Completed-result builder carrying findings, evidence, and request accounting.</summary>
    protected SecurityCheckResult Complete(
        DateTimeOffset startedUtc,
        IReadOnlyList<Finding> findings,
        IReadOnlyList<EvidenceItem> evidence,
        long requestCount)
        => new(
            Metadata.Id,
            CheckExecutionStatus.Completed,
            startedUtc,
            DateTimeOffset.UtcNow,
            findings,
            evidence,
            FailureSummarySafe: null,
            RequestCount: requestCount,
            TargetsExamined: 1);

    /// <summary>Clean skip for contexts without an applicable web target.</summary>
    protected SecurityCheckResult SkipNotApplicable(DateTimeOffset startedUtc)
        => SecurityCheckResult.Empty(Metadata, startedUtc, CheckExecutionStatus.Skipped_NotApplicable);

    private static BusinessImpactLevel ImpactFor(Severity severity) => severity switch
    {
        Severity.Critical or Severity.High => BusinessImpactLevel.Significant,
        Severity.Medium => BusinessImpactLevel.Limited,
        _ => BusinessImpactLevel.Negligible
    };

    /// <summary>Per-context holder enabling response reuse across derived analyses.</summary>
    private sealed class ResponseSlot
    {
        public Uri? Url;
        public SafeHttpResponse? Response;
    }
}
