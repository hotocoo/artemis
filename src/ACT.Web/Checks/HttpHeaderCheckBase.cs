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
    private static readonly ConditionalWeakTable<SecurityCheckContext, ResponseCacheEntry> ResponseCache = new();

    /// <inheritdoc />
    public abstract SecurityCheckMetadata Metadata { get; }

    /// <summary>
    /// Maximum number of same-origin paths (including the root) probed per target. Bounded so a
    /// chatty landing page can never exhaust the request budget or turn a header check into a crawler.
    /// </summary>
    protected const int MaxProbePaths = 12;

    /// <summary>
    /// Runs the check: validates applicability preconditions, discovers a bounded set of same-origin
    /// paths from the landing page, fetches (or reuses) each response, then delegates analysis to the
    /// derived class for every probed URL. Findings and evidence from all paths are combined so a
    /// path-specific defect (e.g. permissive CORS on /api, missing HSTS on /login) is reported.
    /// </summary>
    public virtual async Task<SecurityCheckResult> ExecuteAsync(SecurityCheckContext context, CancellationToken cancellationToken)
    {
        var startedUtc = DateTimeOffset.UtcNow;
        if (context.BaseUrl is not { } baseUrl || !IsWebScheme(baseUrl.Scheme) || !AppliesTo(baseUrl))
        {
            return SkipNotApplicable(startedUtc);
        }

        var probeUrls = await DiscoverProbeUrlsAsync(context, baseUrl, cancellationToken).ConfigureAwait(false);

        var findings = new List<Finding>();
        var evidence = new List<EvidenceItem>();
        long requestCount = 0;
        var targetsExamined = 0;
        var allCompleted = true;

        foreach (var url in probeUrls)
        {
            cancellationToken.ThrowIfCancellationRequested();
            SafeHttpResponse response;
            try
            {
                response = await FetchAsync(context, url, cancellationToken).ConfigureAwait(false);
            }
            catch (ActException)
            {
                // A path may fail closed (e.g. an out-of-scope redirect). Skip it and keep probing.
                allCompleted = false;
                continue;
            }
            var result = await AnalyzeAsync(context, url, response, startedUtc, cancellationToken).ConfigureAwait(false);
            findings.AddRange(result.Findings);
            evidence.AddRange(result.StandaloneEvidence);
            requestCount += result.RequestCount;
            targetsExamined += result.TargetsExamined;
            if (result.Status is not (CheckExecutionStatus.Completed or CheckExecutionStatus.CompletedWithWarnings))
            {
                allCompleted = false;
            }
        }

        return new SecurityCheckResult(
            Metadata.Id,
            allCompleted ? CheckExecutionStatus.Completed : CheckExecutionStatus.CompletedWithWarnings,
            startedUtc,
            DateTimeOffset.UtcNow,
            findings,
            evidence,
            FailureSummarySafe: null,
            RequestCount: requestCount,
            TargetsExamined: targetsExamined);
    }

    /// <summary>
    /// Discovers a bounded set of same-origin probe paths from the landing page. Always includes the
    /// base URL itself. Extracts candidate paths from href/src/action attributes, filters to
    /// same-origin relative or absolute paths, deduplicates, and caps at MaxProbePaths.
    /// </summary>
    protected virtual async Task<IReadOnlyList<Uri>> DiscoverProbeUrlsAsync(
        SecurityCheckContext context, Uri baseUrl, CancellationToken cancellationToken)
    {
        var urls = new List<Uri> { baseUrl };
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        seen.Add(baseUrl.AbsolutePath);

        try
        {
            var rootResponse = await FetchAsync(context, baseUrl, cancellationToken).ConfigureAwait(false);
            var html = rootResponse.BodyAsText();

            foreach (var candidate in ExtractPathCandidates(html))
            {
                if (urls.Count >= MaxProbePaths) break;

                Uri? probeUrl = null;
                if (candidate.StartsWith("/", StringComparison.Ordinal) && !candidate.StartsWith("//"))
                {
                    probeUrl = new Uri(baseUrl, candidate);
                }
                else if (Uri.TryCreate(candidate, UriKind.Absolute, out var abs) &&
                         IsWebScheme(abs.Scheme) && abs.Host.Equals(baseUrl.Host, StringComparison.OrdinalIgnoreCase) &&
                         abs.Port == baseUrl.Port)
                {
                    probeUrl = abs;
                }

                if (probeUrl is not null && seen.Add(probeUrl.AbsolutePath))
                {
                    urls.Add(probeUrl);
                }
            }
        }
        catch (ActException)
        {
            // Scope or transport failure on discovery: fall back to probing only the root.
        }

        return urls;
    }

    /// <summary>
    /// Extracts candidate path strings from HTML href/src/action attributes using a bounded regex.
    /// Never throws; returns an empty list on any parse issue.
    /// </summary>
    private static IEnumerable<string> ExtractPathCandidates(string html)
    {
        if (string.IsNullOrWhiteSpace(html)) yield break;

        var matches = System.Text.RegularExpressions.Regex.Matches(
            html,
            @"(?:href|src|action)\s*=\s*[""']([^""'#?]+)[""']",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

        foreach (System.Text.RegularExpressions.Match match in matches)
        {
            var value = match.Groups[1].Value.Trim();
            if (value.Length > 0 && value.Length <= 500)
            {
                yield return value;
            }
        }
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
        var entry = ResponseCache.GetOrCreateValue(context);
        if (entry.Responses.TryGetValue(url, out var cached))
        {
            return cached;
        }

        var response = await context.Assessment.Http
            .SendAsync(SafeHttpRequest.Get(url, CorrelationId.New()), cancellationToken).ConfigureAwait(false);
        entry.Responses[url] = response;
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

    /// <summary>Per-context holder enabling response reuse across derived analyses and probe paths.</summary>
    private sealed class ResponseCacheEntry
    {
        public readonly System.Collections.Concurrent.ConcurrentDictionary<Uri, SafeHttpResponse> Responses = new();
    }
}
