using System.Text.RegularExpressions;
using ACT.Contracts;

namespace ACT.Web.Checks;

/// <summary>
/// ACT-WEB-CACHECTRL-001: responses for sensitive paths must send Cache-Control: no-store.
/// Sensitivity defaults to the pattern login|signin|session|account over the request path and can
/// be replaced through the constructor-injected predicate. One Medium finding per sensitive path.
/// </summary>
public sealed partial class CacheControlCheck : HttpHeaderCheckBase
{
    /// <summary>Stable identifier of this check.</summary>
    public const string CheckIdValue = "ACT-WEB-CACHECTRL-001";

    private readonly Func<string, bool> _isSensitivePath;

    /// <summary>
    /// Initializes the check. The optional predicate receives the absolute request path and
    /// decides whether it is cache-sensitive; when omitted, paths matching login/signin/session/
    /// account (case-insensitive) are treated as sensitive.
    /// </summary>
    public CacheControlCheck(Func<string, bool>? sensitivePathPredicate = null)
    {
        Id = new CheckId(CheckIdValue);
        _isSensitivePath = sensitivePathPredicate ?? DefaultIsSensitivePath;
    }

    private CheckId Id { get; }

    /// <inheritdoc />
    public override SecurityCheckMetadata Metadata { get; } = DefineMetadata(
        new CheckId(CheckIdValue),
        "Sensitive Response Caching",
        Severity.Medium,
        minRequestsPerTarget: 1,
        maxRequestsPerTarget: 1,
        "Verifies Cache-Control: no-store on responses for login/session/account-style paths.");

    [GeneratedRegex(@"login|signin|session|account", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SensitivePathRegex();

    private static bool DefaultIsSensitivePath(string resourcePath) => SensitivePathRegex().IsMatch(resourcePath);

    /// <inheritdoc />
    protected override Task<SecurityCheckResult> AnalyzeAsync(
        SecurityCheckContext context,
        Uri baseUrl,
        SafeHttpResponse response,
        DateTimeOffset startedUtc,
        CancellationToken cancellationToken)
        => Task.FromResult(Analyze(context, baseUrl, response, startedUtc));

    private SecurityCheckResult Analyze(SecurityCheckContext context, Uri baseUrl, SafeHttpResponse response, DateTimeOffset startedUtc)
    {
        var path = ResourcePathOf(baseUrl);
        if (!_isSensitivePath(path))
        {
            return Complete(startedUtc, [], [], requestCount: 1);
        }

        var cacheControl = FirstHeader(response, "Cache-Control");
        if (cacheControl is not null && cacheControl.Contains("no-store", StringComparison.OrdinalIgnoreCase))
        {
            return Complete(startedUtc, [], [], requestCount: 1);
        }

        var findings = new List<Finding>();
        var evidence = new List<EvidenceItem>();
        findings.Add(BuildFinding(
            context, Id, NormalizeOrigin(baseUrl), path, "cache_control_missing_no_store",
            "Sensitive endpoint is missing Cache-Control: no-store",
            $"The response for sensitive path '{path}' does not declare no-store, so intermediaries and shared browsers caches may retain authentication-relevant content.",
            Severity.Medium, ConfidenceLevel.High, exploitabilityIndicator: false,
            whyItMatters: "Cached credentials, tokens, or personal data survive logout and shared-machine sessions and leak through cache reads.",
            technicalExplanation: "Cache-Control: no-store is the only directive that reliably forbids retention across all cache tiers.",
            remediation: new RemediationGuidance(
                "Send no-store on every sensitive response.",
                ["Emit 'Cache-Control: no-store' (optionally with 'private') on all authenticated and authentication-form responses."],
                ["OWASP Session Management Cheat Sheet - caching"]))); CollectEvidence(evidence, context.Assessment, findings[0].FindingId,
            EvidenceKind.HttpResponseMetadata, "cache-control", cacheControl ?? "<absent>", response.Correlation);

        return Complete(startedUtc, findings, evidence, requestCount: 1);
    }
}
