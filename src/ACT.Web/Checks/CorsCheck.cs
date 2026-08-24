using ACT.Contracts;

namespace ACT.Web.Checks;

/// <summary>
/// ACT-WEB-CORS-001: analyzes Access-Control-Allow-Origin on the fetched response and performs
/// one OPTIONS reflection probe carrying a synthetic Origin. Wildcard allowance on auth-indicating
/// responses (Vary includes Authorization or a WWW-Authenticate challenge is present) is High;
/// a plain wildcard is Low; an echoed probe Origin is High. No credentials are ever sent.
/// </summary>
public sealed class CorsCheck : HttpHeaderCheckBase
{
    /// <summary>Stable identifier of this check.</summary>
    public const string CheckIdValue = "ACT-WEB-CORS-001";

    /// <summary>Synthetic probe origin used for the reflection test (RFC 2606 reserved TLD).</summary>
    public const string ProbeOrigin = "https://act-probe.invalid";

    /// <summary>Initializes a new instance of the <see cref="CorsCheck"/> class.</summary>
    public CorsCheck() => Id = new CheckId(CheckIdValue);

    private CheckId Id { get; }

    /// <inheritdoc />
    public override SecurityCheckMetadata Metadata { get; } = DefineMetadata(
        new CheckId(CheckIdValue),
        "Cross-Origin Resource Sharing",
        Severity.High,
        minRequestsPerTarget: 1,
        maxRequestsPerTarget: 2,
        "Inspects CORS headers and probes origin reflection with one credential-free OPTIONS request.");

    /// <inheritdoc />
    protected override async Task<SecurityCheckResult> AnalyzeAsync(
        SecurityCheckContext context,
        Uri baseUrl,
        SafeHttpResponse response,
        DateTimeOffset startedUtc,
        CancellationToken cancellationToken)
    {
        var origin = NormalizeOrigin(baseUrl);
        var path = ResourcePathOf(baseUrl);
        var findings = new List<Finding>();
        var evidence = new List<EvidenceItem>();
        long requests = 1;

        if (FirstHeader(response, "Access-Control-Allow-Origin") is { } allowOrigin && allowOrigin.Trim() == "*")
        {
            var variesOnAuthorization = FirstHeader(response, "Vary")?.Split(',')
                .Any(v => v.Trim().Equals("Authorization", StringComparison.OrdinalIgnoreCase)) == true;
            var issuesAuthenticationChallenge = HasHeader(response, "WWW-Authenticate");

            if (variesOnAuthorization || issuesAuthenticationChallenge)
            {
                findings.Add(BuildFinding(
                    context, Id, origin, path, "cors_wildcard_on_authenticated_response",
                    "CORS wildcard applied to authentication-bearing responses",
                    "The response grants Access-Control-Allow-Origin: * while also being authentication-indicating (Vary: Authorization or WWW-Authenticate present). Any origin can read these responses once credentials or challenges flow through shared caches or browsers.",
                    Severity.High, ConfidenceLevel.High, exploitabilityIndicator: true,
                    whyItMatters: "Wildcard CORS on authenticated endpoints lets malicious websites read protected data directly from a victim's browser session.",
                    technicalExplanation: "A wildcard ACAO cannot be combined with credentialed requests safely; auth-bearing responses must echo specific vetted origins instead.",
                    remediation: new RemediationGuidance(
                        "Restrict CORS to an explicit allowlist of origins.",
                        ["Echo only vetted origins from configuration instead of '*'.", "Keep Vary: Origin so caches never serve mismatched ACAO values."],
                        ["OWASP Cross-Origin Resource Sharing Cheat Sheet"]));
                CollectEvidence(evidence, context.Assessment, findings[^1].FindingId,
                    EvidenceKind.HttpHeaders, "access-control-allow-origin", allowOrigin, response.Correlation);
            }
            else
            {
                findings.Add(BuildFinding(
                    context, Id, origin, path, "cors_wildcard_origin",
                    "CORS allows any origin to read responses",
                    "The response declares Access-Control-Allow-Origin: *, allowing scripts on every website to read this resource cross-origin.",
                    Severity.Low, ConfidenceLevel.High, exploitabilityIndicator: false,
                    whyItMatters: "Public wildcard reading is acceptable for static public data but becomes a defect the moment any sensitive field appears in the payload.",
                    technicalExplanation: "Wildcard ACAO disables same-origin protection for this resource for all origins simultaneously.",
                    remediation: new RemediationGuidance(
                        "Scope CORS to origins that genuinely need access.",
                        ["Replace '*' with an explicit origin allowlist."],
                        ["OWASP Cross-Origin Resource Sharing Cheat Sheet"]));
                CollectEvidence(evidence, context.Assessment, findings[^1].FindingId,
                    EvidenceKind.HttpHeaders, "access-control-allow-origin", allowOrigin, response.Correlation);
            }
        }

        var probeRequest = new SafeHttpRequest(
            Method: HttpMethod.Options,
            Url: baseUrl,
            Headers: new Dictionary<string, string>
            {
                ["Origin"] = ProbeOrigin,
                ["Access-Control-Request-Method"] = "GET"
            },
            Body: null,
            Correlation: CorrelationId.New());
        var probeResponse = await context.Assessment.Http.SendAsync(probeRequest, cancellationToken).ConfigureAwait(false);
        requests++;

        if (FirstHeader(probeResponse, "Access-Control-Allow-Origin") is { } reflectedOrigin
            && reflectedOrigin.Trim().Equals(ProbeOrigin, StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(BuildFinding(
                context, Id, origin, path, "cors_origin_reflection",
                "CORS reflects arbitrary Origin headers",
                "An OPTIONS preflight carrying an untrusted Origin received that exact value back in Access-Control-Allow-Origin, meaning any website can be granted programmatic read access.",
                Severity.High, ConfidenceLevel.High, exploitabilityIndicator: true,
                whyItMatters: "Reflected origins make every website a trusted reader of this endpoint whenever a victim's browser can authenticate to it.",
                technicalExplanation: "Echoing arbitrary Origin values without validation turns the server into a permissive CORS grantor.",
                remediation: new RemediationGuidance(
                    "Validate origins against an explicit allowlist before echoing.",
                    ["Compare the request Origin against configured trusted origins and deny all others.", "Never reflect the Origin header verbatim."],
                    ["OWASP Cross-Origin Resource Sharing Cheat Sheet"]));
            CollectEvidence(evidence, context.Assessment, findings[^1].FindingId,
                EvidenceKind.HttpResponseMetadata, "reflected_probe_origin", ProbeOrigin, response.Correlation);
        }

        return Complete(startedUtc, findings, evidence, requests);
    }
}
