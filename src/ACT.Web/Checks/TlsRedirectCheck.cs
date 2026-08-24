using System.Globalization;
using ACT.Contracts;

namespace ACT.Web.Checks;

/// <summary>
/// ACT-WEB-TLSREDIRECT-001: when the scope validator permits BOTH schemes for the origin pair,
/// fetches the plain-HTTP form and expects 301/302/308 redirecting to https. A 200 OK yields one
/// Medium finding; a redirect that does not land on https likewise. Validator denial skips the
/// check before any request is sent.
/// </summary>
public sealed class TlsRedirectCheck : HttpHeaderCheckBase
{
    /// <summary>Stable identifier of this check.</summary>
    public const string CheckIdValue = "ACT-WEB-TLSREDIRECT-001";

    /// <summary>Initializes a new instance of the <see cref="TlsRedirectCheck"/> class.</summary>
    public TlsRedirectCheck() => Id = new CheckId(CheckIdValue);

    private CheckId Id { get; }

    /// <inheritdoc />
    public override SecurityCheckMetadata Metadata { get; } = DefineMetadata(
        new CheckId(CheckIdValue),
        "HTTPS Upgrade Redirect",
        Severity.Medium,
        minRequestsPerTarget: 1,
        maxRequestsPerTarget: 1,
        "Verifies that the plain-HTTP form of the target redirects to HTTPS with 301, 302, or 308.");

    /// <inheritdoc />
    public override async Task<SecurityCheckResult> ExecuteAsync(SecurityCheckContext context, CancellationToken cancellationToken)
    {
        var startedUtc = DateTimeOffset.UtcNow;
        if (context.BaseUrl is not { } baseUrl || !IsWebScheme(baseUrl.Scheme))
        {
            return SkipNotApplicable(startedUtc);
        }

        var httpUri = baseUrl.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase)
            ? baseUrl
            : SwapScheme(baseUrl, "http");
        var httpsUri = baseUrl.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase)
            ? baseUrl
            : SwapScheme(baseUrl, "https");

        // Both directions must be authorized before this check contacts anything.
        var httpAllowed = context.Assessment.ScopeValidator.Evaluate(TargetCandidate.FromUri(httpUri)).Allowed;
        var httpsAllowed = context.Assessment.ScopeValidator.Evaluate(TargetCandidate.FromUri(httpsUri)).Allowed;
        if (!httpAllowed || !httpsAllowed)
        {
            return SecurityCheckResult.Empty(Metadata, startedUtc, CheckExecutionStatus.Skipped_OutOfScope);
        }

        var response = await FetchAsync(context, httpUri, cancellationToken).ConfigureAwait(false);
        return Analyze(context, baseUrl, httpUri, response, startedUtc);
    }

    private SecurityCheckResult Analyze(
        SecurityCheckContext context, Uri baseUrl, Uri httpUri, SafeHttpResponse response, DateTimeOffset startedUtc)
    {
        var findings = new List<Finding>();
        var evidence = new List<EvidenceItem>();
        var origin = NormalizeOrigin(baseUrl);
        var path = ResourcePathOf(httpUri);

        switch (response.StatusCode)
        {
            case 301 or 302 or 308:
                if (!LocationUpgradesToHttps(response, httpUri))
                {
                    findings.Add(BuildFinding(
                        context, Id, origin, path, "tls_redirect_not_upgrading",
                        "Plain-HTTP redirect does not land on HTTPS",
                        "The server redirects plain-HTTP traffic but the Location target does not use HTTPS, keeping a downgrade path open to network attackers.",
                        Severity.Medium, ConfidenceLevel.High, exploitabilityIndicator: false,
                        whyItMatters: "A redirect to another plain-HTTP location provides no transport protection at all.",
                        technicalExplanation: "Only redirects whose Location resolves to an https URL remove cleartext exposure.",
                        remediation: new RemediationGuidance(
                            "Redirect plain-HTTP requests directly to their HTTPS equivalent.",
                            ["Emit 'Location: https://<host>/<same-path>' with status 301 or 308 for every HTTP request."],
                            ["OWASP Transport Layer Protection Cheat Sheet"]));
                    CollectEvidence(evidence, context.Assessment, findings[^1].FindingId,
                        EvidenceKind.StatusCode, "redirect_status", response.StatusCode.ToString(CultureInfo.InvariantCulture), response.Correlation);
                }
                break;

            case 200:
                findings.Add(BuildFinding(
                    context, Id, origin, path, "tls_redirect_missing",
                    "Plain-HTTP origin serves content without redirecting to HTTPS",
                    "The plain-HTTP origin answered 200 OK instead of redirecting to HTTPS, so users following links by scheme receive content over unencrypted transport.",
                    Severity.Medium, ConfidenceLevel.High, exploitabilityIndicator: false,
                    whyItMatters: "Without an automatic upgrade every visitor who types the bare hostname exchanges all traffic in cleartext.",
                    technicalExplanation: "Serving 200 OK over HTTP means no HSTS preload entry can exist and no forced upgrade happens client-side.",
                    remediation: new RemediationGuidance(
                        "Redirect all plain-HTTP traffic to HTTPS.",
                        ["Return 301 or 308 with the https equivalent URL for every HTTP request.", "Consider HSTS after the redirect is stable."],
                        ["OWASP Transport Layer Protection Cheat Sheet"]));
                CollectEvidence(evidence, context.Assessment, findings[^1].FindingId,
                    EvidenceKind.StatusCode, "http_status", "200", response.Correlation);
                break;

            default:
                // Other statuses are inconclusive for upgrade behavior; report nothing honestly.
                break;
        }

        return Complete(startedUtc, findings, evidence, requestCount: 1);
    }

    private static bool LocationUpgradesToHttps(SafeHttpResponse response, Uri httpUri)
    {
        var location = FirstHeader(response, "Location");
        if (string.IsNullOrWhiteSpace(location))
        {
            return false;
        }

        try
        {
            if (!Uri.TryCreate(location.Trim(), UriKind.RelativeOrAbsolute, out var parsed))
            {
                return false;
            }

            var absolute = parsed.IsAbsoluteUri ? parsed : new Uri(httpUri, parsed);
            return absolute.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase);
        }
        catch (UriFormatException)
        {
            return false;
        }
    }

    private static Uri SwapScheme(Uri uri, string scheme)
        => new($"{scheme}://{uri.Host}{(uri.IsDefaultPort ? string.Empty : ":" + uri.Port.ToString(CultureInfo.InvariantCulture))}{uri.PathAndQuery}{uri.Fragment}");
}
