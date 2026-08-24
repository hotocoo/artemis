using ACT.Contracts;

namespace ACT.Web.Checks;

/// <summary>
/// ACT-WEB-COOKIE-001: inspects Set-Cookie values and emits exactly one finding per deficiency
/// CLASS across all cookies: missing Secure over HTTPS (Medium), missing HttpOnly on session-like
/// cookie names (Medium), and missing SameSite (Low). Fingerprints use the attribute class, never
/// the cookie name; names appear only in descriptions and redacted evidence.
/// </summary>
public sealed class CookieFlagCheck : HttpHeaderCheckBase
{
    /// <summary>Stable identifier of this check.</summary>
    public const string CheckIdValue = "ACT-WEB-COOKIE-001";

    /// <summary>Initializes a new instance of the <see cref="CookieFlagCheck"/> class.</summary>
    public CookieFlagCheck() => Id = new CheckId(CheckIdValue);

    private CheckId Id { get; }

    /// <inheritdoc />
    public override SecurityCheckMetadata Metadata { get; } = DefineMetadata(
        new CheckId(CheckIdValue),
        "Cookie Attribute Hardening",
        Severity.Medium,
        minRequestsPerTarget: 1,
        maxRequestsPerTarget: 1,
        "Verifies Secure, HttpOnly, and SameSite attributes on cookies returned by the target.");

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
        var origin = NormalizeOrigin(baseUrl);
        var path = ResourcePathOf(baseUrl);
        var findings = new List<Finding>();
        var evidence = new List<EvidenceItem>();
        var missingSecure = new List<string>();
        var missingHttpOnly = new List<string>();
        var missingSameSite = new List<string>();

        foreach (var rawCookie in HeaderValues(response, "Set-Cookie"))
        {
            if (ParseCookie(rawCookie) is not { } cookie)
            {
                continue;
            }

            if (IsSecureScheme(baseUrl) && !cookie.HasSecure)
            {
                missingSecure.Add(cookie.Name);
            }

            if (!cookie.HasHttpOnly && IsSessionLike(cookie.Name))
            {
                missingHttpOnly.Add(cookie.Name);
            }

            if (!cookie.HasSameSite)
            {
                missingSameSite.Add(cookie.Name);
            }
        }

        if (missingSecure.Count > 0)
        {
            EmitClassFinding(context, origin, path, findings, evidence, response.Correlation,
                "cookie_secure_flag_missing", Severity.Medium,
                "Cookies sent without the Secure attribute over HTTPS",
                $"Cookies transmitted over HTTPS lack the Secure attribute: {Describe(missingSecure)}. They will also travel on any plain-HTTP request to this origin's host.",
                whyItMatters: "Without the Secure attribute a single downgrade or mixed-content request leaks the cookie value in cleartext.",
                technicalExplanation: "The Secure attribute restricts cookie transmission to encrypted channels as defined by RFC 6265bis.",
                remediationSummary: "Add the Secure attribute to every cookie.",
                evidenceKey: "cookies_missing_secure");
        }

        if (missingHttpOnly.Count > 0)
        {
            EmitClassFinding(context, origin, path, findings, evidence, response.Correlation,
                "cookie_httponly_flag_missing", Severity.Medium,
                "Session-like cookies are readable from client-side scripts",
                $"Session-like cookies lack the HttpOnly attribute: {Describe(missingHttpOnly)}. Any cross-site scripting flaw can exfiltrate these session values.",
                whyItMatters: "HttpOnly keeps session identifiers out of reach of JavaScript, containing the blast radius of XSS vulnerabilities.",
                technicalExplanation: "The HttpOnly attribute hides the cookie from document.cookie and all client-side script access.",
                remediationSummary: "Set HttpOnly on every session-bearing cookie.",
                evidenceKey: "cookies_missing_httponly");
        }

        if (missingSameSite.Count > 0)
        {
            EmitClassFinding(context, origin, path, findings, evidence, response.Correlation,
                "cookie_samesite_attribute_missing", Severity.Low,
                "Cookies sent without a SameSite attribute",
                $"Cookies are issued without any SameSite attribute: {Describe(missingSameSite)}. Browsers fall back to differing defaults, leaving some requests open to cross-site sending.",
                whyItMatters: "Explicit SameSite policies prevent cookies from riding along on cross-site requests that enable CSRF-style attacks.",
                technicalExplanation: "SameSite=Lax or Strict restricts cross-site cookie inclusion; absence defers to browser defaults that have varied over time.",
                remediationSummary: "Declare an explicit SameSite attribute on every cookie.",
                evidenceKey: "cookies_missing_samesite");
        }

        return Complete(startedUtc, findings, evidence, requestCount: 1);
    }

    private void EmitClassFinding(
        SecurityCheckContext context,
        string origin,
        string path,
        List<Finding> findings,
        List<EvidenceItem> evidence,
        CorrelationId correlation,
        string findingClass,
        Severity severity,
        string title,
        string description,
        string whyItMatters,
        string technicalExplanation,
        string remediationSummary,
        string evidenceKey)
    {
        findings.Add(BuildFinding(
            context, Id, origin, path, findingClass, title, description,
            severity, ConfidenceLevel.High, exploitabilityIndicator: false,
            whyItMatters,
            technicalExplanation,
            new RemediationGuidance(
                remediationSummary,
                [remediationSummary + " Apply it uniformly to all cookies issued by the application."],
                ["OWASP Session Management Cheat Sheet", "RFC 6265bis"])));
        CollectEvidence(evidence, context.Assessment, findings[^1].FindingId,
            EvidenceKind.HttpHeaders, evidenceKey, description, correlation);
    }

    private static string Describe(IReadOnlyList<string> cookieNames)
        => string.Join(", ", cookieNames.Select(n => "'" + n + "'"));

    private static ParsedCookie? ParseCookie(string rawValue)
    {
        var segments = rawValue.Split(';');
        var separatorIndex = segments[0].IndexOf('=');
        if (separatorIndex <= 0)
        {
            return null;
        }

        var name = segments[0][..separatorIndex].Trim();
        if (name.Length == 0)
        {
            return null;
        }

        var attributes = segments.Skip(1).Select(segment => segment.Trim()).ToArray();
        return new ParsedCookie(
            name,
            HasAttribute(attributes, "secure", exactMatch: true),
            HasAttribute(attributes, "httponly", exactMatch: true),
            HasAttribute(attributes, "samesite", exactMatch: false));
    }

    private static bool HasAttribute(string[] attributes, string attributeName, bool exactMatch)
        => exactMatch
            ? attributes.Any(a => a.Equals(attributeName, StringComparison.OrdinalIgnoreCase))
            : attributes.Any(a => a.StartsWith(attributeName, StringComparison.OrdinalIgnoreCase));

    private static bool IsSessionLike(string cookieName)
        => cookieName.Contains("sess", StringComparison.OrdinalIgnoreCase)
           || cookieName.Contains("auth", StringComparison.OrdinalIgnoreCase)
           || cookieName.Contains("token", StringComparison.OrdinalIgnoreCase);

    private sealed record ParsedCookie(string Name, bool HasSecure, bool HasHttpOnly, bool HasSameSite);
}
