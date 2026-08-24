using System.Text.RegularExpressions;
using ACT.Contracts;

namespace ACT.Web.Checks;

/// <summary>
/// ACT-WEB-CSP-001: HTML responses must carry a Content-Security-Policy (Medium when absent).
/// When script-src or default-src allows 'unsafe-inline' without any nonce or hash source,
/// a separate Informational finding records the weakened script policy.
/// </summary>
public sealed partial class CspCheck : HttpHeaderCheckBase
{
    /// <summary>Stable identifier of this check.</summary>
    public const string CheckIdValue = "ACT-WEB-CSP-001";

    /// <summary>Initializes a new instance of the <see cref="CspCheck"/> class.</summary>
    public CspCheck() => Id = new CheckId(CheckIdValue);

    private CheckId Id { get; }

    /// <inheritdoc />
    public override SecurityCheckMetadata Metadata { get; } = DefineMetadata(
        new CheckId(CheckIdValue),
        "Content Security Policy",
        Severity.Medium,
        minRequestsPerTarget: 1,
        maxRequestsPerTarget: 1,
        "Verifies that HTML responses declare a Content-Security-Policy and flags inline-script allowances.");

    [GeneratedRegex(@"'?(?:nonce-[A-Za-z0-9+/=_-]+|sha(?:256|384|512)-[A-Za-z0-9+/=_-]+)'?", RegexOptions.CultureInvariant)]
    private static partial Regex NonceOrHashRegex();

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
        var contentType = response.ContentType ?? string.Empty;
        if (!contentType.Contains("text/html", StringComparison.OrdinalIgnoreCase))
        {
            return Complete(startedUtc, [], [], requestCount: 1);
        }

        var origin = NormalizeOrigin(baseUrl);
        var findings = new List<Finding>();
        var evidence = new List<EvidenceItem>();
        var policy = FirstHeader(response, "Content-Security-Policy");

        if (policy is null)
        {
            findings.Add(BuildFinding(
                context, Id, origin, ResourcePathOf(baseUrl), "csp_missing",
                "HTML response lacks a Content-Security-Policy",
                "The HTML response declares no Content-Security-Policy, so injected inline or third-party scripts run without browser-side restriction.",
                Severity.Medium, ConfidenceLevel.High, exploitabilityIndicator: false,
                whyItMatters: "CSP is the strongest available mitigation against cross-site scripting because it bounds where scripts may come from even after an injection.",
                technicalExplanation: "Content-Security-Policy restricts the sources from which documents load executable and embeddable content.",
                remediation: new RemediationGuidance(
                    "Define a restrictive Content-Security-Policy for HTML responses.",
                    ["Start with 'default-src \'self\'' and add only the origins the application truly needs.", "Prefer nonce- or hash-based script-src over unsafe-inline."],
                    ["OWASP Secure Headers Project - Content Security Policy", "MDN Content-Security-Policy guide"])));            CollectEvidence(evidence, context.Assessment, findings[0].FindingId,
                EvidenceKind.HttpHeaders, "content-security-policy", "<absent>", response.Correlation);
        }
        else if (AllowsInlineScripts(policy))
        {
            findings.Add(BuildFinding(
                context, Id, origin, ResourcePathOf(baseUrl), "csp_unsafe_inline_script_source",
                "Content-Security-Policy permits inline scripts without nonce or hash",
                "The effective script-src/default-src policy contains 'unsafe-inline' and no nonce or hash source, allowing any injected inline script to execute despite CSP being present.",
                Severity.Informational, ConfidenceLevel.High, exploitabilityIndicator: false,
                whyItMatters: "An allow-all inline policy removes most of the XSS protection a CSP would otherwise provide.",
                technicalExplanation: "'unsafe-inline' authorizes inline script elements and event handlers unless a nonce or hash source also present takes precedence in modern browsers.",
                remediation: new RemediationGuidance(
                    "Replace unsafe-inline with nonce- or hash-based script sources.",
                    ["Generate a per-response nonce and add it to every script element.", "Alternatively pin known inline scripts with sha256/sha384/sha512 hashes."],
                    ["OWASP Secure Headers Project - Content Security Policy"])));            CollectEvidence(evidence, context.Assessment, findings[0].FindingId,
                EvidenceKind.HttpHeaders, "content-security-policy", policy, response.Correlation);
        }

        return Complete(startedUtc, findings, evidence, requestCount: 1);
    }

    private static bool AllowsInlineScripts(string policy)
    {
        bool? scriptSourceVerdict = null;
        bool? defaultSourceVerdict = null;

        foreach (var rawDirective in policy.Split(';'))
        {
            var directive = rawDirective.Trim();
            if (directive.Length == 0)
            {
                continue;
            }

            var separator = directive.IndexOfAny([' ', '\t']);
            var name = separator < 0 ? directive : directive[..separator].ToLowerInvariant();
            if (name is not ("script-src" or "default-src"))
            {
                continue;
            }

            var sources = separator < 0
                ? []
                : directive[(separator + 1)..].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            var verdict = sources.Any(s => s.Trim('\'').Equals("unsafe-inline", StringComparison.OrdinalIgnoreCase))
                          && !sources.Any(NonceOrHashRegex().IsMatch);

            if (name == "script-src")
            {
                scriptSourceVerdict ??= verdict;
            }
            else
            {
                defaultSourceVerdict ??= verdict;
            }
        }

        return scriptSourceVerdict ?? defaultSourceVerdict ?? false;
    }
}
