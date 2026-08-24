using ACT.Contracts;

namespace ACT.Web.Checks;

/// <summary>
/// ACT-WEB-SECHEADERS-002: baseline hardening headers. Emits ONE consolidated Medium finding
/// listing every absent header among X-Content-Type-Options (must be nosniff), Referrer-Policy,
/// and Permissions-Policy, anchored to resource path '/'.
/// </summary>
public sealed class SecurityHeadersCheck : HttpHeaderCheckBase
{
    private static readonly string[] ReferrerPolicyOptions =
    [
        "no-referrer", "no-referrer-when-downgrade", "same-origin", "strict-origin",
        "strict-origin-when-cross-origin", "origin", "origin-when-cross-origin", "unsafe-url"
    ];

    /// <summary>Stable identifier of this check.</summary>
    public const string CheckIdValue = "ACT-WEB-SECHEADERS-002";

    /// <summary>Initializes a new instance of the <see cref="SecurityHeadersCheck"/> class.</summary>
    public SecurityHeadersCheck() => Id = new CheckId(CheckIdValue);

    private CheckId Id { get; }

    /// <inheritdoc />
    public override SecurityCheckMetadata Metadata { get; } = DefineMetadata(
        new CheckId(CheckIdValue),
        "Security Header Baseline",
        Severity.Medium,
        minRequestsPerTarget: 1,
        maxRequestsPerTarget: 1,
        "Verifies the baseline set of nosniff, Referrer-Policy, and Permissions-Policy response headers.");

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
        var findings = new List<Finding>();
        var evidence = new List<EvidenceItem>();
        var absent = new List<string>();

        var contentTypeOptions = FirstHeader(response, "X-Content-Type-Options");
        if (contentTypeOptions is null || !contentTypeOptions.Trim().Equals("nosniff", StringComparison.OrdinalIgnoreCase))
        {
            absent.Add("X-Content-Type-Options");
        }

        if (FirstHeader(response, "Referrer-Policy") is not { } referrerPolicy || !ReferrerPolicyOptions.Contains(referrerPolicy.Trim(), StringComparer.OrdinalIgnoreCase))
        {
            absent.Add("Referrer-Policy");
        }

        if (!HasHeader(response, "Permissions-Policy"))
        {
            absent.Add("Permissions-Policy");
        }

        if (absent.Count > 0)
        {
            findings.Add(BuildFinding(
                context, Id, NormalizeOrigin(baseUrl), "/", "security_headers_baseline_missing",
                "Baseline security headers are missing",
                $"The response omits required hardening headers: {string.Join(", ", absent)}. Each missing header leaves a distinct browser-side attack surface open.",
                Severity.Medium, ConfidenceLevel.High, exploitabilityIndicator: false,
                whyItMatters: "These headers cost nothing at runtime and close whole bug classes: MIME confusion, referrer leakage, and unneeded powerful browser features.",
                technicalExplanation: "X-Content-Type-Options: nosniff blocks MIME-type guessing; Referrer-Policy bounds cross-origin URL leakage; Permissions-Policy disables powerful features by default.",
                remediation: new RemediationGuidance(
                    "Send the full baseline of security headers on every response.",
                    ["Add 'X-Content-Type-Options: nosniff'.", "Add a strict 'Referrer-Policy' such as strict-origin-when-cross-origin.", "Add a 'Permissions-Policy' disabling unused powerful features."],
                    ["OWASP Secure Headers Project"]));
            CollectEvidence(evidence, context.Assessment, findings[0].FindingId,
                EvidenceKind.HttpResponseMetadata, "absent_security_headers", string.Join(", ", absent), response.Correlation);
        }

        return Complete(startedUtc, findings, evidence, requestCount: 1);
    }
}
