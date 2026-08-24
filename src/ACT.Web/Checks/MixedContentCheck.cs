using System.Text.RegularExpressions;
using ACT.Contracts;

namespace ACT.Web.Checks;

/// <summary>
/// ACT-WEB-MIXEDCONTENT-001: an HTTPS page embedding src="http://..." or href="http://..."
/// references weakens the origin. Emits ONE Medium finding per page (fingerprint anchored to the
/// page path); matched reference strings go to redacted evidence only, never into descriptions.
/// </summary>
public sealed partial class MixedContentCheck : HttpHeaderCheckBase
{
    /// <summary>Stable identifier of this check.</summary>
    public const string CheckIdValue = "ACT-WEB-MIXEDCONTENT-001";

    /// <summary>Initializes a new instance of the <see cref="MixedContentCheck"/> class.</summary>
    public MixedContentCheck() => Id = new CheckId(CheckIdValue);

    private CheckId Id { get; }

    /// <inheritdoc />
    public override SecurityCheckMetadata Metadata { get; } = DefineMetadata(
        new CheckId(CheckIdValue),
        "Mixed Content",
        Severity.Medium,
        minRequestsPerTarget: 1,
        maxRequestsPerTarget: 1,
        "Scans HTTPS page bodies for src/href references that use plain http:// URLs.");

    /// <inheritdoc />
    protected override bool AppliesTo(Uri baseUrl) => IsSecureScheme(baseUrl);

    [GeneratedRegex(@"\b(?:src|href)\b\s*=\s*[""']http://[^""'>\s]*",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex InsecureReferenceRegex();

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
        var body = response.BodyAsText();
        var matches = InsecureReferenceRegex().Matches(body);
        if (matches.Count == 0)
        {
            return Complete(startedUtc, [], [], requestCount: 1);
        }

        var findings = new List<Finding>();
        var evidence = new List<EvidenceItem>();
        findings.Add(BuildFinding(
            context, Id, NormalizeOrigin(baseUrl), ResourcePathOf(baseUrl), "mixed_content_reference",
            "HTTPS page loads references over plain HTTP",
            $"The encrypted page embeds {matches.Count} src/href reference(s) using insecure http:// URLs. Browsers may block them, or an on-path attacker can substitute hostile content.",
            Severity.Medium, ConfidenceLevel.High, exploitabilityIndicator: true,
            whyItMatters: "A single insecurely loaded script or style can fully compromise a page served over HTTPS; passive references still leak user context.",
            technicalExplanation: "Mixed content breaks the transport guarantee of the enclosing https document and triggers browser blocking or downgrade warnings.",
            remediation: new RemediationGuidance(
                "Serve every embedded reference over HTTPS.",
                ["Update all http:// src and href values to https.", "Add a Content-Security-Policy with upgrade-insecure-requests during migration."],
                ["OWASP Secure Headers Project", "MDN Mixed content guide"])));
        var samples = matches.Cast<System.Text.RegularExpressions.Match>()
            .Select(m => m.Value.Trim('"', '\''))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(10);
        CollectEvidence(evidence, context.Assessment, findings[0].FindingId,
            EvidenceKind.HttpResponseMetadata, "insecure_references", string.Join('\n', samples), response.Correlation);

        return Complete(startedUtc, findings, evidence, requestCount: 1);
    }
}
