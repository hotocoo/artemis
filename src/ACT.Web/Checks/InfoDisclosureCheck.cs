using System.Text.RegularExpressions;
using ACT.Contracts;

namespace ACT.Web.Checks;

/// <summary>
/// ACT-WEB-INFODISCLOSURE-002: Server / X-Powered-By headers containing version-like values
/// (digits followed by a dot and digits) disclose fingerprinting material. ONE consolidated Low
/// finding lists the offending header names; raw header values reach only redacted evidence.
/// </summary>
public sealed partial class InfoDisclosureCheck : HttpHeaderCheckBase
{
    private static readonly string[] InspectedHeaders = ["Server", "X-Powered-By"];

    /// <summary>Stable identifier of this check.</summary>
    public const string CheckIdValue = "ACT-WEB-INFODISCLOSURE-002";

    /// <summary>Initializes a new instance of the <see cref="InfoDisclosureCheck"/> class.</summary>
    public InfoDisclosureCheck() => Id = new CheckId(CheckIdValue);

    private CheckId Id { get; }

    /// <inheritdoc />
    public override SecurityCheckMetadata Metadata { get; } = DefineMetadata(
        new CheckId(CheckIdValue),
        "Version Disclosure",
        Severity.Low,
        minRequestsPerTarget: 1,
        maxRequestsPerTarget: 1,
        "Detects version-bearing Server and X-Powered-By response headers.");

    [GeneratedRegex(@"\d+\.\d+", RegexOptions.CultureInvariant)]
    private static partial Regex VersionLikeRegex();

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
        var disclosing = InspectedHeaders
            .Where(headerName => JoinedHeader(response, headerName) is { } value && VersionLikeRegex().IsMatch(value))
            .ToList();
        if (disclosing.Count == 0)
        {
            return Complete(startedUtc, [], [], requestCount: 1);
        }

        var findings = new List<Finding>();
        var evidence = new List<EvidenceItem>();
        findings.Add(BuildFinding(
            context, Id, NormalizeOrigin(baseUrl), "/", "version_disclosure_headers",
            "Response headers disclose software versions",
            $"The response advertises version-bearing headers ({string.Join(", ", disclosing)}), letting attackers match the deployment against known vulnerabilities without probing.",
            Severity.Low, ConfidenceLevel.High, exploitabilityIndicator: false,
            whyItMatters: "Version banners shrink attacker reconnaissance to a database lookup and make targeted exploits cheaper.",
            technicalExplanation: "Server and X-Powered-By values are advisory metadata the application chooses to publish; removing them removes free intelligence.",
            remediation: new RemediationGuidance(
                "Suppress version information in server banners.",
                ["Configure the web server to omit version suffixes from Server.", "Remove X-Powered-By entirely at the framework or proxy layer."],
                ["OWASP Attack Surface Analyzer guidance on banner suppression"])));
        var dump = string.Join('\n', disclosing.Select(name => name + ": " + (JoinedHeader(response, name) ?? string.Empty)));
        CollectEvidence(evidence, context.Assessment, findings[0].FindingId,
            EvidenceKind.HttpHeaders, "version_bearing_headers", dump, response.Correlation);

        return Complete(startedUtc, findings, evidence, requestCount: 1);
    }
}
