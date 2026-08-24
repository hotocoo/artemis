using System.Globalization;
using System.Text.RegularExpressions;
using ACT.Contracts;

namespace ACT.Web.Checks;

/// <summary>
/// ACT-WEB-HSTS-001: on HTTPS targets, verifies Strict-Transport-Security is present, parses,
/// and declares at least 30 days of max-age. Plain-HTTP targets are skipped: HSTS is defined
/// only for secure transport.
/// </summary>
public sealed partial class HstsCheck : HttpHeaderCheckBase
{
    /// <summary>Stable identifier of this check.</summary>
    public const string CheckIdValue = "ACT-WEB-HSTS-001";

    private const long MinimumMaxAgeSeconds = 2_592_000;

    /// <summary>Initializes a new instance of the <see cref="HstsCheck"/> class.</summary>
    public HstsCheck() => Id = new CheckId(CheckIdValue);

    private CheckId Id { get; }

    /// <inheritdoc />
    public override SecurityCheckMetadata Metadata { get; } = DefineMetadata(
        new CheckId(CheckIdValue),
        "HSTS Enforcement",
        Severity.Medium,
        minRequestsPerTarget: 1,
        maxRequestsPerTarget: 1,
        "Verifies that HTTPS targets send a valid Strict-Transport-Security header with adequate max-age.");

    /// <inheritdoc />
    protected override bool AppliesTo(Uri baseUrl) => IsSecureScheme(baseUrl);

    [GeneratedRegex(@"max-age\s*=\s*(\d+)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex MaxAgeRegex();

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
        var findings = new List<Finding>();
        var evidence = new List<EvidenceItem>();
        var header = FirstHeader(response, "Strict-Transport-Security");

        if (header is null)
        {
            findings.Add(BuildFinding(
                context, Id, origin, ResourcePathOf(baseUrl), "hsts_missing",
                "HTTPS service does not send Strict-Transport-Security",
                "The HTTPS response carries no Strict-Transport-Security header, so downgrade-stripping attacks and insecure scheme typos remain possible for visitors.",
                Severity.Medium, ConfidenceLevel.High, exploitabilityIndicator: false,
                whyItMatters: "Without HSTS an active attacker can force victims onto plain HTTP and read or modify traffic before the browser ever tries HTTPS.",
                technicalExplanation: "RFC 6797 requires the Strict-Transport-Security response header on secure responses to pin future requests to HTTPS.",
                remediation: new RemediationGuidance(
                    "Send an HSTS header on every HTTPS response.",
                    ["Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all HTTPS responses.", "Roll out gradually with a short max-age before committing to a long one."],
                    ["OWASP Secure Headers Project - HTTP Strict Transport Security", "RFC 6797"]));
            CollectEvidence(evidence, context.Assessment, findings[0].FindingId,
                EvidenceKind.HttpHeaders, "strict-transport-security", "<absent>", response.Correlation);
        }
        else if (!TryParseMaxAge(header, out var maxAge))
        {
            findings.Add(BuildFinding(
                context, Id, origin, ResourcePathOf(baseUrl), "hsts_invalid",
                "Strict-Transport-Security header is malformed",
                "The HSTS header cannot be parsed and browsers will ignore it entirely, leaving the site without transport pinning.",
                Severity.Medium, ConfidenceLevel.High, exploitabilityIndicator: false,
                whyItMatters: "A malformed header provides no protection while giving operators false confidence that HSTS is enabled.",
                technicalExplanation: "Browsers require a syntactically valid max-age directive (a non-negative integer) to honor HSTS policy.",
                remediation: new RemediationGuidance(
                    "Correct the HSTS header syntax.",
                    ["Emit exactly 'Strict-Transport-Security: max-age=<seconds>[; includeSubDomains]' with a numeric max-age."],
                    ["OWASP Secure Headers Project - HTTP Strict Transport Security", "RFC 6797"]));
            CollectEvidence(evidence, context.Assessment, findings[0].FindingId,
                EvidenceKind.HttpHeaders, "strict-transport-security", header, response.Correlation);
        }
        else if (maxAge < MinimumMaxAgeSeconds)
        {
            findings.Add(BuildFinding(
                context, Id, origin, ResourcePathOf(baseUrl), "hsts_max_age_below_minimum",
                "HSTS max-age below recommended 30 days",
                $"The HSTS max-age of {maxAge} seconds is shorter than the commonly accepted minimum of {MinimumMaxAgeSeconds} seconds (30 days), weakening long-term protection.",
                Severity.Low, ConfidenceLevel.High, exploitabilityIndicator: false,
                whyItMatters: "Short max-age windows let attackers wait out the policy and resume downgrade attacks soon afterwards.",
                technicalExplanation: "Long-lived max-age values are what give HSTS its durable protective effect across visits.",
                remediation: new RemediationGuidance(
                    "Raise the HSTS max-age.",
                    ["Increase max-age to at least 2592000 seconds once rollout stability is confirmed."],
                    ["OWASP Secure Headers Project - HTTP Strict Transport Security"]));
            CollectEvidence(evidence, context.Assessment, findings[0].FindingId,
                EvidenceKind.HttpHeaders, "strict-transport-security", header, response.Correlation);
        }

        return Complete(startedUtc, findings, evidence, requestCount: 1);
    }

    private static bool TryParseMaxAge(string header, out long maxAge)
    {
        var match = MaxAgeRegex().Match(header);
        maxAge = -1;
        return match.Success
            && long.TryParse(match.Groups[1].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out maxAge);
    }
}
