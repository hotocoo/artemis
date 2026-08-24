
using System.Security.Cryptography;
using System.Text;

namespace ACT.Contracts;

/// <summary>
/// Deterministic fingerprinting: identical check+target+resource+class always yields the same
/// hash regardless of evidence wording, timestamps, or request noise.
/// </summary>
public static class FindingFingerprinter
{
    public static FindingFingerprint Fingerprint(FingerprintComponents components)
    {
        var canonical = string.Join('|',
            components.CheckId.Value.Trim().ToUpperInvariant(),
            Normalize(components.NormalizedTarget),
            Normalize(components.RelevantResource),
            Normalize(components.FindingClass));
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return new FindingFingerprint(Convert.ToHexString(bytes).ToLowerInvariant());
    }

    private static string Normalize(string input)
    {
        var trimmed = input.Trim().TrimEnd('/');
        var builder = new StringBuilder(trimmed.Length);
        foreach (var character in trimmed.ToLowerInvariant())
        {
            builder.Append(character switch
            {
                ' ' or '\t' or '\r' or '\n' => '_',
                _ => character
            });
        }
        return builder.ToString();
    }
}

/// <summary>Terse constructor for findings with all invariants enforced.</summary>
public static class FindingFactory
{
    public static Finding Create(
        Guid assessmentId,
        CheckId checkId,
        string targetDisplay,
        CheckCategory category,
        string title,
        string description,
        Severity severity,
        ConfidenceLevel confidence,
        bool exploitabilityIndicator,
        BusinessImpactLevel businessImpact,
        string whyItMatters,
        string technicalExplanation,
        RemediationGuidance remediation,
        FingerprintComponents fingerprintComponents,
        string? assetReference = null,
        Guid? regressionTestId = null,
        string? cvssVector = null,
        double? cvssBaseScore = null)
    {
        if (string.IsNullOrWhiteSpace(title)) throw new ArgumentException("Title required.", nameof(title));
        if (string.IsNullOrWhiteSpace(description)) throw new ArgumentException("Description required.", nameof(description));

        var now = DateTimeOffset.UtcNow;
        return new Finding(
            FindingId: Guid.NewGuid(),
            AssessmentId: assessmentId,
            CheckId: checkId,
            TargetDisplay: targetDisplay,
            AssetReference: assetReference,
            Category: category,
            Title: title,
            Description: description,
            TechnicalSeverity: severity,
            Confidence: confidence,
            ConfidenceScore: confidence switch
            {
                ConfidenceLevel.High => 0.9,
                ConfidenceLevel.Medium => 0.6,
                _ => 0.3
            },
            ExploitabilityIndicator: exploitabilityIndicator,
            BusinessImpact: businessImpact,
            WhyItMatters: whyItMatters,
            TechnicalExplanation: technicalExplanation,
            Remediation: remediation,
            FirstSeenUtc: now,
            LastSeenUtc: now,
            Status: FindingStatus.New,
            Fingerprint: FindingFingerprinter.Fingerprint(fingerprintComponents),
            RegressionTestId: regressionTestId,
            CvssVector: cvssVector,
            CvssBaseScore: cvssBaseScore);
    }

    /// <summary>Merges an incoming observation into an existing stored finding lifecycle-wise.</summary>
    public static Finding WithReobservation(Finding existing, DateTimeOffset seenAt) =>
        existing with
        {
            LastSeenUtc = seenAt > existing.LastSeenUtc ? seenAt : existing.LastSeenUtc
        };
}
