using System.Security.Cryptography;
using System.Text;
using ACT.Contracts;

namespace ACT.Reporting;

/// <summary>Detects service- and finding-level drift between a stored baseline and fresh results.</summary>
public static class DriftAnalyzer
{
    /// <summary>Kind code for a prohibited service answering on a port.</summary>
    public const string UnexpectedServiceExposed = "unexpected-service-exposed";

    /// <summary>Kind code for an expected service missing from observations.</summary>
    public const string ExpectedServiceAbsent = "expected-service-absent";

    /// <summary>Kind code for a finding whose fingerprint the baseline does not accept.</summary>
    public const string NewFinding = "finding-new";

    /// <summary>Kind code for an accepted fingerprint that no longer appears among the findings.</summary>
    public const string ResolvedFinding = "finding-resolved";

    /// <summary>Kind code for a remediated finding detected again.</summary>
    public const string RegressedFinding = "finding-regressed";

    /// <summary>
    /// Compares baseline expectations against observations. A prohibited port that answers is High
    /// severity ("Unexpected service exposed"); an expected port that is missing is Medium severity
    /// ("Expected service absent").
    /// </summary>
    public static IReadOnlyList<DriftObservation> Compare(SecurityBaseline baseline, IReadOnlyList<ServiceObservation> observations)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        ArgumentNullException.ThrowIfNull(observations);

        var observed = observations.Select(static o => (o.Port, o.Protocol)).ToHashSet();
        var reportedProhibited = new HashSet<(int Port, ProtocolKind Protocol)>();
        var reportedMissing = new HashSet<(int Port, ProtocolKind Protocol)>();
        var drift = new List<DriftObservation>();

        foreach (var observation in observations)
        {
            if (!reportedProhibited.Add((observation.Port, observation.Protocol)))
            {
                continue;
            }

            var prohibited = baseline.ExpectedServices.Any(entry =>
                entry.Port == observation.Port
                && entry.Protocol == observation.Protocol
                && entry.Status == BaselineServiceStatus.Prohibited);
            if (!prohibited)
            {
                continue;
            }

            drift.Add(new DriftObservation(
                UnexpectedServiceExposed,
                "Unexpected service exposed: port " + observation.Port + "/" + observation.Protocol + " answered although the baseline marks it prohibited.",
                Severity.High,
                Suffix(baseline.BaselineId, UnexpectedServiceExposed, observation.Port, observation.Protocol)));
        }

        foreach (var entry in baseline.ExpectedServices)
        {
            if (entry.Status != BaselineServiceStatus.Expected
                || observed.Contains((entry.Port, entry.Protocol))
                || !reportedMissing.Add((entry.Port, entry.Protocol)))
            {
                continue;
            }

            drift.Add(new DriftObservation(
                ExpectedServiceAbsent,
                "Expected service absent: port " + entry.Port + "/" + entry.Protocol + " is expected by the baseline but was not observed.",
                Severity.Medium,
                Suffix(baseline.BaselineId, ExpectedServiceAbsent, entry.Port, entry.Protocol)));
        }

        return [.. drift
            .OrderBy(static d => d.Kind, StringComparer.Ordinal)
            .ThenBy(static d => d.Detail, StringComparer.Ordinal)];
    }

    /// <summary>
    /// Compares a baseline against the findings of one fresh assessment. A fingerprint the baseline
    /// does not accept is NEW drift at the finding's own technical severity (never inflated or
    /// discounted); a remediated finding detected again is REGRESSED; an accepted fingerprint that
    /// no longer appears is RESOLVED - worded honestly, because absence alone cannot distinguish
    /// a fix from checks that simply did not run this time.
    /// </summary>
    public static IReadOnlyList<DriftObservation> CompareFindings(SecurityBaseline baseline, IReadOnlyList<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        ArgumentNullException.ThrowIfNull(findings);

        var accepted = baseline.AcceptedFindingFingerprints.ToHashSet(StringComparer.Ordinal);
        var present = new HashSet<string>(StringComparer.Ordinal);
        var drift = new List<DriftObservation>();

        foreach (var finding in findings)
        {
            var fingerprint = finding.Fingerprint.Hash;
            if (!present.Add(fingerprint))
            {
                continue;
            }

            if (accepted.Contains(fingerprint))
            {
                // Explicitly dispositioned by an operator through triage before baseline creation;
                // re-observing it is the expected steady state, not drift.
                continue;
            }

            var regressed = finding.Status == FindingStatus.Regressed;
            var kind = regressed ? RegressedFinding : NewFinding;
            var detail = regressed
                ? "Regressed finding: '" + finding.Title + "' (" + finding.TechnicalSeverity
                    + ", check " + finding.CheckId.Value + ") was remediated but was detected again; "
                    + "fingerprint " + Short(fingerprint) + "."
                : "New finding versus baseline: '" + finding.Title + "' (" + finding.TechnicalSeverity
                    + ", check " + finding.CheckId.Value + ", status " + finding.Status
                    + ") is not in the accepted set; fingerprint " + Short(fingerprint) + ".";
            drift.Add(new DriftObservation(
                kind,
                detail,
                finding.TechnicalSeverity,
                FingerprintSuffix(baseline.BaselineId, kind, fingerprint)));
        }

        foreach (var fingerprint in baseline.AcceptedFindingFingerprints.OrderBy(static f => f, StringComparer.Ordinal))
        {
            if (present.Contains(fingerprint))
            {
                continue;
            }

            drift.Add(new DriftObservation(
                ResolvedFinding,
                "Resolved or unobserved: accepted fingerprint " + Short(fingerprint)
                    + " did not appear among this assessment's findings. Confirm the relevant checks "
                    + "actually ran before treating this as resolved.",
                Severity.Informational,
                FingerprintSuffix(baseline.BaselineId, ResolvedFinding, fingerprint)));
        }

        return [.. drift
            .OrderBy(static d => d.Kind, StringComparer.Ordinal)
            .ThenBy(static d => d.Detail, StringComparer.Ordinal)];
    }

    private static string Suffix(Guid baselineId, string kind, int port, ProtocolKind protocol)
    {
        var canonical = baselineId.ToString("N") + "|" + kind + "|" + port + "|" + protocol;
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexString(hash.AsSpan(0, 8)).ToLowerInvariant();
    }

    private static string FingerprintSuffix(Guid baselineId, string kind, string fingerprint)
    {
        var canonical = baselineId.ToString("N") + "|" + kind + "|" + fingerprint;
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexString(hash.AsSpan(0, 8)).ToLowerInvariant();
    }

    private static string Short(string fingerprint) =>
        fingerprint.Length <= 16 ? fingerprint : fingerprint[..16];
}
