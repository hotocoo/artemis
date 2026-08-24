using System.Security.Cryptography;
using System.Text;
using ACT.Contracts;

namespace ACT.Reporting;

/// <summary>Detects service-level drift between a stored baseline and fresh observations.</summary>
public static class DriftAnalyzer
{
    /// <summary>Kind code for a prohibited service answering on a port.</summary>
    public const string UnexpectedServiceExposed = "unexpected-service-exposed";

    /// <summary>Kind code for an expected service missing from observations.</summary>
    public const string ExpectedServiceAbsent = "expected-service-absent";

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

    private static string Suffix(Guid baselineId, string kind, int port, ProtocolKind protocol)
    {
        var canonical = baselineId.ToString("N") + "|" + kind + "|" + port + "|" + protocol;
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToHexString(hash.AsSpan(0, 8)).ToLowerInvariant();
    }
}
