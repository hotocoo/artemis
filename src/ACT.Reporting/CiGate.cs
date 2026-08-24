using ACT.Contracts;

namespace ACT.Reporting;

/// <summary>Knobs controlling which report outcomes fail a continuous-integration build.</summary>
public sealed record CiGateOptions
{
    /// <summary>New findings at this severity or above fail the build. Default: High.</summary>
    public Severity FailOnNewSeverityOrHigher { get; init; } = Severity.High;

    /// <summary>Fails the build when a regression is detected. Default: true.</summary>
    public bool FailOnRegressions { get; init; } = true;

    /// <summary>Fingerprints explicitly accepted ahead of time; they are never counted as new.</summary>
    public IReadOnlyCollection<string> BaselineAcceptedFingerprints { get; init; } = [];
}

/// <summary>Compares a fresh assessment against history and decides whether CI should fail.</summary>
public static class CiGate
{
    /// <summary>
    /// Evaluates the gate. NEW means the fingerprint was unseen in previous findings and is not
    /// baseline-accepted. REGRESSION means the finding is marked Regressed now, or its fingerprint
    /// was previously Remediated and has been reobserved.
    /// </summary>
    public static CiGateDecision Evaluate(CiGateOptions options, IReadOnlyList<Finding> previousFindings, ReportInput current)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(previousFindings);
        ReportRendering.EnsureValid(current);

        var seenBefore = previousFindings
            .Select(static f => f.Fingerprint.Hash)
            .ToHashSet(StringComparer.Ordinal);
        var previouslyRemediated = previousFindings
            .Where(static f => f.Status == FindingStatus.Remediated)
            .Select(static f => f.Fingerprint.Hash)
            .ToHashSet(StringComparer.Ordinal);
        var accepted = options.BaselineAcceptedFingerprints.ToHashSet(StringComparer.Ordinal);

        var reasons = new List<string>();
        var triggering = new List<Finding>();
        foreach (var item in current.Items)
        {
            var finding = item.Finding;
            var hash = finding.Fingerprint.Hash;
            var isNew = !seenBefore.Contains(hash) && !accepted.Contains(hash);
            var isRegression = finding.Status == FindingStatus.Regressed || previouslyRemediated.Contains(hash);
            var failsAsNew = isNew && finding.TechnicalSeverity >= options.FailOnNewSeverityOrHigher;
            var failsAsRegression = isRegression && options.FailOnRegressions;
            if (!failsAsNew && !failsAsRegression)
            {
                continue;
            }

            triggering.Add(finding);
            reasons.Add(Explain(failsAsNew, failsAsRegression, finding, ShortHash(hash)));
        }

        return new CiGateDecision(triggering.Count > 0, reasons, triggering);
    }

    private static string Explain(bool failsAsNew, bool failsAsRegression, Finding finding, string shortHash)
    {
        var label = finding.TechnicalSeverity.ToString();
        var check = finding.CheckId.Value;
        return (failsAsNew, failsAsRegression) switch
        {
            (true, true) => "NEW+REGRESSION: " + label + "-severity finding from check '" + check + "' (fingerprint " + shortHash + ") is new versus the accepted baseline and regresses a previously remediated issue.",
            (true, false) => "NEW: " + label + "-severity finding from check '" + check + "' (fingerprint " + shortHash + ") is not present in the previous run or the accepted baseline.",
            _ => "REGRESSION: finding from check '" + check + "' (fingerprint " + shortHash + ") is marked " + finding.Status + " or reappeared after being remediated.",
        };
    }

    private static string ShortHash(string hash) => hash.Length <= 12 ? hash : hash[..12];
}
