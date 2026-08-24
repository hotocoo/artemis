using System.Globalization;
using ACT.Contracts;

namespace ACT.Reporting;

/// <summary>Shared validation, ordering, and formatting helpers used by every formatter.</summary>
internal static class ReportRendering
{
    /// <summary>Severities ordered from most to least severe.</summary>
    internal static readonly Severity[] SeverityOrderDesc =
        [Severity.Critical, Severity.High, Severity.Medium, Severity.Low, Severity.Informational];

    internal static void EnsureValid(ReportInput input)
    {
        _ = input ?? throw Fail("input was not provided.");
        _ = input.Assessment ?? throw Fail("the assessment record is missing.");
        _ = input.Scope ?? throw Fail("the scope definition is missing.");
        _ = input.Items ?? throw Fail("the finding list is missing.");
        if (input.Items.Any(static i => i?.Finding is null))
        {
            throw Fail("the finding list contains a null entry.");
        }

        static ActException Fail(string detail) => ActException.FailClosed(
            ErrorCategory.Report,
            "The report cannot be rendered because its input is incomplete.",
            $"ReportInput invalid: {detail}");
    }

    /// <summary>Orders findings deterministically: severity down, then check id, fingerprint, finding id.</summary>
    internal static IReadOnlyList<FindingWithEvidence> OrderedItems(ReportInput input) =>
        [.. input.Items
            .OrderByDescending(static i => i.Finding.TechnicalSeverity)
            .ThenBy(static i => i.Finding.CheckId.Value, StringComparer.Ordinal)
            .ThenBy(static i => i.Finding.Fingerprint.Hash, StringComparer.Ordinal)
            .ThenBy(static i => i.Finding.FindingId)];

    internal static string UtcText(DateTimeOffset moment) =>
        moment.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);

    internal static string ScoreText(double score) =>
        score.ToString("0.###", CultureInfo.InvariantCulture);

    internal static string SingleLine(string text) =>
        text.Replace("\r\n", " ", StringComparison.Ordinal).Replace('\r', ' ').Replace('\n', ' ');

    internal static string MarkdownSafe(string text) =>
        SingleLine(text).Replace("|", "\\|", StringComparison.Ordinal);

    internal static string CoverageLine(VerificationCoverage coverage) =>
        $"tested {coverage.Tested}, not tested {coverage.NotTested}, inaccessible {coverage.Inaccessible}, " +
        $"inconclusive {coverage.Inconclusive}, confirmed {coverage.Confirmed}, inferred {coverage.Inferred}";

    internal static double AveragePriority(IReadOnlyList<FindingWithEvidence> items) =>
        items.Count == 0
            ? 0d
            : Math.Round(items.Average(static i => i.Finding.PriorityScore), 2, MidpointRounding.AwayFromZero);

    internal static IReadOnlyList<(Severity Severity, IReadOnlyList<Finding> Findings)> GroupBySeverity(
        IReadOnlyList<Finding> findings)
    {
        var groups = new List<(Severity, IReadOnlyList<Finding>)>();
        foreach (var severity in SeverityOrderDesc)
        {
            var bucket = findings.Where(f => f.TechnicalSeverity == severity).ToList();
            if (bucket.Count > 0)
            {
                groups.Add((severity, bucket));
            }
        }

        return groups;
    }
}
