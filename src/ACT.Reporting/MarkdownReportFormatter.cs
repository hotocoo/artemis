using System.Globalization;
using System.Text;
using ACT.Contracts;

namespace ACT.Reporting;

/// <summary>Renders the report as a GitHub-flavored Markdown document.</summary>
public sealed class MarkdownReportFormatter : IReportFormatter
{
    /// <inheritdoc />
    public string ContentType => "text/markdown; charset=utf-8";

    /// <inheritdoc />
    public string FileExtension => "md";

    /// <inheritdoc />
    public Task<string> RenderAsync(ReportInput input, CancellationToken cancellationToken)
    {
        ReportRendering.EnsureValid(input);
        cancellationToken.ThrowIfCancellationRequested();
        var items = ReportRendering.OrderedItems(input);
        var findings = items.Select(static i => i.Finding).ToList();
        var builder = new StringBuilder(capacity: 4096);
        builder.AppendLine("# Artemis Assessment Report — " + ReportRendering.SingleLine(input.Assessment.Name));
        builder.AppendLine();
        AppendExecutiveSummary(builder, input, findings);
        AppendRiskSummary(builder, items, findings);
        AppendTechnicalFindings(builder, findings);
        AppendRemediationPlan(builder, items);
        AppendRegressionCoverage(builder, findings);
        AppendAssessmentScope(builder, input.Scope);
        AppendCoverageAndLimitations(builder, input);
        builder.AppendLine();
        builder.AppendLine("_Generated " + ReportRendering.UtcText(input.GeneratedUtc) + " by " + input.ToolVersion + "._");
        return Task.FromResult(builder.ToString());
    }

    private static void Section(StringBuilder builder, string title)
    {
        builder.Append("## ").AppendLine(title);
        builder.AppendLine();
    }

    private static void AppendExecutiveSummary(StringBuilder builder, ReportInput input, IReadOnlyList<Finding> findings)
    {
        Section(builder, "Executive Summary");
        var assessment = input.Assessment;
        builder.AppendLine("- Assessment **" + ReportRendering.SingleLine(assessment.Name) + "** (state: " + assessment.State + "), operator " + ReportRendering.SingleLine(assessment.OperatorIdentity) + ", organization " + ReportRendering.SingleLine(assessment.Organization) + ".");
        builder.AppendLine("- Report generated " + ReportRendering.UtcText(input.GeneratedUtc) + " using " + input.ToolVersion + ".");
        builder.AppendLine("- Findings: " + findings.Count + " total — critical " + Count(findings, Severity.Critical) + ", high " + Count(findings, Severity.High) + ", medium " + Count(findings, Severity.Medium) + ", low " + Count(findings, Severity.Low) + ", informational " + Count(findings, Severity.Informational) + ".");
        if (input.Metrics is { } metrics)
        {
            builder.AppendLine("- Run metrics: " + metrics.RequestsSent + " requests sent, " + metrics.ChecksExecuted + " checks executed (" + metrics.ChecksFailed + " failed) over " + metrics.TotalDuration.ToString("c", CultureInfo.InvariantCulture) + ".");
        }

        builder.AppendLine();
    }

    private static void AppendRiskSummary(StringBuilder builder, IReadOnlyList<FindingWithEvidence> items, IReadOnlyList<Finding> findings)
    {
        Section(builder, "Risk Summary");
        builder.AppendLine("| Severity | Findings |");
        builder.AppendLine("| --- | ---: |");
        foreach (var (severity, group) in ReportRendering.GroupBySeverity(findings))
        {
            builder.AppendLine("| " + severity + " | " + group.Count + " |");
        }

        if (findings.Count == 0)
        {
            builder.AppendLine("| (none) | 0 |");
        }

        builder.AppendLine();
        builder.AppendLine("- Highest observed severity: " + (findings.Count == 0 ? "none" : findings.Max(static f => f.TechnicalSeverity).ToString()) + ".");
        builder.AppendLine("- Average priority score: " + ReportRendering.ScoreText(ReportRendering.AveragePriority(items)) + ".");
        builder.AppendLine();
    }

    private static void AppendTechnicalFindings(StringBuilder builder, IReadOnlyList<Finding> findings)
    {
        Section(builder, "Technical Findings");
        if (findings.Count == 0)
        {
            builder.AppendLine("_No findings were emitted for this assessment._");
            builder.AppendLine();
            return;
        }

        foreach (var (severity, group) in ReportRendering.GroupBySeverity(findings))
        {
            builder.Append("### ").AppendLine(severity.ToString());
            builder.AppendLine();
            foreach (var finding in group)
            {
                AppendFinding(builder, finding);
            }
        }
    }

    private static void AppendFinding(StringBuilder builder, Finding finding)
    {
        builder.AppendLine("#### " + ReportRendering.MarkdownSafe(finding.Title));
        builder.AppendLine();
        builder.AppendLine("- Id: `" + finding.FindingId + "`");
        builder.AppendLine("- Check: `" + finding.CheckId.Value + "` · Category: " + finding.Category + " · Confidence: " + finding.Confidence + " · Status: " + finding.Status);
        builder.AppendLine("- Target: `" + ReportRendering.MarkdownSafe(finding.TargetDisplay) + "`");
        builder.AppendLine("- First seen: " + ReportRendering.UtcText(finding.FirstSeenUtc) + " · Last seen: " + ReportRendering.UtcText(finding.LastSeenUtc));
        builder.AppendLine("- Priority score: " + ReportRendering.ScoreText(finding.PriorityScore) + " · Fingerprint: `" + finding.Fingerprint.Hash + "`" + (finding.ExploitabilityIndicator ? " · Exploitability indicator present" : string.Empty));
        builder.AppendLine();
        builder.AppendLine(ReportRendering.MarkdownSafe(finding.Description));
        builder.AppendLine();
        builder.AppendLine("**Why it matters:** " + ReportRendering.MarkdownSafe(finding.WhyItMatters));
        builder.AppendLine();
        builder.AppendLine("**Remediation:** " + ReportRendering.MarkdownSafe(finding.Remediation.Summary));
        for (var index = 0; index < finding.Remediation.Steps.Count; index++)
        {
            builder.AppendLine((index + 1) + ". " + ReportRendering.MarkdownSafe(finding.Remediation.Steps[index]));
        }

        if (finding.Remediation.References.Count > 0)
        {
            builder.AppendLine("References: " + string.Join(", ", finding.Remediation.References));
        }

        builder.AppendLine();
    }

    private static void AppendRemediationPlan(StringBuilder builder, IReadOnlyList<FindingWithEvidence> items)
    {
        Section(builder, "Remediation Plan");
        var plan = items
            .OrderByDescending(static i => i.Finding.PriorityScore)
            .ThenBy(static i => i.Finding.Fingerprint.Hash, StringComparer.Ordinal)
            .Select(static i => i.Finding)
            .ToList();
        for (var index = 0; index < plan.Count; index++)
        {
            var finding = plan[index];
            var firstAction = finding.Remediation.Steps.Count > 0
                ? ReportRendering.MarkdownSafe(finding.Remediation.Steps[0])
                : ReportRendering.MarkdownSafe(finding.Remediation.Summary);
            builder.AppendLine((index + 1) + ". **" + ReportRendering.MarkdownSafe(finding.Title) + "** — priority " + ReportRendering.ScoreText(finding.PriorityScore) + "; check `" + finding.CheckId.Value + "` on `" + ReportRendering.MarkdownSafe(finding.TargetDisplay) + "`; start with: " + firstAction);
        }

        if (plan.Count == 0)
        {
            builder.AppendLine("_Nothing to remediate._");
        }

        builder.AppendLine();
    }

    private static void AppendRegressionCoverage(StringBuilder builder, IReadOnlyList<Finding> findings)
    {
        Section(builder, "Regression Coverage");
        var covered = findings.Count(static f => f.RegressionTestId is not null);
        builder.AppendLine("- " + covered + " of " + findings.Count + " findings carry a regression test identifier.");
        builder.AppendLine();
    }

    private static void AppendAssessmentScope(StringBuilder builder, ScopeDefinition scope)
    {
        Section(builder, "Assessment Scope");
        builder.AppendLine("- Target type: " + scope.TargetType);
        builder.AppendLine("- Allowlisted targets: " + Join(scope.AllowlistedTargets));
        builder.AppendLine("- Excluded targets: " + Join(scope.ExcludedTargets));
        builder.AppendLine("- Permitted protocols: " + JoinEnums(scope.PermittedProtocols));
        builder.AppendLine("- Permitted ports: " + Join(scope.PermittedPorts.Select(static p => p.ToString())));
        builder.AppendLine("- Rate limit: " + scope.RequestsPerSecond.ToString("0.##", CultureInfo.InvariantCulture) + " req/s · Concurrency limit: " + scope.ConcurrencyLimit + " · Max requests: " + scope.MaxRequests + " · Max runtime: " + scope.MaxRuntime.ToString("c", CultureInfo.InvariantCulture));
        builder.AppendLine("- Redaction policy: " + scope.DataRedactionPolicy);
        builder.AppendLine("- Allowed categories: " + JoinEnums(scope.AllowedCategories));
        builder.AppendLine("- Prohibited categories: " + JoinEnums(scope.ProhibitedCategories));
        builder.AppendLine("- Authorization statement: \"" + ReportRendering.SingleLine(scope.AuthorizationStatement) + "\"");
        builder.AppendLine();
    }

    private static void AppendCoverageAndLimitations(StringBuilder builder, ReportInput input)
    {
        Section(builder, "Coverage & Limitations");
        builder.AppendLine("- Coverage counts: " + ReportRendering.CoverageLine(input.Coverage) + ".");
        var limitations = input.Limitations is { } provided && provided.Length > 0
            ? ReportRendering.SingleLine(provided)
            : "none recorded.";
        builder.AppendLine("- Limitations: " + limitations);
        builder.AppendLine();
    }

    private static int Count(IReadOnlyList<Finding> findings, Severity severity) =>
        findings.Count(f => f.TechnicalSeverity == severity);

    private static string Join(IEnumerable<string> values)
    {
        var joined = string.Join(", ", values);
        return joined.Length == 0 ? "(none)" : joined;
    }

    private static string JoinEnums<T>(IEnumerable<T> values) where T : struct, Enum =>
        Join(values.Select(static value => value.ToString()));
}
