using System.Net;
using System.Text;
using ACT.Contracts;

namespace ACT.Reporting;

/// <summary>Renders the report as a valid standalone HTML5 document with escaped output.</summary>
public sealed class HtmlReportFormatter : IReportFormatter
{
    /// <inheritdoc />
    public string ContentType => "text/html; charset=utf-8";

    /// <inheritdoc />
    public string FileExtension => "html";

    private const string StyleBlock = """
        <style>
        :root{--ink:#16202b;--muted:#5b6672;--line:#d7dde4;--brand:#0a5aa8;--bg:#f5f7fa}
        *{box-sizing:border-box}
        body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.55 "Segoe UI",-apple-system,"Helvetica Neue",Arial,sans-serif}
        main{max-width:62rem;margin:1.5rem auto;padding:2rem 2.2rem;background:#fff;border:1px solid var(--line);border-radius:8px}
        h1{font-size:1.65rem;margin:.1rem 0}
        h2{font-size:1.18rem;margin-top:2rem;padding-bottom:.3rem;border-bottom:2px solid var(--brand)}
        h3{font-size:1.05rem;margin-top:1.4rem}
        h4{font-size:1rem;margin-bottom:.2rem}
        code{font-family:ui-monospace,SFMono-Regular,Consolas,Menlo,monospace;font-size:.86em;background:#eef1f5;padding:.05em .35em;border-radius:3px}
        table{border-collapse:collapse;width:100%;margin:.6rem 0}
        th,td{text-align:left;padding:.35rem .55rem;border:1px solid var(--line)}
        th{background:#edf1f6}
        td.num,th.num{text-align:right}
        .meta{color:var(--muted);font-size:.92rem}
        .sev-critical{color:#8f0f0f}
        .sev-high{color:#b3261e}
        .sev-medium{color:#9a6700}
        .sev-low{color:#175bb0}
        .sev-informational{color:#57606a}
        article.finding{border-left:3px solid var(--line);padding:.15rem 0 .15rem .9rem;margin:.9rem 0}
        footer{margin-top:2.2rem;color:var(--muted);font-size:.85rem}
        </style>
        """;

    /// <inheritdoc />
    public Task<string> RenderAsync(ReportInput input, CancellationToken cancellationToken)
    {
        ReportRendering.EnsureValid(input);
        cancellationToken.ThrowIfCancellationRequested();
        var items = ReportRendering.OrderedItems(input);
        var findings = items.Select(static i => i.Finding).ToList();
        var assessment = input.Assessment;
        var builder = new StringBuilder(capacity: 8192);

        builder.AppendLine("<!DOCTYPE html>");
        builder.AppendLine("<html lang=\"en\">");
        builder.AppendLine("<head>");
        builder.AppendLine("<meta charset=\"utf-8\">");
        builder.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
        builder.AppendLine("<title>" + H(assessment.Name) + " — Artemis Assessment Report</title>");
        builder.AppendLine(StyleBlock.TrimEnd());
        builder.AppendLine("</head>");
        builder.AppendLine("<body>");
        builder.AppendLine("<main>");
        builder.AppendLine("<header>");
        builder.AppendLine("<p class=\"meta\">" + H(input.ToolVersion) + "</p>");
        builder.AppendLine("<h1>" + H(assessment.Name) + "</h1>");
        builder.AppendLine("<p class=\"meta\">Assessment " + H(assessment.AssessmentId.ToString()) + " · state " + H(assessment.State.ToString()) + " · operator " + H(assessment.OperatorIdentity) + " · organization " + H(assessment.Organization) + "</p>");
        builder.AppendLine("</header>");

        builder.AppendLine("<section id=\"executive-summary\">");
        builder.AppendLine("<h2>Executive Summary</h2>");
        builder.AppendLine("<ul>");
        builder.AppendLine("<li>Report generated " + H(ReportRendering.UtcText(input.GeneratedUtc)) + ".</li>");
        builder.AppendLine("<li>Findings: " + findings.Count + " total — critical " + Count(findings, Severity.Critical) + ", high " + Count(findings, Severity.High) + ", medium " + Count(findings, Severity.Medium) + ", low " + Count(findings, Severity.Low) + ", informational " + Count(findings, Severity.Informational) + ".</li>");
        if (input.Metrics is { } metrics)
        {
            builder.AppendLine("<li>Run metrics: " + metrics.RequestsSent + " requests sent, " + metrics.ChecksExecuted + " checks executed (" + metrics.ChecksFailed + " failed).</li>");
        }

        builder.AppendLine("</ul>");
        builder.AppendLine("</section>");

        builder.AppendLine("<section id=\"risk-summary\">");
        builder.AppendLine("<h2>Risk Summary</h2>");
        builder.AppendLine("<table><thead><tr><th scope=\"col\">Severity</th><th scope=\"col\" class=\"num\">Findings</th></tr></thead><tbody>");
        foreach (var (severity, group) in ReportRendering.GroupBySeverity(findings))
        {
            builder.AppendLine("<tr class=\"sev-" + severity.ToString().ToLowerInvariant() + "\"><td>" + severity + "</td><td class=\"num\">" + group.Count + "</td></tr>");
        }

        builder.AppendLine("</tbody></table>");
        builder.AppendLine("<p>Highest observed severity: " + (findings.Count == 0 ? "none" : findings.Max(static f => f.TechnicalSeverity).ToString()) + ". Average priority score: " + ReportRendering.ScoreText(ReportRendering.AveragePriority(items)) + ".</p>");
        builder.AppendLine("</section>");

        builder.AppendLine("<section id=\"technical-findings\">");
        builder.AppendLine("<h2>Technical Findings</h2>");
        if (findings.Count == 0)
        {
            builder.AppendLine("<p>No findings were emitted for this assessment.</p>");
        }
        else
        {
            foreach (var (severity, group) in ReportRendering.GroupBySeverity(findings))
            {
                builder.AppendLine("<h3 class=\"sev-" + severity.ToString().ToLowerInvariant() + "\">" + severity + "</h3>");
                foreach (var finding in group)
                {
                    AppendFinding(builder, finding);
                }
            }
        }

        builder.AppendLine("</section>");

        builder.AppendLine("<section id=\"remediation-plan\">");
        builder.AppendLine("<h2>Remediation Plan</h2>");
        builder.AppendLine("<ol>");
        foreach (var finding in items
            .OrderByDescending(static i => i.Finding.PriorityScore)
            .ThenBy(static i => i.Finding.Fingerprint.Hash, StringComparer.Ordinal)
            .Select(static i => i.Finding))
        {
            var firstAction = finding.Remediation.Steps.Count > 0 ? H(finding.Remediation.Steps[0]) : H(finding.Remediation.Summary);
            builder.AppendLine("<li><strong>" + H(finding.Title) + "</strong> — priority " + ReportRendering.ScoreText(finding.PriorityScore) + "; check " + H(finding.CheckId.Value) + " on " + H(finding.TargetDisplay) + "; start with: " + firstAction + "</li>");
        }

        builder.AppendLine("</ol>");
        builder.AppendLine("</section>");

        var covered = findings.Count(static f => f.RegressionTestId is not null);
        builder.AppendLine("<section id=\"regression-coverage\">");
        builder.AppendLine("<h2>Regression Coverage</h2>");
        builder.AppendLine("<p>" + covered + " of " + findings.Count + " findings carry a regression test identifier.</p>");
        builder.AppendLine("</section>");

        builder.AppendLine("<section id=\"assessment-scope\">");
        builder.AppendLine("<h2>Assessment Scope</h2>");
        builder.AppendLine("<ul>");
        AppendScopeItem(builder, "Target type", input.Scope.TargetType.ToString());
        AppendScopeItem(builder, "Allowlisted targets", JoinOrNone(input.Scope.AllowlistedTargets));
        AppendScopeItem(builder, "Excluded targets", JoinOrNone(input.Scope.ExcludedTargets));
        AppendScopeItem(builder, "Permitted protocols", JoinOrNone(input.Scope.PermittedProtocols.Select(static p => p.ToString())));
        AppendScopeItem(builder, "Permitted ports", JoinOrNone(input.Scope.PermittedPorts.Select(static p => p.ToString())));
        AppendScopeItem(builder, "Redaction policy", input.Scope.DataRedactionPolicy.ToString());
        AppendScopeItem(builder, "Allowed categories", JoinOrNone(input.Scope.AllowedCategories.Select(static c => c.ToString())));
        AppendScopeItem(builder, "Prohibited categories", JoinOrNone(input.Scope.ProhibitedCategories.Select(static c => c.ToString())));
        AppendScopeItem(builder, "Authorization statement", input.Scope.AuthorizationStatement);
        builder.AppendLine("</ul>");
        builder.AppendLine("</section>");

        builder.AppendLine("<section id=\"coverage-limitations\">");
        builder.AppendLine("<h2>Coverage &amp; Limitations</h2>");
        builder.AppendLine("<p>Coverage counts: " + H(ReportRendering.CoverageLine(input.Coverage)) + ".</p>");
        var limitations = input.Limitations is { } provided && provided.Length > 0 ? provided : "none recorded.";
        builder.AppendLine("<p><strong>Limitations:</strong> " + H(limitations) + "</p>");
        builder.AppendLine("</section>");

        builder.AppendLine("<footer>Generated " + H(ReportRendering.UtcText(input.GeneratedUtc)) + " by " + H(input.ToolVersion) + ".</footer>");
        builder.AppendLine("</main>");
        builder.AppendLine("</body>");
        builder.AppendLine("</html>");
        return Task.FromResult(builder.ToString());
    }

    private static void AppendFinding(StringBuilder builder, Finding finding)
    {
        builder.AppendLine("<article class=\"finding\">");
        builder.AppendLine("<h4>" + H(finding.Title) + "</h4>");
        builder.AppendLine("<p class=\"meta\">Check " + H(finding.CheckId.Value) + " · " + H(finding.Category.ToString()) + " · Confidence " + H(finding.Confidence.ToString()) + " · Status " + H(finding.Status.ToString()) + " · Priority " + ReportRendering.ScoreText(finding.PriorityScore) + "</p>");
        builder.AppendLine("<p><strong>Target:</strong> <code>" + H(finding.TargetDisplay) + "</code></p>");
        builder.AppendLine("<p><strong>Fingerprint:</strong> <code>" + H(finding.Fingerprint.Hash) + "</code> · First seen " + H(ReportRendering.UtcText(finding.FirstSeenUtc)) + " · Last seen " + H(ReportRendering.UtcText(finding.LastSeenUtc)) + "</p>");
        builder.AppendLine("<p>" + H(finding.Description) + "</p>");
        builder.AppendLine("<p><strong>Why it matters:</strong> " + H(finding.WhyItMatters) + "</p>");
        builder.AppendLine("<p><strong>Remediation:</strong> " + H(finding.Remediation.Summary) + "</p>");
        if (finding.Remediation.Steps.Count > 0)
        {
            builder.AppendLine("<ol>");
            foreach (var step in finding.Remediation.Steps)
            {
                builder.AppendLine("<li>" + H(step) + "</li>");
            }

            builder.AppendLine("</ol>");
        }

        builder.AppendLine("</article>");
    }

    private static void AppendScopeItem(StringBuilder builder, string label, string value) =>
        builder.AppendLine("<li><strong>" + H(label) + ":</strong> " + H(value) + "</li>");

    private static string JoinOrNone(IEnumerable<string> values)
    {
        var joined = string.Join(", ", values);
        return joined.Length == 0 ? "(none)" : joined;
    }

    private static int Count(IReadOnlyList<Finding> findings, Severity severity) =>
        findings.Count(f => f.TechnicalSeverity == severity);

    /// <summary>Encodes text so it can never break out of markup context.</summary>
    private static string H(string? text) => WebUtility.HtmlEncode(text ?? string.Empty);
}
