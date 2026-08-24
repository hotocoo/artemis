using System.Text.Json;
using System.Text.Json.Serialization;
using ACT.Contracts;

namespace ACT.Reporting;

/// <summary>Renders the report as pretty-printed, deterministic JSON (stable ordering, string enums).</summary>
public sealed class JsonReportFormatter : IReportFormatter
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web)
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <inheritdoc />
    public string ContentType => "application/json; charset=utf-8";

    /// <inheritdoc />
    public string FileExtension => "json";

    /// <inheritdoc />
    public Task<string> RenderAsync(ReportInput input, CancellationToken cancellationToken)
    {
        ReportRendering.EnsureValid(input);
        cancellationToken.ThrowIfCancellationRequested();
        var items = ReportRendering.OrderedItems(input);
        var findings = items.Select(static i => i.Finding).ToList();
        var assessment = input.Assessment;
        var scope = input.Scope;

        var model = new JsonReport(
            ToolVersion: input.ToolVersion,
            GeneratedUtc: input.GeneratedUtc,
            Assessment: new JsonAssessment(
                assessment.AssessmentId,
                assessment.Name,
                assessment.State.ToString(),
                assessment.OperatorIdentity,
                assessment.Organization,
                assessment.CreatedUtc,
                assessment.StartedUtc,
                assessment.CompletedUtc,
                assessment.ScopeId),
            Scope: new JsonScope(
                [.. scope.AllowlistedTargets],
                [.. scope.ExcludedTargets],
                [.. scope.PermittedProtocols.Select(static p => p.ToString())],
                [.. scope.PermittedPorts.Select(static p => p.ToString())],
                [.. scope.AllowedCategories.Select(static c => c.ToString())],
                [.. scope.ProhibitedCategories.Select(static c => c.ToString())],
                scope.RequestsPerSecond,
                scope.ConcurrencyLimit,
                scope.MaxRequests,
                scope.MaxRuntime,
                scope.DataRedactionPolicy.ToString()),
            Metrics: input.Metrics is null
                ? null
                : new JsonMetrics(
                    input.Metrics.RequestsSent,
                    input.Metrics.ChecksExecuted,
                    input.Metrics.ChecksFailed,
                    input.Metrics.FindingsEmitted,
                    input.Metrics.TotalDuration,
                    input.Metrics.BytesReceived),
            Coverage: new JsonCoverage(
                input.Coverage.Tested,
                input.Coverage.NotTested,
                input.Coverage.Inaccessible,
                input.Coverage.Inconclusive,
                input.Coverage.Confirmed,
                input.Coverage.Inferred),
            Limitations: input.Limitations,
            RiskSummary: BuildRiskSummary(findings, items),
            Findings: [.. items.Select(BuildFinding)]);

        return Task.FromResult(JsonSerializer.Serialize(model, Options));
    }

    private static JsonRiskSummary BuildRiskSummary(List<Finding> findings, IReadOnlyList<FindingWithEvidence> items)
    {
        var counts = new List<JsonSeverityCount>();
        foreach (var severity in ReportRendering.SeverityOrderDesc)
        {
            var count = findings.Count(f => f.TechnicalSeverity == severity);
            if (count > 0)
            {
                counts.Add(new JsonSeverityCount(severity.ToString(), count));
            }
        }

        return new JsonRiskSummary(findings.Count, counts, ReportRendering.AveragePriority(items));
    }

    private static JsonFinding BuildFinding(FindingWithEvidence item)
    {
        var finding = item.Finding;
        var evidence = item.EvidenceItems
            .OrderBy(static e => e.CapturedAtUtc)
            .ThenBy(static e => e.EvidenceId)
            .Select(static e => new JsonEvidence(
                e.EvidenceId, e.Kind.ToString(), e.Key, e.RedactedValue, e.CapturedAtUtc, e.CollectedBy.Value))
            .ToList();
        return new JsonFinding(
            finding.FindingId,
            finding.CheckId.Value,
            finding.Title,
            finding.TargetDisplay,
            finding.Category.ToString(),
            finding.TechnicalSeverity.ToString(),
            finding.Confidence.ToString(),
            finding.Status.ToString(),
            finding.PriorityScore,
            finding.FirstSeenUtc,
            finding.LastSeenUtc,
            finding.Fingerprint.Hash,
            finding.ExploitabilityIndicator,
            finding.BusinessImpact.ToString(),
            finding.WhyItMatters,
            finding.TechnicalExplanation,
            new JsonRemediation(
                finding.Remediation.Summary,
                [.. finding.Remediation.Steps],
                [.. finding.Remediation.References]),
            finding.CvssVector,
            finding.CvssBaseScore,
            finding.RegressionTestId,
            evidence.Count,
            evidence);
    }
}

internal sealed record JsonReport(
    string ToolVersion,
    DateTimeOffset GeneratedUtc,
    JsonAssessment Assessment,
    JsonScope Scope,
    JsonMetrics? Metrics,
    JsonCoverage Coverage,
    string? Limitations,
    JsonRiskSummary RiskSummary,
    IReadOnlyList<JsonFinding> Findings);

internal sealed record JsonAssessment(
    Guid Id,
    string Name,
    string State,
    string OperatorIdentity,
    string Organization,
    DateTimeOffset CreatedUtc,
    DateTimeOffset? StartedUtc,
    DateTimeOffset? CompletedUtc,
    Guid ScopeId);

internal sealed record JsonScope(
    IReadOnlyList<string> AllowlistedTargets,
    IReadOnlyList<string> ExcludedTargets,
    IReadOnlyList<string> PermittedProtocols,
    IReadOnlyList<string> PermittedPorts,
    IReadOnlyList<string> AllowedCategories,
    IReadOnlyList<string> ProhibitedCategories,
    double RequestsPerSecond,
    int ConcurrencyLimit,
    long MaxRequests,
    TimeSpan MaxRuntime,
    string RedactionPolicy);

internal sealed record JsonMetrics(
    long RequestsSent,
    long ChecksExecuted,
    long ChecksFailed,
    long FindingsEmitted,
    TimeSpan TotalDuration,
    long BytesReceived);

internal sealed record JsonCoverage(
    int Tested,
    int NotTested,
    int Inaccessible,
    int Inconclusive,
    int Confirmed,
    int Inferred);

internal sealed record JsonRiskSummary(int TotalFindings, IReadOnlyList<JsonSeverityCount> BySeverity, double AveragePriorityScore);

internal sealed record JsonSeverityCount(string Severity, int Count);

internal sealed record JsonRemediation(string Summary, IReadOnlyList<string> Steps, IReadOnlyList<string> References);

internal sealed record JsonEvidence(
    Guid EvidenceId,
    string Kind,
    string Key,
    string RedactedValue,
    DateTimeOffset CapturedAtUtc,
    string CollectedBy);

internal sealed record JsonFinding(
    Guid Id,
    string CheckId,
    string Title,
    string Target,
    string Category,
    string Severity,
    string Confidence,
    string Status,
    double PriorityScore,
    DateTimeOffset FirstSeenUtc,
    DateTimeOffset LastSeenUtc,
    string Fingerprint,
    bool ExploitabilityIndicator,
    string BusinessImpact,
    string WhyItMatters,
    string TechnicalExplanation,
    JsonRemediation Remediation,
    string? CvssVector,
    double? CvssBaseScore,
    Guid? RegressionTestId,
    int EvidenceCount,
    IReadOnlyList<JsonEvidence> Evidence);
