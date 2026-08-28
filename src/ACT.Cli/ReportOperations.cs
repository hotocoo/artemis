using ACT.Contracts;
using ACT.Persistence;
using ACT.Reporting;

namespace ACT.Cli;

/// <summary>
/// Shared report assembly used by both the CLI and the operator console. The input is built
/// strictly from persisted rows - never from live state - rendering is deterministic per format,
/// and every generated artifact appends a <c>report.generated</c> entry to the hash-chained
/// audit ledger so each report has a lifecycle record like every other surface action.
/// </summary>
public static class ReportOperations
{
    /// <summary>
    /// Renders one assessment's report in the requested format, optionally writing it under an
    /// output directory, and records the generation in the audit ledger exactly once.
    /// </summary>
    public static async Task<GeneratedReport> GenerateAsync(
        ActDatabase db,
        Guid assessmentId,
        ReportFormat format,
        string actor,
        CorrelationId correlation,
        string? outputDirectory = null)
    {
        ArgumentNullException.ThrowIfNull(db);

        var record = await db.GetAssessmentAsync(assessmentId)
            ?? throw ActException.FailClosed(
                ErrorCategory.Report,
                "The requested assessment does not exist.",
                "Assessment '" + assessmentId + "' was not found.");

        // The report scope summary comes from the stored scope definition.
        var scope = await db.GetConfigAsync<ScopeDefinition>("scope:" + assessmentId.ToString("N"))
            ?? throw ActException.FailClosed(
                ErrorCategory.Report,
                "The assessment has no stored scope to include in the report.",
                "No scope was stored for assessment " + assessmentId + ".");

        var findings = await db.ListFindingsAsync(assessmentId, null, null, 100_000);
        var metrics = await db.GetMetricsAsync(assessmentId);

        // Coverage is computed from the persisted check execution ledger - never estimated. A
        // report claims exactly as much testing as the engine recorded, and no more.
        var checkRuns = await db.ListCheckRunsAsync(assessmentId, 100_000);

        var input = new ReportInput(
            record,
            scope,
            findings.Select(static f => new FindingWithEvidence(f, [])).ToList(),
            metrics,
            CoverageOperations.ComputeVerificationCoverage(checkRuns, findings),
            Limitations: "Scope-limited assessment; absence of findings does not imply absence of vulnerabilities.",
            DateTimeOffset.UtcNow,
            CommandMetadata.Version);

        var assembler = new ReportAssembler();
        var rendered = await assembler.RenderAsync(input, format, CancellationToken.None);
        string? writtenPath = outputDirectory is null
            ? null
            : await assembler.AssembleFileAsync(outputDirectory, input, format, CancellationToken.None);

        await db.AppendAuditAsync(new AuditDraft(
            Actor: actor,
            Action: "report.generated",
            ObjectType: "assessment",
            ObjectId: assessmentId.ToString(),
            Result: format + " report; " + findings.Count + " finding(s) included; "
                + checkRuns.Count + " recorded check run(s)"
                + (writtenPath is null ? "" : "; written " + writtenPath),
            Correlation: correlation));

        return new GeneratedReport(record, format, findings.Count, rendered, writtenPath);
    }

    /// <summary>Download or archive file name for one rendered report artifact.</summary>
    public static string FileName(Guid assessmentId, ReportFormat format) =>
        "artemis-report-" + assessmentId.ToString("N")[..8] + "." + Extension(format);

    /// <summary>Canonical file extension per report format.</summary>
    public static string Extension(ReportFormat format) => format switch
    {
        ReportFormat.Json => "json",
        ReportFormat.Csv => "csv",
        ReportFormat.Markdown => "md",
        ReportFormat.Html => "html",
        ReportFormat.Sarif => "sarif",
        _ => UnknownFormat(format)
    };

    /// <summary>MIME type served with each report download.</summary>
    public static string ContentType(ReportFormat format) => format switch
    {
        ReportFormat.Json or ReportFormat.Sarif => "application/json",
        ReportFormat.Csv => "text/csv",
        ReportFormat.Markdown => "text/markdown",
        ReportFormat.Html => "text/html",
        _ => UnknownFormat(format)
    };

    private static string UnknownFormat(ReportFormat format) =>
        throw ActException.FailClosed(
            ErrorCategory.Report,
            "The requested report format is unknown.",
            "No renderer mapping exists for ReportFormat value " + (int)format + ".");

    /// <summary>
    /// Parses a user-supplied format name; fails closed instead of defaulting to JSON. Numeric
    /// input is refused even when it happens to match an enum value - "2" is not a format name.
    /// </summary>
    public static bool TryParseFormat(string? text, out ReportFormat format)
    {
        if (string.IsNullOrWhiteSpace(text) || char.IsAsciiDigit(text[0]))
        {
            format = ReportFormat.Json;
            return false;
        }

        // Accept both the enum names ("Markdown") and the file extensions the console links and
        // CLI --format flag use ("md"). The download route receives the extension from the URL
        // segment, so refusing it would 404 the very link the Reports page renders.
        var normalized = text.Trim();
        if (Enum.TryParse<ReportFormat>(normalized, ignoreCase: true, out var byName)
            && byName is ReportFormat.Json or ReportFormat.Csv or ReportFormat.Markdown
                or ReportFormat.Html or ReportFormat.Sarif)
        {
            format = byName;
            return true;
        }

        var byExtension = normalized.ToLowerInvariant() switch
        {
            "json" => ReportFormat.Json,
            "csv" => ReportFormat.Csv,
            "md" or "markdown" => ReportFormat.Markdown,
            "html" or "htm" => ReportFormat.Html,
            "sarif" => ReportFormat.Sarif,
            _ => (ReportFormat?)null
        };
        if (byExtension is { } resolved)
        {
            format = resolved;
            return true;
        }

        format = ReportFormat.Json;
        return false;
    }
}

/// <summary>One fully rendered report plus what honest summaries and downloads need.</summary>
public sealed record GeneratedReport(
    AssessmentRecord Assessment,
    ReportFormat Format,
    int FindingCount,
    string Content,
    string? WrittenPath);
