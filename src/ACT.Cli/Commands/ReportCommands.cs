
using System.Text.Json;
using ACT.Contracts;
using ACT.Persistence;
using ACT.Reporting;
using Microsoft.Extensions.DependencyInjection;

namespace ACT.Cli;

/// <summary>artemis report generate --assessment ID --format sarif --out DIR</summary>
public static class ReportCommands
{
    public static async Task<int> Run(IServiceProvider services, string[] args)
    {
        if (args.Length == 0 || args[0] != "generate")
        {
            Console.Error.WriteLine("usage: artemis report generate --assessment ID [--format json|csv|markdown|html|sarif] [--out DIR]");
            return ExitCodes.UsageError;
        }

        string? assessmentText = null;
        var format = ReportFormat.Json;
        string? outDir = null;
        for (var i = 1; i < args.Length - 1; i++)
        {
            if (args[i] == "--assessment") assessmentText = args[i + 1];
            if (args[i] == "--format" && Enum.TryParse<ReportFormat>(args[i + 1], true, out var f)) format = f;
            if (args[i] == "--out") outDir = args[i + 1];
        }
        if (!Guid.TryParse(assessmentText, out var assessmentId))
        {
            Console.Error.WriteLine("error: --assessment ID is required.");
            return ExitCodes.UsageError;
        }

        var db = services.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();

        var record = await db.GetAssessmentAsync(assessmentId)
            ?? throw ActException.FailClosed(ErrorCategory.Report,
                "The requested assessment does not exist.",
                $"Assessment '{assessmentId}' was not found.");

        // The report scope summary comes from the stored scope definition.
        var scope = await db.GetConfigAsync<ScopeDefinition>("scope:" + assessmentId.ToString("N"))
            ?? throw ActException.FailClosed(ErrorCategory.Report,
                "The assessment has no stored scope to include in the report.",
                $"No scope was stored for assessment {assessmentId}.");

        var findings = await db.ListFindingsAsync(assessmentId, null, null, 100000);
        var metrics = await db.GetMetricsAsync(assessmentId);

        var input = new ReportInput(
            record,
            scope,
            findings.Select(f => new FindingWithEvidence(f, [])).ToList(),
            metrics,
            new VerificationCoverage(
                Tested: findings.Count,
                NotTested: 0,
                Inaccessible: 0,
                Inconclusive: 0,
                Confirmed: findings.Count(f => f.Status == FindingStatus.Confirmed),
                Inferred: findings.Count(f => f.Confidence != ConfidenceLevel.High)),
            Limitations: "Scope-limited assessment; absence of findings does not imply absence of vulnerabilities.",
            DateTimeOffset.UtcNow,
            CommandMetadata.Version);

        var assembler = new ReportAssembler();
        var rendered = await assembler.RenderAsync(input, format, CancellationToken.None);
        string? writtenPath = outDir is null ? null : await assembler.AssembleFileAsync(outDir, input, format, CancellationToken.None);

        return await OutputWriter.WriteAsync(services,
            writtenPath is null ? rendered : rendered + Environment.NewLine + "written: " + writtenPath,
            JsonSerializer.Serialize(new
            {
                assessmentId,
                format = format.ToString(),
                findingsIncluded = findings.Count,
                file = writtenPath
            }, JsonOpts.Indented));
    }
}
