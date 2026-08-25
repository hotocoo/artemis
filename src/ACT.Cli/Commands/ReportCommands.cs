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
            Console.Error.WriteLine("usage: artemis report generate --assessment ID [--format json|csv|markdown|html|sarif] [--out DIR] [--actor OPERATOR]");
            return ExitCodes.UsageError;
        }

        string? assessmentText = null;
        var format = ReportFormat.Json;
        string? outDir = null;
        for (var i = 1; i < args.Length - 1; i++)
        {
            if (args[i] == "--assessment") assessmentText = args[i + 1];
            if (args[i] == "--format" && !ReportOperations.TryParseFormat(args[i + 1], out format))
            {
                Console.Error.WriteLine("error: unknown report format '" + args[i + 1] + "'.");
                return ExitCodes.UsageError;
            }

            if (args[i] == "--out") outDir = args[i + 1];
        }

        if (!Guid.TryParse(assessmentText, out var assessmentId))
        {
            Console.Error.WriteLine("error: --assessment ID is required.");
            return ExitCodes.UsageError;
        }

        var db = services.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();

        var actor = FlagValue(args, "--actor")?.Trim() is { Length: > 0 } explicitActor ? explicitActor : "cli-operator";
        var report = await ReportOperations.GenerateAsync(db, assessmentId, format, actor, CorrelationId.New(), outDir);

        return await OutputWriter.WriteAsync(services,
            report.WrittenPath is null
                ? report.Content
                : report.Content + Environment.NewLine + "written: " + report.WrittenPath,
            JsonSerializer.Serialize(new
            {
                assessmentId,
                format = report.Format.ToString(),
                findingsIncluded = report.FindingCount,
                file = report.WrittenPath
            }, JsonOpts.Indented));
    }

    private static string? FlagValue(string[] args, string flag)
    {
        for (var i = 1; i < args.Length - 1; i++)
        {
            if (args[i] == flag) return args[i + 1];
        }

        return null;
    }
}
