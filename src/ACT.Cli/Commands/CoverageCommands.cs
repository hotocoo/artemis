using System.Text;
using System.Text.Json;
using ACT.Contracts;
using ACT.Persistence;
using ACT.Reporting;
using Microsoft.Extensions.DependencyInjection;

namespace ACT.Cli;

/// <summary>artemis coverage show - one assessment's check execution ledger.</summary>
public static class CoverageCommands
{
    public static async Task<int> Run(IServiceProvider services, string[] args)
    {
        if (args.Length == 0 || args[0] != "show")
        {
            return Usage();
        }

        var db = services.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();

        var assessmentText = FlagValue(args[1..], "--assessment");
        if (assessmentText is null || !Guid.TryParse(assessmentText, out var assessmentId))
        {
            Console.Error.WriteLine("error: --assessment ASSESSMENT_ID is required");
            return ExitCodes.UsageError;
        }

        try
        {
            var snapshot = await CoverageOperations.BuildAsync(db, assessmentId);
            return await Render(services, snapshot);
        }
        catch (ActException ex)
        {
            Console.Error.WriteLine("error: " + ex.SafeMessage);
            return ExitCodes.RuntimeFailure;
        }

        static int Usage()
        {
            Console.Error.WriteLine("usage: artemis coverage show --assessment ASSESSMENT_ID [--json]");
            Console.Error.WriteLine();
            Console.Error.WriteLine("Prints exactly what the check execution ledger proves about this assessment:");
            Console.Error.WriteLine("every recorded run with its true outcome (completed, skipped, failed closed,");
            Console.Error.WriteLine("timed out), honest verification counts derived from those rows only, and every");
            Console.Error.WriteLine("registered check with no recorded execution. Coverage is never estimated.");
            return ExitCodes.UsageError;
        }
    }

    private static async Task<int> Render(IServiceProvider services, CoverageOperations.CoverageSnapshot snapshot)
    {
        var text = new StringBuilder();
        text.AppendLine($"coverage for assessment {snapshot.Assessment.AssessmentId} \"{snapshot.Assessment.Name}\" ({snapshot.Assessment.State})");
        var s = snapshot.Summary;
        text.AppendLine(
            $"executed {s.Executed} | skipped {s.Skipped} | failed closed {s.FailedClosed} | timed out {s.TimedOut}"
            + $" | requests sent {s.RequestsSent} | targets examined {s.TargetsExamined}");

        if (snapshot.Runs.Count == 0)
        {
            text.AppendLine("(no check executions recorded for this assessment)");
        }
        else
        {
            text.AppendLine();
            text.AppendLine(string.Format("{0,-26} {1,-24} {2,-21} {3,6} {4,8} {5}",
                "CHECK", "OUTCOME", "STARTED (UTC)", "REQ", "TARGETS", "NOTE"));
            foreach (var run in snapshot.Runs)
            {
                text.AppendLine(string.Format("{0,-26} {1,-24} {2,-21} {3,6} {4,8} {5}",
                    Truncate(run.CheckId, 26),
                    run.Status.ToString(),
                    run.StartedUtc.ToString("u"),
                    run.RequestCount,
                    run.TargetsExamined,
                    run.FailureSummarySafe is { Length: > 0 } note ? Truncate(note, 60) : "-"));
            }
        }

        if (snapshot.NeverExecuted.Count > 0)
        {
            text.AppendLine();
            text.AppendLine("registered checks with NO recorded execution (reason not persisted - excluded at planning or not applicable):");
            foreach (var meta in snapshot.NeverExecuted)
            {
                text.AppendLine("  " + meta.Id.Value + " (" + meta.Category + ", " + meta.SafetyLevel + ")");
            }
        }

        var c = snapshot.Coverage;
        text.AppendLine();
        text.AppendLine("verification counts: " + CoverageOperations.VerificationCountsLine(c) + ".");

        var json = JsonSerializer.Serialize(new
        {
            assessmentId = snapshot.Assessment.AssessmentId,
            state = snapshot.Assessment.State.ToString(),
            summary = new
            {
                executed = s.Executed,
                skipped = s.Skipped,
                failedClosed = s.FailedClosed,
                timedOut = s.TimedOut,
                requestsSent = s.RequestsSent,
                targetsExamined = s.TargetsExamined,
                totalRuns = s.TotalRuns
            },
            coverage = new
            {
                tested = c.Tested,
                notTested = c.NotTested,
                inaccessible = c.Inaccessible,
                inconclusive = c.Inconclusive,
                confirmed = c.Confirmed,
                inferred = c.Inferred
            },
            runs = snapshot.Runs.Select(r => new
            {
                r.CheckId,
                outcome = r.Status.ToString(),
                startedUtc = r.StartedUtc,
                completedUtc = r.CompletedUtc,
                r.RequestCount,
                r.TargetsExamined,
                note = r.FailureSummarySafe
            }),
            neverExecutedChecks = snapshot.NeverExecuted.Select(m => new
            {
                id = m.Id.Value,
                name = m.Name,
                category = m.Category.ToString(),
                safetyLevel = m.SafetyLevel.ToString()
            })
        }, JsonOpts.Indented);

        return await OutputWriter.WriteAsync(services, text.ToString(), json);
    }

    private static string? FlagValue(string[] args, string flag)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == flag)
            {
                return args[i + 1];
            }
        }

        return null;
    }

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..(max - 3)] + "...";
}
