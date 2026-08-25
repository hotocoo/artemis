using System.Text;
using System.Text.Json;
using ACT.Contracts;
using ACT.Persistence;
using ACT.Reporting;
using Microsoft.Extensions.DependencyInjection;

namespace ACT.Cli;

/// <summary>artemis baseline create|list|compare - stored security baselines and their drift.</summary>
public static class BaselineCommands
{
    public static async Task<int> Run(IServiceProvider services, string[] args)
    {
        if (args.Length == 0)
        {
            return Usage();
        }

        var db = services.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();

        return args[0] switch
        {
            "create" => await CreateAsync(services, db, args[1..]),
            "list" => await ListAsync(services, db, args[1..]),
            "compare" => await CompareAsync(services, db, args[1..]),
            _ => Usage()
        };

        static int Usage()
        {
            Console.Error.WriteLine("usage: artemis baseline create --assessment ASSESSMENT_ID [--name NAME] [--actor OPERATOR]");
            Console.Error.WriteLine("       artemis baseline list (--assessment ASSESSMENT_ID | --scope SCOPE_ID)");
            Console.Error.WriteLine("       artemis baseline compare --assessment ASSESSMENT_ID [--baseline BASELINE_ID]");
            Console.Error.WriteLine();
            Console.Error.WriteLine("Creation snapshots observed services and accepts only fingerprints an operator has");
            Console.Error.WriteLine("already dispositioned through triage (AcceptedRisk / FalsePositive). Comparison exits 5");
            Console.Error.WriteLine("(gate failed) when any drift is present so pipelines can fail on it.");
            return ExitCodes.UsageError;
        }
    }

    private static async Task<int> CreateAsync(IServiceProvider services, ActDatabase db, string[] args)
    {
        var assessmentText = FlagValue(args, "--assessment");
        if (assessmentText is null || !Guid.TryParse(assessmentText, out var assessmentId))
        {
            Console.Error.WriteLine("error: --assessment ASSESSMENT_ID is required");
            return ExitCodes.UsageError;
        }

        var assessment = await db.GetAssessmentAsync(assessmentId);
        if (assessment is null)
        {
            Console.Error.WriteLine("error: assessment not found: " + assessmentId);
            return ExitCodes.RuntimeFailure;
        }

        var name = FlagValue(args, "--name")?.Trim() is { Length: > 0 } explicitName
            ? explicitName
            : "baseline " + DateTimeOffset.UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'");
        var actor = FlagValue(args, "--actor")?.Trim() is { Length: > 0 } explicitActor ? explicitActor : "cli-operator";

        var baseline = await BaselineOperations.CreateAsync(db, assessment, name, actor, CorrelationId.New());
        return await OutputWriter.WriteAsync(services,
            "baseline " + baseline.BaselineId + " created from assessment " + assessmentId
            + ": " + baseline.ExpectedServices.Count + " expected service(s), "
            + baseline.AcceptedFindingFingerprints.Count + " accepted finding fingerprint(s)"
            + " (accepted = triaged AcceptedRisk/FalsePositive only)",
            JsonSerializer.Serialize(new
            {
                baselineId = baseline.BaselineId,
                scopeId = baseline.ScopeId,
                name = baseline.Name,
                createdUtc = baseline.CreatedUtc,
                expectedServices = baseline.ExpectedServices.Count,
                acceptedFingerprints = baseline.AcceptedFindingFingerprints.Count
            }, JsonOpts.Indented));
    }

    private static async Task<int> ListAsync(IServiceProvider services, ActDatabase db, string[] args)
    {
        var assessmentText = FlagValue(args, "--assessment");
        var scopeText = FlagValue(args, "--scope");
        Guid? scopeId = null;
        if (scopeText is not null && Guid.TryParse(scopeText, out var parsedScope))
        {
            scopeId = parsedScope;
        }
        else if (assessmentText is { } assessmentRaw && Guid.TryParse(assessmentRaw, out var parsedAssessment))
        {
            var assessment = await db.GetAssessmentAsync(parsedAssessment);
            if (assessment is null)
            {
                Console.Error.WriteLine("error: assessment not found: " + parsedAssessment);
                return ExitCodes.RuntimeFailure;
            }

            scopeId = assessment.ScopeId;
        }
        else
        {
            Console.Error.WriteLine("error: provide --assessment ASSESSMENT_ID or --scope SCOPE_ID");
            return ExitCodes.UsageError;
        }

        var baselines = await db.ListBaselinesAsync(scopeId.Value);
        var text = new StringBuilder();
        text.AppendLine(string.Format("{0,-38} {1,-30} {2,-21} {3,-9} {4}", "BASELINE", "NAME", "CREATED (UTC)", "SERVICES", "ACCEPTED"));
        foreach (var baseline in baselines)
        {
            text.AppendLine(string.Format("{0,-38} {1,-30} {2,-21} {3,-9} {4}",
                baseline.BaselineId,
                Truncate(baseline.Name, 30),
                baseline.CreatedUtc.ToString("u"),
                baseline.ExpectedServices.Count,
                baseline.AcceptedFindingFingerprints.Count));
        }

        if (baselines.Count == 0)
        {
            text.AppendLine("(no baselines stored for this scope)");
        }

        var json = JsonSerializer.Serialize(baselines.Select(b => new
        {
            baselineId = b.BaselineId,
            scopeId = b.ScopeId,
            name = b.Name,
            createdUtc = b.CreatedUtc,
            expectedServices = b.ExpectedServices.Count,
            acceptedFingerprints = b.AcceptedFindingFingerprints.Count
        }), JsonOpts.Indented);
        return await OutputWriter.WriteAsync(services, text.ToString(), json);
    }

    private static async Task<int> CompareAsync(IServiceProvider services, ActDatabase db, string[] args)
    {
        var assessmentText = FlagValue(args, "--assessment");
        if (assessmentText is null || !Guid.TryParse(assessmentText, out var assessmentId))
        {
            Console.Error.WriteLine("error: --assessment ASSESSMENT_ID is required");
            return ExitCodes.UsageError;
        }

        Guid? baselineId = null;
        if (FlagValue(args, "--baseline") is { } baselineRaw)
        {
            if (!Guid.TryParse(baselineRaw, out var parsedBaseline))
            {
                Console.Error.WriteLine("error: --baseline must be a baseline identifier");
                return ExitCodes.UsageError;
            }

            baselineId = parsedBaseline;
        }

        var comparison = await BaselineOperations.CompareAsync(
            db, assessmentId, baselineId, "cli-operator", CorrelationId.New());

        var text = new StringBuilder();
        text.AppendLine(comparison.Observations.Count == 0
            ? "no drift: this assessment matches the baseline exactly."
            : comparison.Observations.Count + " drift observation(s):");
        foreach (var observation in comparison.Observations)
        {
            text.AppendLine("[" + observation.SuggestedSeverity + "] [" + observation.Kind + "] " + observation.Detail);
        }

        text.AppendLine("exit code: " + (comparison.Observations.Count > 0 ? ExitCodes.GateFailed + " (gate failed)" : ExitCodes.Ok));
        var json = JsonSerializer.Serialize(new
        {
            baselineId = comparison.BaselineId,
            scopeId = comparison.ScopeId,
            assessmentId = comparison.AssessmentId,
            comparedUtc = comparison.ComparedUtc,
            observationCount = comparison.Observations.Count,
            newFindings = comparison.Observations.Count(o => o.Kind == DriftAnalyzer.NewFinding),
            regressedFindings = comparison.Observations.Count(o => o.Kind == DriftAnalyzer.RegressedFinding),
            resolvedFindings = comparison.Observations.Count(o => o.Kind == DriftAnalyzer.ResolvedFinding),
            serviceDrift = comparison.Observations.Count(o =>
                o.Kind is DriftAnalyzer.UnexpectedServiceExposed or DriftAnalyzer.ExpectedServiceAbsent),
            observations = comparison.Observations.Select(o => new
            {
                kind = o.Kind,
                severity = o.SuggestedSeverity.ToString(),
                detail = o.Detail,
                fingerprintSuffix = o.FingerprintSuffix
            })
        }, JsonOpts.Indented);

        // The human path prints through WriteAsync; the gate decision rides the exit code so CI
        // and scheduled runs can fail honestly on drift without parsing output.
        var write = await OutputWriter.WriteAsync(services, text.ToString(), json);
        return comparison.Observations.Count > 0 ? ExitCodes.GateFailed : write;
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
