
using System.Text.Json;
using ACT.Contracts;
using ACT.Persistence;
using ACT.Policy;
using Microsoft.Extensions.DependencyInjection;

namespace ACT.Cli;

/// <summary>artemis assessment create|start|status|stop.</summary>
public static class AssessmentCommands
{
    public static async Task<int> Run(IServiceProvider services, string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("usage: artemis assessment <create|start|status|stop> ...");
            return ExitCodes.UsageError;
        }
        return args[0] switch
        {
            "create" => await CreateAsync(services, args[1..]),
            "start" => await StartAsync(services, args[1..]),
            "status" => await StatusAsync(services, args[1..]),
            "stop" => await StopAsync(services, args[1..]),
            "disarm" => await DisarmAsync(services, args[1..]),
            _ => Usage()
        };

        static int Usage()
        {
            Console.Error.WriteLine("usage: artemis assessment create --scope FILE");
            Console.Error.WriteLine("       artemis assessment start --scope FILE [--base-url URL] [--fixtures FILE]");
            Console.Error.WriteLine("       artemis assessment status ASSESSMENT_ID");
            Console.Error.WriteLine("       artemis assessment stop --emergency REASON");
            Console.Error.WriteLine("       artemis assessment disarm --reason REASON");
            return ExitCodes.UsageError;
        }
    }

    private static ScopeDefinition LoadScope(string path)
    {
        var scope = ScopeFile.Load(path);
        scope.Validate();
        return scope;
    }

    private static async Task<int> CreateAsync(IServiceProvider services, string[] args)
    {
        var file = FlagValue(args, "--scope");
        if (file is null) { Console.Error.WriteLine("error: --scope FILE required"); return ExitCodes.UsageError; }

        var scope = LoadScope(file);
        var db = services.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();

        var record = new AssessmentRecord(
            scope.AssessmentId, scope.ScopeId,
            Path.GetFileNameWithoutExtension(file),
            AssessmentRunState.Created,
            DateTimeOffset.UtcNow, null, null,
            scope.OperatorIdentity, scope.Organization);

        await db.CreateAssessmentAsync(record, scope);
        // Persist the typed scope for later retrieval by reports and re-runs.
        await db.SetConfigAsync("scope:" + scope.AssessmentId.ToString("N"), scope);
        return await OutputWriter.WriteAsync(services,
            $"created assessment {record.AssessmentId} (scope {scope.ScopeId})",
            JsonSerializer.Serialize(new { assessmentId = record.AssessmentId, scopeId = scope.ScopeId }, JsonOpts.Indented));
    }

    private static async Task<int> StartAsync(IServiceProvider services, string[] args)
    {
        var file = FlagValue(args, "--scope");
        if (file is null) { Console.Error.WriteLine("error: --scope FILE required"); return ExitCodes.UsageError; }
        var baseUrlFlag = FlagValue(args, "--base-url");
        var fixturesFile = FlagValue(args, "--fixtures");

        var scope = LoadScope(file);

        var baseUrl = AssessmentLauncher.ResolveBaseUrl(baseUrlFlag, scope);
        if (baseUrl is null && scope.TargetType is not TargetTypeKind.LocalSourceRepository)
        {
            Console.Error.WriteLine("error: this scope needs --base-url to identify the HTTP origin to assess.");
            return ExitCodes.UsageError;
        }

        var fixtures = AuthorizationFixtureSet.None;
        if (fixturesFile is not null)
        {
            fixtures = FixturesFile.Load(fixturesFile);
            fixtures.Validate();
        }

        // The launch path is shared verbatim with scheduled executions so both entries get
        // identical authorization, budgeting, and audit behavior by construction.
        var summary = await AssessmentLauncher.LaunchAsync(services, scope, baseUrl, fixtures, CancellationToken.None);

        return await OutputWriter.WriteAsync(services,
            $"assessment {scope.AssessmentId} completed: {summary.ChecksExecuted} checks executed, " +
            $"{summary.Findings.Count} findings, {summary.RequestsReserved} requests in {summary.Duration.TotalSeconds:0.0}s",
            JsonSerializer.Serialize(new
            {
                assessmentId = scope.AssessmentId,
                state = summary.FinalState.ToString(),
                checksExecuted = summary.ChecksExecuted,
                findings = summary.Findings.Select(f => new
                {
                    title = f.Title,
                    severity = f.TechnicalSeverity.ToString(),
                    priority = Math.Round(f.PriorityScore, 1),
                    target = f.TargetDisplay
                })
            }, JsonOpts.Indented));
    }

    /// <summary>
    /// Arms a persistent emergency-stop flag. Running engines poll this flag through the same
    /// database they already use, so a separate 'artemis assessment stop' process cancels them.
    /// </summary>
    private static async Task<int> StopAsync(IServiceProvider services, string[] args)
    {
        var emergencyIndex = Array.FindIndex(args, a => a == "--emergency");
        if (emergencyIndex < 0 || emergencyIndex + 1 >= args.Length)
        {
            Console.Error.WriteLine("error: assessment stop requires --emergency REASON");
            Console.Error.WriteLine("       artemis assessment stop --emergency REASON");
            return ExitCodes.UsageError;
        }
        var reason = args[emergencyIndex + 1];

        var db = services.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();
        await db.SetConfigAsync(EmergencyFlagKey, new EmergencyStopFlag(DateTimeOffset.UtcNow, reason));
        await db.AppendAuditAsync(new AuditDraft(
            "operator", "assessment.emergency_stop", "configuration", EmergencyFlagKey,
            reason[..Math.Min(120, reason.Length)], CorrelationId.New()));

        // Arm this process's latch too, so a console-hosted engine stops immediately.
        services.GetRequiredService<EmergencyStop>().Arm(reason);

        return await OutputWriter.WriteAsync(services,
            "EMERGENCY STOP armed: " + reason,
            JsonSerializer.Serialize(new { emergencyStop = true, reason }));
    }

    /// <summary>
    /// The explicit operator action that ends an emergency stop. Clears BOTH denial surfaces -
    /// the persisted flag every process polls and this process's latch - and records the disarm
    /// in the hash-chained audit log. Disarming without an armed stop fails closed: a 'success'
    /// there would more likely signal a confused operator than a real state change.
    /// </summary>
    private static async Task<int> DisarmAsync(IServiceProvider services, string[] args)
    {
        var reasonIndex = Array.FindIndex(args, a => a == "--reason");
        if (reasonIndex < 0 || reasonIndex + 1 >= args.Length)
        {
            Console.Error.WriteLine("error: assessment disarm requires --reason REASON");
            Console.Error.WriteLine("       artemis assessment disarm --reason REASON");
            return ExitCodes.UsageError;
        }
        var reason = args[reasonIndex + 1];

        var db = services.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();
        var existing = await db.GetConfigAsync<EmergencyStopFlag>(EmergencyFlagKey);
        if (existing is null)
        {
            Console.Error.WriteLine("error: no emergency stop is armed; nothing to disarm");
            return ExitCodes.RuntimeFailure;
        }

        var removed = await db.ClearConfigAsync(EmergencyFlagKey);
        services.GetRequiredService<EmergencyStop>().Disarm("operator-cli");

        static string Truncate(string value) => value[..Math.Min(120, value.Length)];
        await db.AppendAuditAsync(new AuditDraft(
            "operator", "assessment.emergency_stop_disarmed", "configuration", EmergencyFlagKey,
            $"armed {existing.ArmedUtc:u} ({Truncate(existing.Reason)}) disarmed: {Truncate(reason)}",
            CorrelationId.New()));

        return await OutputWriter.WriteAsync(services,
            "EMERGENCY STOP disarmed" + (removed ? "" : " (flag was already absent)") + ": " + reason,
            JsonSerializer.Serialize(new { emergencyStop = false, reason }));
    }

    public const string EmergencyFlagKey = "emergency-stop";

    private static async Task<int> StatusAsync(IServiceProvider services, string[] args)
    {
        if (args.Length == 0 || !Guid.TryParse(args[0], out var id))
        {
            Console.Error.WriteLine("usage: artemis assessment status ASSESSMENT_ID");
            return ExitCodes.UsageError;
        }
        var db = services.GetRequiredService<ActDatabase>();
        var record = await db.GetAssessmentAsync(id);
        if (record is null)
        {
            Console.Error.WriteLine("error: assessment not found: " + id);
            return ExitCodes.RuntimeFailure;
        }
        var metrics = await db.GetMetricsAsync(id);
        return await OutputWriter.WriteAsync(services,
            $"{record.Name} [{record.State}] created {record.CreatedUtc:u} completed {record.CompletedUtc?.ToString("u") ?? "-"}",
            JsonSerializer.Serialize(new
            {
                record.AssessmentId,
                name = record.Name,
                state = record.State.ToString(),
                record.CreatedUtc,
                record.CompletedUtc,
                metrics = metrics == null
                    ? null
                    : new
                    {
                        requests = metrics.RequestsSent,
                        checksExecuted = metrics.ChecksExecuted,
                        checksFailed = metrics.ChecksFailed,
                        totalDurationMs = metrics.TotalDuration.TotalMilliseconds
                    }
            }, JsonOpts.Indented));
    }

    private static string? FlagValue(string[] args, string flag)
    {
        var index = Array.FindIndex(args, a => a == flag);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }
}

/// <summary>Run-scoped ledger collecting discovery output for the engine.</summary>
public sealed class CollectingLedger : IAssessmentLedger
{
    private readonly List<AssetRecord> _assets = [];
    private readonly List<ServiceObservation> _services = [];

    public Task<AssetRecord> RecordAssetAsync(AssetRecord asset, CancellationToken cancellationToken)
    {
        lock (_assets) _assets.Add(asset);
        return Task.FromResult(asset);
    }

    public Task<ServiceObservation> RecordServiceAsync(ServiceObservation service, CancellationToken cancellationToken)
    {
        lock (_services) _services.Add(service);
        return Task.FromResult(service);
    }

    public IReadOnlyList<ServiceObservation> ObservedServices() => [.. _services];
}
