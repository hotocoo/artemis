
using System.Text.Json;
using ACT.Api;
using ACT.Cli.Composition;
using ACT.Contracts;
using ACT.Core;
using ACT.Evidence;
using ACT.Network;
using ACT.Persistence;
using ACT.Policy;
using ACT.Risk;
using ACT.Scope;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

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
            _ => Usage()
        };

        static int Usage()
        {
            Console.Error.WriteLine("usage: artemis assessment create --scope FILE");
            Console.Error.WriteLine("       artemis assessment start --scope FILE [--base-url URL] [--fixtures FILE]");
            Console.Error.WriteLine("       artemis assessment status ASSESSMENT_ID");
            Console.Error.WriteLine("       artemis assessment stop --emergency REASON");
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
        var configuration = services.GetRequiredService<IConfiguration>();
        _ = configuration; // limits already validated at host build

        var compiled = new CompiledScope(scope);
        var resolver = new PinningDnsResolver();
        var validator = new ScopeValidator(compiled, resolver);
        var limiter = new TokenBucketRateLimiter(scope.RequestsPerSecond);
        var budget = ResourceBudget.FromScope(scope, EngineDefaults.Conservative);
        var redactor = new StandardEvidenceRedactor(scope.DataRedactionPolicy);

        var baseUrl = ResolveBaseUrl(baseUrlFlag, scope);
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

        var emergency = services.GetRequiredService<EmergencyStop>();
        var gate = new PolicyGateAdapter(
            services.GetRequiredService<IPolicyEvaluator>(), emergency);

        await using var http = new SafeHttpEngine(validator, validator, budget, limiter, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);
        AssessmentContext context = new AssessmentContext(
            scope.AssessmentId, scope, validator, http, limiter,
            new EvidenceFactory(redactor), Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, fixtures, budget,
            Ledger: new CollectingLedger(), LanguageModel: null)
        {
            CancellationToken = CancellationToken.None
        };

        var assetKind = scope.TargetType is TargetTypeKind.LocalSourceRepository ? AssetKind.Repository : AssetKind.Url;
        var asset = new AssetRecord(Guid.NewGuid(), scope.AssessmentId, assetKind,
            assetKind == AssetKind.Repository ? "repository" : baseUrl!.Host,
            assetKind == AssetKind.Repository
                ? compiled.AllowMatchers.OfType<LocalRepositoryMatcher>().FirstOrDefault()?.RootPath ?? ""
                : baseUrl!.ToString(),
            [], DateTimeOffset.UtcNow, WithinScope: true);
        await context.Ledger.RecordAssetAsync(asset, CancellationToken.None);

        var contexts = new List<SecurityCheckContext>
        {
            new(context, asset, Service: null, BaseUrl: baseUrl)
        };

        var checks = new List<ISecurityCheck>();
        if (baseUrl is not null)
        {
            checks.AddRange(CheckRegistry.CreateTargetedChecks(baseUrl));
            checks.Add(new ApiBehavioralCheck());
            if (fixtures.Expectations.Count > 0)
            {
                contexts[0] = contexts[0] with { BaseUrl = baseUrl };
            }
        }

        var correlation = CorrelationId.New();

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken.None);
        var watcher = WatchEmergencyFlag(services, linkedCts, linkedCts.Token);
        context = context with { CancellationToken = linkedCts.Token };

        var engine = services.GetRequiredService<AssessmentEngine>();
        AssessmentRunSummary summary;
        try
        {
            summary = await engine.RunAsync(new AssessmentRunRequest(
                scope.AssessmentId, correlation, scope, budget,
                checks, contexts, PreexistingFindings: null,
                Scorer: new DeterministicFindingScorer()), linkedCts.Token);
        }
        finally
        {
            linkedCts.Cancel();
            try { await watcher; } catch (OperationCanceledException) { }
        }

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
                    title = f.Title, severity = f.TechnicalSeverity.ToString(),
                    priority = Math.Round(f.PriorityScore, 1), target = f.TargetDisplay
                })
            }, JsonOpts.Indented));
    }

    private static Uri? ResolveBaseUrl(string? explicitFlag, ScopeDefinition scope)
    {
        if (explicitFlag is not null) return new Uri(explicitFlag);
        foreach (var entry in scope.AllowlistedTargets)
        {
            if (entry.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                entry.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                return new Uri(entry);
            }
        }
        return null;
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

    /// <summary>Polls the persisted emergency flag and cancels the linked token when armed.</summary>
    private static async Task WatchEmergencyFlag(IServiceProvider services, CancellationTokenSource linked,
        CancellationToken external)
    {
        var db = services.GetRequiredService<ActDatabase>();
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(2));
        try
        {
            while (await timer.WaitForNextTickAsync(external))
            {
                if (linked.IsCancellationRequested) return;
                var flag = await db.GetConfigAsync<EmergencyStopFlag>(EmergencyFlagKey, external);
                if (flag is not null)
                {
                    linked.Cancel();
                    return;
                }
            }
        }
        catch (OperationCanceledException)
        {
            // External cancellation ends the watcher normally.
        }
    }

    internal const string EmergencyFlagKey = "emergency-stop";

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
                record.AssessmentId, name = record.Name, state = record.State.ToString(),
                record.CreatedUtc, record.CompletedUtc,
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
