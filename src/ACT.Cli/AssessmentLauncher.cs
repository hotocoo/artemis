
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
using Microsoft.Extensions.DependencyInjection;

namespace ACT.Cli;

/// <summary>
/// The single path for turning a validated scope into a running assessment: scope compilation,
/// pinned-DNS validation, budgeted safe HTTP, emergency-flag watching, engine execution. Both the
/// interactive 'assessment start' command and scheduled executions launch through here, so every
/// entry point inherits identical authorization, budget, and audit behavior by construction.
/// </summary>
internal static class AssessmentLauncher
{
    /// <summary>
    /// Resolves the HTTP origin to assess: an explicit override wins; otherwise the first
    /// allowlisted http(s) URL target. Null means the scope is not URL-addressable.
    /// </summary>
    public static Uri? ResolveBaseUrl(string? explicitOverride, ScopeDefinition scope)
    {
        if (explicitOverride is not null) return new Uri(explicitOverride);
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

    /// <summary>Builds the asset record for one launch from the compiled scope's matchers.</summary>
    public static AssetRecord BuildAsset(ScopeDefinition scope, CompiledScope compiled, Uri? baseUrl)
    {
        var assetKind = scope.TargetType is TargetTypeKind.LocalSourceRepository ? AssetKind.Repository : AssetKind.Url;
        return new AssetRecord(
            Guid.NewGuid(), scope.AssessmentId, assetKind,
            assetKind == AssetKind.Repository ? "repository" : baseUrl!.Host,
            assetKind == AssetKind.Repository
                ? compiled.AllowMatchers.OfType<LocalRepositoryMatcher>().FirstOrDefault()?.RootPath ?? ""
                : baseUrl!.ToString(),
            [], DateTimeOffset.UtcNow, WithinScope: true);
    }

    /// <summary>
    /// Runs one full assessment synchronously. Requires a structurally valid scope and, for
    /// URL-target scopes, a resolved base URL (fails closed otherwise). Persists through the
    /// host's registered recorder and audit sink; polls the persisted emergency flag so a separate
    /// 'artemis assessment stop' process cancels this run.
    /// </summary>
    public static async Task<AssessmentRunSummary> LaunchAsync(
        IServiceProvider services,
        ScopeDefinition scope,
        Uri? baseUrl,
        AuthorizationFixtureSet fixtures,
        CancellationToken externalToken)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(scope);

        if (baseUrl is null && scope.TargetType is not TargetTypeKind.LocalSourceRepository)
        {
            throw ActException.FailClosed(ErrorCategory.Configuration,
                "This scope needs an HTTP origin before anything can be assessed.",
                $"Scope {scope.ScopeId} targets {scope.TargetType} but no base URL was resolved.");
        }

        var compiled = new CompiledScope(scope);
        var resolver = new PinningDnsResolver();
        var validator = new ScopeValidator(compiled, resolver);
        var limiter = new TokenBucketRateLimiter(scope.RequestsPerSecond);
        var budget = ResourceBudget.FromScope(scope, EngineDefaults.Conservative);
        var redactor = new StandardEvidenceRedactor(scope.DataRedactionPolicy);

        var emergency = services.GetRequiredService<EmergencyStop>();
        var gate = new PolicyGateAdapter(
            services.GetRequiredService<IPolicyEvaluator>(), emergency);

        await using var http = new SafeHttpEngine(
            validator, validator, budget, limiter, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);

        var evidenceFactory = new EvidenceFactory(redactor);
        var context = new AssessmentContext(
            scope.AssessmentId, scope, validator, http, limiter,
            evidenceFactory,
            Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance,
            fixtures, budget,
            Ledger: new CollectingLedger(), LanguageModel: null);

        var asset = BuildAsset(scope, compiled, baseUrl);
        await context.Ledger.RecordAssetAsync(asset, externalToken);

        var contexts = new List<SecurityCheckContext>
        {
            new(context, asset, Service: null, BaseUrl: baseUrl)
        };

        // Check selection mirrors the asset kind: URL-addressable targets receive the web/TLS/API
        // battery through the safe engine; local repository targets receive the network-free
        // source and dependency analyses. A scope that supports neither has no executable work.
        var checks = new List<ISecurityCheck>();
        if (baseUrl is not null)
        {
            checks.AddRange(CheckRegistry.CreateTargetedChecks(baseUrl));
            checks.Add(new ApiBehavioralCheck());
        }
        else if (scope.TargetType is TargetTypeKind.LocalSourceRepository or TargetTypeKind.TestEnvironment)
        {
            checks.AddRange(CheckRegistry.CreateRepositoryChecks(evidenceFactory));
        }

        var correlation = CorrelationId.New();

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(externalToken);
        var watcher = WatchEmergencyFlag(services, linkedCts, externalToken);
        context = context with { CancellationToken = linkedCts.Token };

        var engine = services.GetRequiredService<AssessmentEngine>();
        try
        {
            return await engine.RunAsync(new AssessmentRunRequest(
                scope.AssessmentId, correlation, scope, budget,
                checks, contexts, PreexistingFindings: null,
                Scorer: services.GetService<IFindingScorer>() ?? new DeterministicFindingScorer()),
                linkedCts.Token);
        }
        finally
        {
            linkedCts.Cancel();
            try { await watcher; } catch (OperationCanceledException) { }
        }
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
                var flag = await db.GetConfigAsync<EmergencyStopFlag>(AssessmentCommands.EmergencyFlagKey, external);
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
}
