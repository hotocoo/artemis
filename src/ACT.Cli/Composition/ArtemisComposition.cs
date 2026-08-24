
using ACT.Contracts;
using ACT.Core;
using ACT.Persistence;
using ACT.Policy;
using ACT.Risk;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace ACT.Cli.Composition;

/// <summary>
/// Wires storage, policy, risk, and the engine together. Composition is explicit: nothing here
/// relies on reflection scanning, so every participating check is registered by name.
/// </summary>
public static class ArtemisComposition
{
    public static IServiceCollection AddArtemisPersistence(this IServiceCollection services)
    {
        services.AddSingleton<ActDatabase>(sp =>
        {
            var configuration = sp.GetRequiredService<IConfiguration>();
            var rawPath = configuration["Act:Storage:DatabasePath"] ?? "artemis.db";
            var databasePath = Path.IsPathRooted(rawPath)
                ? rawPath
                : Path.Combine(AppContext.BaseDirectory, rawPath);
            var walEnabled = !string.Equals(configuration["Act:Storage:WalEnabled"], "false", StringComparison.OrdinalIgnoreCase);
            return new ActDatabase(databasePath, new StorageOptions { DatabasePath = databasePath, WalEnabled = walEnabled });
        });
        services.AddSingleton<IAssessmentRecorder, DatabaseRecorder>();
        services.AddSingleton<IAuditSink>(sp => new DatabaseAuditSink(sp.GetRequiredService<ActDatabase>()));
        services.AddHostedService<DatabaseInitializationService>();
        return services;
    }

    public static IServiceCollection AddArtemisPolicy(this IServiceCollection services)
    {
        services.AddSingleton<EmergencyStop>();
        services.AddSingleton<IPolicyEvaluator>(sp => new ScopePolicyEvaluator(
            sp.GetRequiredService<EmergencyStop>(),
            ScopePolicyEvaluator.AllPermissions,
            allowActiveChecks: true));
        services.AddSingleton<ICheckGate, PolicyGateAdapter>();
        return services;
    }

    public static IServiceCollection AddArtemisRisk(this IServiceCollection services)
    {
        services.AddSingleton<IFindingScorer, DeterministicFindingScorer>();
        return services;
    }
}

/// <summary>Initializes the SQLite schema at host start so commands never race migrations.</summary>
public sealed class DatabaseInitializationService(ActDatabase database, ILogger<DatabaseInitializationService> logger) : IHostedService
{
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await database.InitializeAsync(cancellationToken);
        logger.LogInformation("Artemis database initialized");
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}

/// <summary>Bridges policy verdicts into the engine's gate abstraction.</summary>
public sealed class PolicyGateAdapter(IPolicyEvaluator policy, EmergencyStop emergencyStop) : ICheckGate
{
    public GateDecision Evaluate(ScopeDefinition scope, SecurityCheckMetadata metadata)
    {
        if (emergencyStop.IsArmed)
        {
            return GateDecision.Deny("EMERGENCY_STOP_ARMED", "Emergency stop is armed; no checks may run.");
        }
        var decision = policy.Evaluate(scope, metadata);
        return decision.Allowed
            ? GateDecision.Allow()
            : GateDecision.Deny(decision.ReasonCode, decision.SafeMessage);
    }
}

/// <summary>Maps findings onto deterministic risk inputs.</summary>
public sealed class DeterministicFindingScorer : IFindingScorer
{
    private static readonly HashSet<CheckCategory> NetworkFacing =
    [
        CheckCategory.Network, CheckCategory.Tls, CheckCategory.Http, CheckCategory.Api, CheckCategory.Authorization
    ];

    public double Score(Finding finding) => DeterministicRiskScorer.Score(new RiskInput(
        finding.TechnicalSeverity,
        finding.Confidence,
        finding.ExploitabilityIndicator,
        ExposedToNetwork: NetworkFacing.Contains(finding.Category),
        Recurring: finding.Status is FindingStatus.Regressed or FindingStatus.Reopened,
        RemediationAvailable: finding.Remediation.Steps.Count > 0,
        finding.BusinessImpact));
}

/// <summary>Persists engine output through the database.</summary>
public sealed class DatabaseRecorder(ActDatabase database, ILogger<DatabaseRecorder> logger) : IAssessmentRecorder
{
    private static readonly Lock WriteLock = new();

    public async Task<AssetRecord> RecordAssetAsync(AssetRecord asset, CancellationToken cancellationToken)
    {
        await database.AddAssetAsync(asset, cancellationToken);
        return asset;
    }

    public async Task<ServiceObservation> RecordServiceAsync(ServiceObservation service, CancellationToken cancellationToken)
    {
        await database.AddServiceAsync(service, cancellationToken);
        return service;
    }

    public IReadOnlyList<ServiceObservation> ObservedServices() => [];

    public async Task UpsertFindingAsync(Finding finding, CancellationToken cancellationToken)
    {
        await database.UpsertFindingAsync(finding, cancellationToken);
        logger.LogDebug("Finding upserted: {Fingerprint}", finding.Fingerprint.Hash[..12]);
    }

    public Task RecordEvidenceBatchAsync(IReadOnlyList<EvidenceItem> items, CancellationToken cancellationToken) =>
        database.AddEvidenceBatchAsync(items, cancellationToken);

    public Task RecordCheckRunAsync(SecurityCheckResult result, Guid assessmentId, CancellationToken cancellationToken) =>
        database.RecordCheckRunAsync(result, assessmentId, cancellationToken);

    public Task SetAssessmentStateAsync(Guid assessmentId, AssessmentRunState state, CancellationToken cancellationToken) =>
        database.UpdateAssessmentStateAsync(assessmentId, state, cancellationToken);
}
