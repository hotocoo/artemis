using ACT.Cli;
using ACT.Cli.Composition;
using ACT.Contracts;
using ACT.Core;
using ACT.Persistence;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ACT.IntegrationTests;

/// <summary>
/// The planning-exclusion ledger through the REAL production path: a full assessment launched
/// via AssessmentLauncher against the disposable loopback lab, persisted through the real
/// DatabaseRecorder into real SQLite, audited through the real hash chain, and read back
/// through the same coverage surface the CLI and operator console render.
/// </summary>
[Collection("lab")]
public sealed class PlanExclusionLedgerEndToEndTests(LabFixture lab)
{
    [Fact]
    public async Task LaunchedAssessment_PersistsEveryPlanningExclusionAndCoverageSurfacesThem()
    {
        var directory = Path.Combine(Path.GetTempPath(), "act-plan-e2e", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var databasePath = Path.Combine(directory, "act.db");

        // Exactly the production wiring minus host transport: ArtemisHostFactory.ConfigureServices
        // (core engine, logging) plus persistence, policy gate, and risk - pointed at a throwaway
        // database file.
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Act:Storage:DatabasePath"] = databasePath,
            ["Act:Storage:WalEnabled"] = "false"
        }).Build();
        var services = new ServiceCollection();
        ArtemisHostFactory.ConfigureServices(services, configuration, new GlobalOptions());
        services.AddArtemisPersistence();
        services.AddArtemisPolicy();
        services.AddArtemisRisk();
        await using var provider = services.BuildServiceProvider();

        var db = provider.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();

        // Mirror the real 'artemis assessment start' sequence exactly: the assessment row and
        // its typed scope copy exist BEFORE the launcher runs.
        var scope = MakeLabScope(lab);
        await db.CreateAssessmentAsync(new AssessmentRecord(
            scope.AssessmentId, scope.ScopeId, "plan-exclusion-e2e",
            AssessmentRunState.Created, DateTimeOffset.UtcNow, null, null,
            scope.OperatorIdentity, scope.Organization), scope);
        await db.SetConfigAsync("scope:" + scope.AssessmentId.ToString("N"), scope);

        var summary = await AssessmentLauncher.LaunchAsync(
            provider, scope, lab.BaseUrl, AuthorizationFixtureSet.None, CancellationToken.None);

        // The assessment really ran against the lab...
        Assert.Equal(AssessmentRunState.Completed, summary.FinalState);
        Assert.True(summary.ChecksExecuted > 0, "the web battery should have executed against the lab");

        // ...and its plan carried deterministic exclusions (the scope denies the whole
        // Authorization category, so the fixture-driven API behavioral check - the only check
        // declaring that category - was kept out BEFORE any work ran).
        Assert.NotEmpty(summary.Exclusions);
        var apiExclusion = Assert.Single(summary.Exclusions, e => e.CheckId == "ACT-API-BEHAVIOR-001");
        Assert.False(string.IsNullOrWhiteSpace(apiExclusion.ReasonCode));

        // Every decision became a stored row - none lost, none invented.
        var stored = await db.ListPlanExclusionsAsync(scope.AssessmentId);
        Assert.Equal(summary.Exclusions.Count, stored.Count);
        foreach (var decision in summary.Exclusions)
        {
            Assert.Contains(stored, s => s.CheckId == decision.CheckId
                && s.ReasonCode == decision.ReasonCode
                && s.Detail == decision.SafeMessage);
        }

        // The decision is tamper-evident in the audit chain like every lifecycle event.
        var events = await db.ReadRecentAuditAsync(100);
        Assert.Contains(events, e => e.Action == "plan.exclusions"
            && e.ObjectId == scope.AssessmentId.ToString());
        Assert.True(await db.VerifyChainAsync());

        // The coverage surface answers "why did this check never run?" strictly from those
        // stored rows. The excluded behavioral check is carried with its persisted reason and
        // never leaks into the unexplained column.
        var snapshot = await CoverageOperations.BuildAsync(db, scope.AssessmentId);
        Assert.Equal(stored.Count, snapshot.PlanExclusions.Count);
        var excludedIds = stored.Select(static s => s.CheckId).ToHashSet(StringComparer.Ordinal);
        Assert.Contains(excludedIds, id => id == "ACT-API-BEHAVIOR-001");
        Assert.DoesNotContain(snapshot.UnexplainedNeverExecuted, m => excludedIds.Contains(m.Id.Value));

        // Registered catalog checks with no execution and NO stored reason (the repository-only
        // analyses, never offered on a URL target) remain visible as an honest gap - the surface
        // refuses to invent excuses for them.
        Assert.Equal(
            snapshot.NeverExecuted.Where(m => !excludedIds.Contains(m.Id.Value)).Select(m => m.Id.Value).OrderBy(x => x),
            snapshot.UnexplainedNeverExecuted.Select(m => m.Id.Value).OrderBy(x => x));
    }

    /// <summary>
    /// The lab scope deliberately denies the Authorization category so the plan provably
    /// excludes the fixture-driven API behavioral check even though it was offered to the
    /// orchestrator. No other registered check declares that category.
    /// </summary>
    private ScopeDefinition MakeLabScope(LabFixture lab)
    {
        var allowed = Enum.GetValues<CheckCategory>().Where(c => c != CheckCategory.Authorization).ToArray();
        return new ScopeDefinition(
            ScopeId: Guid.NewGuid(),
            AssessmentId: Guid.NewGuid(),
            OperatorIdentity: "plan-e2e-operator",
            Organization: "artemis-e2e",
            TargetType: TargetTypeKind.Localhost,
            AllowlistedTargets: ["localhost", "127.0.0.1"],
            ExcludedTargets: [],
            PermittedProtocols: [ProtocolKind.Tcp, ProtocolKind.Http],
            PermittedPorts: [PortRange.Single(lab.BaseUrl.Port)],
            RequestsPerSecond: 50,
            ConcurrencyLimit: 4,
            MaxRuntime: TimeSpan.FromMinutes(5),
            MaxRequests: 500,
            AllowedCategories: allowed,
            ProhibitedCategories: [CheckCategory.Authorization],
            EmergencyStopEnabled: true,
            EvidenceRetentionPeriod: TimeSpan.FromDays(7),
            DataRedactionPolicy: RedactionPolicy.Standard,
            AuthorizationStatement: "E2E authorization statement for the local test lab.");
    }
}
