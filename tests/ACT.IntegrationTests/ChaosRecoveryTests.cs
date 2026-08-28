using ACT.Cli;
using ACT.Contracts;
using ACT.Desktop;
using ACT.Persistence;
using ACT.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;

namespace ACT.IntegrationTests;

/// <summary>
/// The production-readiness gaps a chaotic operator workflow exposes: the console's emergency
/// stop must be GLOBAL (the operator manual promises it cancels in-flight work in other
/// processes), and a hard crash must never strand an assessment row in a non-terminal state.
/// </summary>
public sealed class ChaosRecoveryTests
{
    private static async Task<RecoveryDb> CreateDatabaseAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), "act-chaos-recovery", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var databasePath = Path.Combine(directory, "act.db");
        var database = new ActDatabase(databasePath, new StorageOptions
        {
            DatabasePath = databasePath,
            WalEnabled = false,
            RetentionDays = 90
        });
        await database.InitializeAsync();
        return new RecoveryDb(directory, database);
    }

    private sealed record RecoveryDb(string Directory, ActDatabase Database) : IAsyncDisposable
    {
        public async ValueTask DisposeAsync()
        {
            await Database.DisposeAsync();
            SqliteConnection.ClearAllPools();
            try { System.IO.Directory.Delete(Directory, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static IServiceProvider BuildConsoleServices(RecoveryDb fixture)
    {
        var services = new ServiceCollection();
        services.AddSingleton(fixture.Database);
        services.AddSingleton<EmergencyStopProxy>();
        services.AddSingleton<EmergencyStop>();
        return services.BuildServiceProvider();
    }

    [Fact]
    public async Task ConsoleEmergencyStopPersistsTheGlobalFlag()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var provider = BuildConsoleServices(fixture);
            var db = fixture.Database;

            var result = await Pages.EmergencyStop(provider);
            // The handler redirects the operator back to the dashboard after arming.
            Assert.NotNull(result);
            Assert.Contains("Redirect", result.GetType().Name);

            // The persisted flag is what every other process polls: a CLI run in flight must
            // see it, not only this host's in-process latch.
            var flag = await db.GetConfigAsync<EmergencyStopFlag>(AssessmentCommands.EmergencyFlagKey);
            Assert.NotNull(flag);
            Assert.Contains("web console", flag!.Reason);

            // The decision is on the hash chain under the console actor.
            var events = await db.ReadRecentAuditAsync(10);
            Assert.Contains(events, e => e.Action == "assessment.emergency_stop"
                && e.Actor == "operator-console");
            Assert.True(await db.VerifyChainAsync());

            // The console's own view is armed too, so the dashboard banner renders.
            Assert.True(provider.GetRequiredService<EmergencyStopProxy>().Snapshot().Armed);
        }
    }

    [Fact]
    public async Task ConsoleDisarmClearsThePersistedFlagOtherProcessesPoll()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var provider = BuildConsoleServices(fixture);
            var db = fixture.Database;

            await Pages.EmergencyStop(provider);
            Assert.NotNull(await db.GetConfigAsync<EmergencyStopFlag>(AssessmentCommands.EmergencyFlagKey));

            await Pages.EmergencyStopDisarm(provider);

            Assert.Null(await db.GetConfigAsync<EmergencyStopFlag>(AssessmentCommands.EmergencyFlagKey));
            Assert.False(provider.GetRequiredService<EmergencyStopProxy>().Snapshot().Armed);
            var events = await db.ReadRecentAuditAsync(10);
            Assert.Contains(events, e => e.Action == "assessment.emergency_stop_disarmed");
        }
    }

    [Fact]
    public async Task OrphanReconciliationMarksStrandedRowsFailedAndAuditsIt()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var (assessment, scope) = MakeStrandedPair(
                state: AssessmentRunState.Running,
                createdUtc: DateTimeOffset.UtcNow.AddHours(-2));
            await db.CreateAssessmentAsync(assessment, scope);
            await db.SetConfigAsync("scope:" + assessment.AssessmentId.ToString("N"), scope);

            var reconciled = await AssessmentReconciliation.ReconcileOrphansAsync(db);

            Assert.Equal(1, reconciled);
            Assert.Equal(AssessmentRunState.Failed, (await db.GetAssessmentAsync(assessment.AssessmentId))!.State);
            var events = await db.ReadRecentAuditAsync(10);
            Assert.Contains(events, e => e.Action == "assessment.crash_reconciled"
                && e.ObjectId == assessment.AssessmentId.ToString());
            Assert.True(await db.VerifyChainAsync());
        }
    }

    [Fact]
    public async Task OrphanReconciliationNeverTouchesFreshOrTerminalRows()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;

            // Fresh in-flight row: a live process may own it right now.
            var fresh = MakeStrandedPair(AssessmentRunState.Running, DateTimeOffset.UtcNow);
            await db.CreateAssessmentAsync(fresh.Assessment, fresh.Scope);
            await db.SetConfigAsync("scope:" + fresh.Assessment.AssessmentId.ToString("N"), fresh.Scope);

            // Terminal rows are history; reconciliation never rewrites it.
            var done = MakeStrandedPair(AssessmentRunState.Completed, DateTimeOffset.UtcNow.AddDays(-5));
            await db.CreateAssessmentAsync(done.Assessment, done.Scope);
            await db.SetConfigAsync("scope:" + done.Assessment.AssessmentId.ToString("N"), done.Scope);

            var reconciled = await AssessmentReconciliation.ReconcileOrphansAsync(db);

            Assert.Equal(0, reconciled);
            Assert.Equal(AssessmentRunState.Running, (await db.GetAssessmentAsync(fresh.Assessment.AssessmentId))!.State);
            Assert.Equal(AssessmentRunState.Completed, (await db.GetAssessmentAsync(done.Assessment.AssessmentId))!.State);
        }
    }

    [Fact]
    public async Task OrphanReconciliationSkipsRowsWithoutAStoredScope()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            // CreateAssessmentAsync writes the scopes table, but reconciliation reads the
            // config-table copy the launch path stores via SetConfigAsync. A row without that
            // copy has no budget to check against, so it is skipped rather than guessed at.
            var scope = MakeScopeFor(new AssessmentRecord(
                Guid.NewGuid(), Guid.NewGuid(), "no-scope-row", AssessmentRunState.Running,
                DateTimeOffset.UtcNow.AddHours(-3), null, null, "op", "org"), TimeSpan.FromMinutes(5));
            var assessment = new AssessmentRecord(
                scope.AssessmentId, scope.ScopeId, "no-scope-row", AssessmentRunState.Running,
                DateTimeOffset.UtcNow.AddHours(-3), null, null, "op", "org");
            await db.CreateAssessmentAsync(assessment, scope);

            var reconciled = await AssessmentReconciliation.ReconcileOrphansAsync(db);

            Assert.Equal(0, reconciled);
            Assert.Equal(AssessmentRunState.Running, (await db.GetAssessmentAsync(assessment.AssessmentId))!.State);
        }
    }

    [Fact]
    public async Task AssessmentStatusSelfInitializesAFreshDatabase()
    {
        // The chaos workflow caught this: 'assessment status' was the one read command that
        // never initialized the database, so it failed with "not ready" on every fresh process.
        var directory = Path.Combine(Path.GetTempPath(), "act-status-init", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var databasePath = Path.Combine(directory, "act.db");

        // Phase 1: a fully initialized database creates the assessment.
        var writer = new ActDatabase(databasePath, new StorageOptions { DatabasePath = databasePath, WalEnabled = false });
        await writer.InitializeAsync();
        var scope = new ScopeDefinition(
            Guid.NewGuid(), Guid.NewGuid(), "status-op", "artemis-e2e", TargetTypeKind.Localhost,
            ["localhost"], [], [ProtocolKind.Http], [PortRange.Single(47391)], 5, 2,
            TimeSpan.FromMinutes(5), 500, Enum.GetValues<CheckCategory>(), [],
            EmergencyStopEnabled: true, EvidenceRetentionPeriod: TimeSpan.FromDays(30),
            DataRedactionPolicy: RedactionPolicy.Standard,
            AuthorizationStatement: "Status init test authorization.");
        var assessment = new AssessmentRecord(
            scope.AssessmentId, scope.ScopeId, "status-init", AssessmentRunState.Completed,
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(1), DateTimeOffset.UtcNow.AddMinutes(1),
            "status-op", "artemis-e2e");
        await writer.CreateAssessmentAsync(assessment, scope);
        await writer.DisposeAsync();
        SqliteConnection.ClearAllPools();

        // Phase 2: a FRESH database instance (not initialized) backs the status command. The
        // command must initialize itself or it fails closed with "not ready".
        var fresh = new ActDatabase(databasePath, new StorageOptions { DatabasePath = databasePath, WalEnabled = false });
        var services = new ServiceCollection();
        services.AddSingleton(fresh);
        services.AddSingleton(new GlobalOptions());
        await using var provider = services.BuildServiceProvider();

        var exit = await AssessmentCommands.Run(provider, ["status", assessment.AssessmentId.ToString(), "--json"]);

        Assert.Equal(ExitCodes.Ok, exit);
        try { System.IO.Directory.Delete(directory, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static (AssessmentRecord Assessment, ScopeDefinition Scope) MakeStrandedPair(
        AssessmentRunState state, DateTimeOffset createdUtc)
    {
        var assessmentId = Guid.NewGuid();
        var scope = new ScopeDefinition(
            Guid.NewGuid(), assessmentId, "chaos-operator", "artemis-e2e", TargetTypeKind.Localhost,
            ["localhost"], [], [ProtocolKind.Http], [PortRange.Single(47391)], 5, 2,
            // One-minute budget: anything still non-terminal two hours later is provably dead.
            TimeSpan.FromMinutes(1), 500, Enum.GetValues<CheckCategory>(), [],
            EmergencyStopEnabled: true, EvidenceRetentionPeriod: TimeSpan.FromDays(30),
            DataRedactionPolicy: RedactionPolicy.Standard,
            AuthorizationStatement: "Chaos recovery test authorization.");
        var assessment = new AssessmentRecord(
            assessmentId, scope.ScopeId, "chaos-recovery", state, createdUtc,
            state == AssessmentRunState.Completed ? createdUtc.AddMinutes(1) : null,
            null, scope.OperatorIdentity, scope.Organization);
        return (assessment, scope);
    }

    private static ScopeDefinition MakeScopeFor(AssessmentRecord assessment, TimeSpan maxRuntime) => new(
        Guid.NewGuid(), assessment.AssessmentId, "chaos-operator", "artemis-e2e",
        TargetTypeKind.Localhost, ["localhost"], [], [ProtocolKind.Http], [PortRange.Single(47391)],
        5, 2, maxRuntime, 500, Enum.GetValues<CheckCategory>(), [],
        EmergencyStopEnabled: true, EvidenceRetentionPeriod: TimeSpan.FromDays(30),
        DataRedactionPolicy: RedactionPolicy.Standard,
        AuthorizationStatement: "Chaos recovery test authorization.");
}
