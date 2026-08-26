
using ACT.Cli;
using ACT.Contracts;
using ACT.Persistence;
using ACT.Policy;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ACT.IntegrationTests;

/// <summary>
/// The full emergency-stop lifecycle across processes and surfaces: arming persists a flag that
/// denies new launches and pauses maintenance, disarming requires an explicit operator reason,
/// clears BOTH surfaces, is audited, and work resumes afterwards.
/// </summary>
public sealed class EmergencyStopLifecycleTests
{
    private static async Task<LifecycleDb> CreateDatabaseAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), "act-stop-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var databasePath = Path.Combine(directory, "act.db");
        var database = new ActDatabase(databasePath, new StorageOptions
        {
            DatabasePath = databasePath,
            WalEnabled = false,
            RetentionDays = 90
        });
        await database.InitializeAsync();
        return new LifecycleDb(directory, database, databasePath);
    }

    private sealed record LifecycleDb(string Directory, ActDatabase Database, string DatabasePath)
        : IAsyncDisposable
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

    private static IServiceProvider BuildServices(LifecycleDb fixture)
    {
        var services = new ServiceCollection();
        services.AddSingleton(fixture.Database);
        services.AddSingleton(new EmergencyStop());
        // Command handlers print through OutputWriter, which reads the parsed globals.
        services.AddSingleton(new GlobalOptions());
        return services.BuildServiceProvider();
    }

    /// <summary>A repository-target scope: LaunchAsync needs no base URL for it.</summary>
    private static ScopeDefinition MakeRepositoryScope() => new(
        ScopeId: Guid.NewGuid(),
        AssessmentId: Guid.NewGuid(),
        OperatorIdentity: "stop-test-operator",
        Organization: "artemis-tests",
        TargetType: TargetTypeKind.LocalSourceRepository,
        AllowlistedTargets: ["./src"],
        ExcludedTargets: [],
        PermittedProtocols: [ProtocolKind.Tcp],
        PermittedPorts: [PortRange.Single(443)],
        RequestsPerSecond: 5,
        ConcurrencyLimit: 2,
        MaxRuntime: TimeSpan.FromMinutes(10),
        MaxRequests: 100,
        AllowedCategories: Enum.GetValues<CheckCategory>(),
        ProhibitedCategories: [],
        EmergencyStopEnabled: true,
        EvidenceRetentionPeriod: TimeSpan.FromDays(7),
        DataRedactionPolicy: RedactionPolicy.Standard,
        AuthorizationStatement: "Stop-lifecycle test authorization.");

    [Fact]
    public async Task ArmedStopDeniesNewLaunchesBeforeAnyWork()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var provider = BuildServices(fixture);
            var stopExit = await AssessmentCommands.Run(provider, ["stop", "--emergency", "active incident"]);
            Assert.Equal(ExitCodes.Ok, stopExit);

            // The launcher must refuse BEFORE resolving any engine service: a provider without a
            // policy evaluator proves the denial came from the pre-flight, not from later wiring.
            await Assert.ThrowsAsync<ActException>(() =>
                AssessmentLauncher.LaunchAsync(
                    provider, MakeRepositoryScope(), null, AuthorizationFixtureSet.None, CancellationToken.None));
        }
    }

    [Fact]
    public async Task DisarmRequiresAnArmedStopAndAnExplicitReason()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var provider = BuildServices(fixture);

            var missingReason = await AssessmentCommands.Run(provider, ["disarm"]);
            Assert.Equal(ExitCodes.UsageError, missingReason);

            var nothingArmed = await AssessmentCommands.Run(provider, ["disarm", "--reason", "all clear"]);
            Assert.Equal(ExitCodes.RuntimeFailure, nothingArmed);
        }
    }

    [Fact]
    public async Task FullLifecycleArmDenyDisarmResumeIsAudited()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var provider = BuildServices(fixture);

            // Arm via one surface; the persisted flag is what every other process polls.
            Assert.Equal(ExitCodes.Ok, await AssessmentCommands.Run(
                provider, ["stop", "--emergency", "active incident"]));
            Assert.NotNull(await db.GetConfigAsync<EmergencyStopFlag>(AssessmentCommands.EmergencyFlagKey));

            // While armed, retention maintenance skips honestly - evidence outlives the incident.
            Assert.Null(await RetentionMaintenance.MaybeSweepAsync(provider));

            // Disarm from the CLI surface clears the persisted state...
            Assert.Equal(ExitCodes.Ok, await AssessmentCommands.Run(
                provider, ["disarm", "--reason", "incident closed"]));
            Assert.Null(await db.GetConfigAsync<EmergencyStopFlag>(AssessmentCommands.EmergencyFlagKey));

            // ...and the same operator action disarms this process's latch too.
            Assert.False(provider.GetRequiredService<EmergencyStop>().IsArmed);

            // Both lifecycle transitions are tamper-evident and the chain still verifies.
            var events = await db.ReadRecentAuditAsync(20);
            Assert.Contains(events, e => e.Action == "assessment.emergency_stop");
            Assert.Contains(events, e => e.Action == "assessment.emergency_stop_disarmed"
                && e.Result.Contains("active incident") && e.Result.Contains("incident closed"));
            Assert.True(await db.VerifyChainAsync());

            // Work resumes: with no emergency anywhere, launches proceed past pre-flight (the
            // provider lacks an evaluator, so failure identity proves WHERE execution reached).
            await Assert.ThrowsAsync<InvalidOperationException>(() =>
                AssessmentLauncher.LaunchAsync(
                    provider, MakeRepositoryScope(), null, AuthorizationFixtureSet.None, CancellationToken.None));
        }
    }
}
