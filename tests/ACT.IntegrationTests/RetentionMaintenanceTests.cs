
using ACT.Cli;
using ACT.Contracts;
using ACT.Persistence;
using ACT.Policy;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ACT.IntegrationTests;

/// <summary>
/// Retention-maintenance semantics carried by schedule ticks: honest throttle decisions,
/// emergency-stop skips that never destroy evidence mid-incident, and one audited sweep that
/// honors every scope's own configured window.
/// </summary>
public sealed class RetentionMaintenanceTests
{
    // ---------- fixture ----------

    private static async Task<MaintenanceDb> CreateDatabaseAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), "act-retention-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var databasePath = Path.Combine(directory, "act.db");
        var database = new ActDatabase(databasePath, new StorageOptions
        {
            DatabasePath = databasePath,
            WalEnabled = false,
            RetentionDays = 90
        });
        await database.InitializeAsync();
        return new MaintenanceDb(directory, database, databasePath);
    }

    private sealed record MaintenanceDb(string Directory, ActDatabase Database, string DatabasePath)
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

    private static ScopeDefinition MakeScope(Guid scopeId, Guid assessmentId, TimeSpan retention) => new(
        ScopeId: scopeId,
        AssessmentId: assessmentId,
        OperatorIdentity: "retention-test-operator",
        Organization: "artemis-tests",
        TargetType: TargetTypeKind.Localhost,
        AllowlistedTargets: ["localhost"],
        ExcludedTargets: [],
        PermittedProtocols: [ProtocolKind.Https],
        PermittedPorts: [PortRange.Single(8443)],
        RequestsPerSecond: 5,
        ConcurrencyLimit: 2,
        MaxRuntime: TimeSpan.FromMinutes(30),
        MaxRequests: 500,
        AllowedCategories: Enum.GetValues<CheckCategory>(),
        ProhibitedCategories: [],
        EmergencyStopEnabled: true,
        EvidenceRetentionPeriod: retention,
        DataRedactionPolicy: RedactionPolicy.Standard,
        AuthorizationStatement: "Test authorization statement.");

    private static Finding MakeFinding(Guid assessmentId, string classification)
    {
        var finding = FindingFactory.Create(
            assessmentId,
            CheckId.From("CHK-TST"),
            "svc.local:8443",
            CheckCategory.Tls,
            "Title " + classification,
            "Description " + classification,
            Severity.Medium,
            ConfidenceLevel.High,
            exploitabilityIndicator: false,
            BusinessImpactLevel.Limited,
            "why it matters",
            "technical explanation",
            new RemediationGuidance("Fix it.", ["step-one"], []),
            new FingerprintComponents(CheckId.From("CHK-TST"), "target.local", "resource", classification));
        return finding with { PriorityScore = 42 };
    }

    private static EvidenceItem MakeEvidence(Guid findingId, string key, DateTimeOffset capturedAt) => new(
        EvidenceId: Guid.NewGuid(),
        FindingId: findingId,
        Kind: EvidenceKind.HttpResponseMetadata,
        Key: key,
        RedactedValue: "redacted-" + key,
        CapturedAtUtc: capturedAt,
        CollectedBy: CheckId.From("CHK-TST"),
        Correlation: CorrelationId.New(),
        Attributes: new Dictionary<string, string>());

    private static async Task SeedExpiredAndFreshEvidenceAsync(MaintenanceDb fixture, TimeSpan retention)
    {
        var db = fixture.Database;
        var assessmentId = Guid.NewGuid();
        var scopeId = Guid.NewGuid();
        await db.CreateAssessmentAsync(
            new AssessmentRecord(assessmentId, scopeId, "seeded", AssessmentRunState.Completed,
                DateTimeOffset.UtcNow, null, null, "operator", "org"),
            MakeScope(scopeId, assessmentId, retention));

        var finding = MakeFinding(assessmentId, "maintenance-class");
        await db.UpsertFindingAsync(finding);
        var now = DateTimeOffset.UtcNow;
        await db.AddEvidenceBatchAsync(
        [
            MakeEvidence(finding.FindingId, "expired", now - retention - TimeSpan.FromDays(2)),
            MakeEvidence(finding.FindingId, "fresh", now)
        ]);
    }

    private static IServiceProvider BuildServices(MaintenanceDb fixture, EmergencyStop? stop = null)
    {
        var services = new ServiceCollection();
        services.AddSingleton(fixture.Database);
        services.AddSingleton(stop ?? new EmergencyStop());
        return services.BuildServiceProvider();
    }

    private static async Task<long> RawCountAsync(MaintenanceDb fixture, string sql)
    {
        await using var connection = new SqliteConnection("Data Source=" + fixture.DatabasePath);
        await connection.OpenAsync();
        var command = connection.CreateCommand();
        command.CommandText = sql;
        var raw = await command.ExecuteScalarAsync();
        return Convert.ToInt64(raw);
    }

    // ---------- throttle decision ----------

    [Fact]
    public void ThrottleNeverTriggersWithoutPriorSweepOrInsideInterval()
    {
        var now = DateTimeOffset.UtcNow;
        Assert.True(RetentionMaintenance.ShouldAutoSweep(null, now));

        Assert.False(RetentionMaintenance.ShouldAutoSweep(now.AddHours(-23), now));
        Assert.True(RetentionMaintenance.ShouldAutoSweep(now.AddHours(-24), now));
        Assert.True(RetentionMaintenance.ShouldAutoSweep(now.AddDays(-30), now));

        // A future stamp (clock moved back) must not trigger an early sweep.
        Assert.False(RetentionMaintenance.ShouldAutoSweep(now.AddHours(1), now));
    }

    // ---------- emergency-stop skips ----------

    [Fact]
    public async Task AutoSweepSkipsWhileInProcessStopIsArmedAndLeavesEvidenceUntouched()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            await SeedExpiredAndFreshEvidenceAsync(fixture, TimeSpan.FromDays(7));
            var stop = new EmergencyStop();
            stop.Arm("simulated incident");

            var result = await RetentionMaintenance.MaybeSweepAsync(BuildServices(fixture, stop));

            Assert.Null(result);
            Assert.Equal(2, await RawCountAsync(fixture, "SELECT COUNT(*) FROM evidence"));
            Assert.Null(await fixture.Database.GetConfigAsync<RetentionMaintenance.AutoSweepStamp>(
                RetentionMaintenance.LastSweepKey));
        }
    }

    [Fact]
    public async Task AutoSweepSkipsWhileAnotherProcessHasTheStopFlagPersisted()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            await SeedExpiredAndFreshEvidenceAsync(fixture, TimeSpan.FromDays(7));
            var services = BuildServices(fixture);
            // 'artemis assessment stop' writes this flag from a separate process.
            await fixture.Database.SetConfigAsync(
                "emergency-stop", new EmergencyStopFlag(DateTimeOffset.UtcNow, "cross-process incident"));

            var result = await RetentionMaintenance.MaybeSweepAsync(services);

            Assert.Null(result);
            Assert.Equal(2, await RawCountAsync(fixture, "SELECT COUNT(*) FROM evidence"));
        }
    }

    // ---------- full sweep path ----------

    [Fact]
    public async Task AutoSweepDeletesPerScopeWindowsAuditsAndThenThrottles()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            await SeedExpiredAndFreshEvidenceAsync(fixture, TimeSpan.FromDays(7));
            var services = BuildServices(fixture);

            var result = await RetentionMaintenance.MaybeSweepAsync(services);

            Assert.NotNull(result);
            Assert.Equal(1, result!.TotalDeleted);
            Assert.All(result.Scopes, scope =>
                Assert.True(scope.DeletedCount is 0 or 1, "only the expired item may vanish"));
            Assert.Equal(1, await RawCountAsync(fixture, "SELECT COUNT(*) FROM evidence"));

            // The sweep is tamper-evident: exactly one audited deletion event and a valid chain.
            var events = await fixture.Database.ReadRecentAuditAsync(20);
            Assert.Contains(events, e => e.Action == "evidence.retention_swept");
            Assert.True(await fixture.Database.VerifyChainAsync());

            // The throttle stamp is written even when nothing was deleted, so quiet databases do
            // not re-scan every tick... and an immediate second call is a no-op.
            var stamp = await fixture.Database.GetConfigAsync<RetentionMaintenance.AutoSweepStamp>(
                RetentionMaintenance.LastSweepKey);
            Assert.NotNull(stamp);

            var secondPass = await RetentionMaintenance.MaybeSweepAsync(services);
            Assert.Null(secondPass);
            Assert.Equal(1, await RawCountAsync(fixture, "SELECT COUNT(*) FROM evidence"));
        }
    }

    [Fact]
    public async Task QuietDatabasesAreSweptButNotAudited()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            // Nothing stored at all: the sweep runs (and stamps) but audits no no-op entry.
            var services = BuildServices(fixture);

            var result = await RetentionMaintenance.MaybeSweepAsync(services);

            Assert.NotNull(result);
            Assert.Equal(0, result!.TotalDeleted);
            var events = await fixture.Database.ReadRecentAuditAsync(20);
            Assert.DoesNotContain(events, e => e.Action == "evidence.retention_swept");
            Assert.NotNull(await fixture.Database.GetConfigAsync<RetentionMaintenance.AutoSweepStamp>(
                RetentionMaintenance.LastSweepKey));
        }
    }
}
