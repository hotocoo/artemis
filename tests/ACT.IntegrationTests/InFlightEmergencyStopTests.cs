
using ACT.Cli;
using ACT.Cli.Composition;
using ACT.Contracts;
using ACT.Persistence;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ACT.IntegrationTests;

/// <summary>
/// The in-flight half of the emergency-stop contract, proven through the REAL launch path:
/// an assessment is already executing when a second operator arms the persisted flag, and the
/// launcher's watcher cancels it mid-run. The watch poll is bound to a small interval so the
/// scenario is deterministic at test speed; production keeps the two-second default.
/// </summary>
[Collection("lab")]
public sealed class InFlightEmergencyStopTests(LabFixture lab)
{
    [Fact]
    public async Task ArmingWhileRunningCancelsTheAssessmentMidFlight()
    {
        var directory = Path.Combine(Path.GetTempPath(), "act-inflight-stop", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var databasePath = Path.Combine(directory, "act.db");

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
        // Deterministic in-flight detection: 25 ms instead of the production 2 s.
        services.AddSingleton(new EmergencyStopWatchOptions { PollInterval = TimeSpan.FromMilliseconds(25) });
        await using var provider = services.BuildServiceProvider();

        var db = provider.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();

        var scope = MakeSlowLabScope();
        await db.CreateAssessmentAsync(new AssessmentRecord(
            scope.AssessmentId, scope.ScopeId, "inflight-stop-e2e",
            AssessmentRunState.Created, DateTimeOffset.UtcNow, null, null,
            scope.OperatorIdentity, scope.Organization), scope);
        await db.SetConfigAsync("scope:" + scope.AssessmentId.ToString("N"), scope);

        var launch = AssessmentLauncher.LaunchAsync(
            provider, scope, lab.BaseUrl, AuthorizationFixtureSet.None, CancellationToken.None);

        // Wait until the engine has actually entered Running and work exists, then arm from
        // "another process" by writing exactly what 'artemis assessment stop' persists.
        var armedUtc = await WaitUntilRunningThenArm(db, scope.AssessmentId);

        // The launcher propagates the engine's cancellation after marking the run stopped.
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            launch.WaitAsync(TimeSpan.FromSeconds(60)));

        var record = await db.GetAssessmentAsync(scope.AssessmentId);
        Assert.NotNull(record);
        Assert.Equal(AssessmentRunState.Stopped, record!.State);

        // No check completed AFTER the stop was armed: whatever was still executing at that
        // moment ends as the engine's cancellation marker, never as a quiet success.
        var runs = await db.ListCheckRunsAsync(scope.AssessmentId);
        foreach (var run in runs)
        {
            // A check finishing within the one watcher tick after the flag lands is still an
            // honest pre-stop completion; anything later must carry a cancellation marker.
            var cancelledMarker = run.Status is CheckExecutionStatus.TimedOut or CheckExecutionStatus.Failed_FailedClosed;
            Assert.True(cancelledMarker || run.CompletedUtc < armedUtc + TimeSpan.FromMilliseconds(500),
                run.CheckId + " completed well after the emergency stop was armed.");
        }

        var events = await db.ReadRecentAuditAsync(50);
        Assert.Contains(events, e => e.Action == "assessment.stopped"
            && e.ObjectId == scope.AssessmentId.ToString()
            && e.Result.Contains("runtime-limit-or-emergency"));
        Assert.True(await db.VerifyChainAsync());

        // The persisted flag outlives the cancelled run until an operator disarms - the next
        // launch attempt must be denied before any work, not merely cancelled later.
        await Assert.ThrowsAsync<ActException>(() => AssessmentLauncher.LaunchAsync(
            provider, MakeSlowLabScope(), lab.BaseUrl, AuthorizationFixtureSet.None, CancellationToken.None));
    }

    /// <summary>Low request rate keeps the battery running long enough to observe and interrupt.</summary>
    private ScopeDefinition MakeSlowLabScope() => new(
        ScopeId: Guid.NewGuid(),
        AssessmentId: Guid.NewGuid(),
        OperatorIdentity: "inflight-stop-operator",
        Organization: "artemis-e2e",
        TargetType: TargetTypeKind.Localhost,
        AllowlistedTargets: ["localhost", "127.0.0.1"],
        ExcludedTargets: [],
        PermittedProtocols: [ProtocolKind.Tcp, ProtocolKind.Http],
        PermittedPorts: [PortRange.Single(lab.BaseUrl.Port)],
        RequestsPerSecond: 5,
        ConcurrencyLimit: 2,
        MaxRuntime: TimeSpan.FromMinutes(5),
        MaxRequests: 500,
        AllowedCategories: Enum.GetValues<CheckCategory>(),
        ProhibitedCategories: [],
        EmergencyStopEnabled: true,
        EvidenceRetentionPeriod: TimeSpan.FromDays(7),
        DataRedactionPolicy: RedactionPolicy.Standard,
        AuthorizationStatement: "In-flight emergency stop scenario authorization.");

    private static async Task<DateTimeOffset> WaitUntilRunningThenArm(ActDatabase db, Guid assessmentId)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(30);
        while (DateTime.UtcNow < deadline)
        {
            var record = await db.GetAssessmentAsync(assessmentId);
            if (record?.State == AssessmentRunState.Running)
            {
                var armedUtc = DateTimeOffset.UtcNow;
                await db.SetConfigAsync(AssessmentCommands.EmergencyFlagKey,
                    new EmergencyStopFlag(armedUtc, "in-flight drill"));
                return armedUtc;
            }

            await Task.Delay(20);
        }

        throw new TimeoutException("Assessment never reached Running within 30 seconds.");
    }
}
