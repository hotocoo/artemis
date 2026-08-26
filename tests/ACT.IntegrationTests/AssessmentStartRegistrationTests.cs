
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
/// The documented operator flow is a single 'artemis assessment start --scope FILE'. These tests
/// pin the launcher guarantee that makes that honest: a launch with NO prior registration creates
/// the assessment row and its typed scope copy itself, so state transitions, coverage, and report
/// generation all find their records instead of failing closed mid-run. An explicit
/// 'assessment create' first remains fully supported and must not duplicate or conflict.
/// </summary>
[Collection("lab")]
public sealed class AssessmentStartRegistrationTests(LabFixture lab)
{
    private static (ServiceProvider Provider, string Directory) BuildProvider()
    {
        var directory = Path.Combine(Path.GetTempPath(), "act-start-reg", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Act:Storage:DatabasePath"] = Path.Combine(directory, "act.db"),
            ["Act:Storage:WalEnabled"] = "false"
        }).Build();
        var services = new ServiceCollection();
        ArtemisHostFactory.ConfigureServices(services, configuration, new GlobalOptions());
        services.AddArtemisPersistence();
        services.AddArtemisPolicy();
        services.AddArtemisRisk();
        return (services.BuildServiceProvider(), directory);
    }

    private ScopeDefinition MakeLabScope() => new(
        ScopeId: Guid.NewGuid(),
        AssessmentId: Guid.NewGuid(),
        OperatorIdentity: "start-reg-operator",
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
        AllowedCategories: Enum.GetValues<CheckCategory>(),
        ProhibitedCategories: [],
        EmergencyStopEnabled: true,
        EvidenceRetentionPeriod: TimeSpan.FromDays(7),
        DataRedactionPolicy: RedactionPolicy.Standard,
        AuthorizationStatement: "E2E authorization statement for the local test lab.");

    [Fact]
    public async Task StartWithoutCreate_RegistersItselfAndCompletes()
    {
        var (provider, _) = BuildProvider();
        await using var _ = provider;
        var db = provider.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();

        var scope = MakeLabScope();

        // No CreateAssessmentAsync, no scope config - exactly what the CLI 'start' one-liner gets.
        var summary = await AssessmentLauncher.LaunchAsync(
            provider, scope, lab.BaseUrl, AuthorizationFixtureSet.None, CancellationToken.None);

        Assert.Equal(AssessmentRunState.Completed, summary.FinalState);

        // The lifecycle row now exists, is COMPLETED, and the typed scope copy reports read by
        // assessment id is present - the run is fully visible to every downstream surface.
        var record = await db.GetAssessmentAsync(scope.AssessmentId);
        Assert.NotNull(record);
        Assert.Equal(AssessmentRunState.Completed, record!.State);
        var storedScope = await db.GetConfigAsync<ScopeDefinition>("scope:" + scope.AssessmentId.ToString("N"));
        Assert.NotNull(storedScope);
        Assert.Equal(scope.ScopeId, storedScope!.ScopeId);
    }

    [Fact]
    public async Task StartAfterCreate_DoesNotDuplicateOrConflict()
    {
        var (provider, _) = BuildProvider();
        await using var _ = provider;
        var db = provider.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();

        var scope = MakeLabScope();
        const string operatorLabel = "explicit-create-operator";
        await db.CreateAssessmentAsync(new AssessmentRecord(
            scope.AssessmentId, scope.ScopeId, "pre-registered",
            AssessmentRunState.Created, DateTimeOffset.UtcNow, null, null,
            operatorLabel, "artemis-e2e"), scope);
        await db.SetConfigAsync("scope:" + scope.AssessmentId.ToString("N"), scope);

        var summary = await AssessmentLauncher.LaunchAsync(
            provider, scope, lab.BaseUrl, AuthorizationFixtureSet.None, CancellationToken.None);

        Assert.Equal(AssessmentRunState.Completed, summary.FinalState);

        // Exactly one row, still carrying the explicit creation's operator identity.
        var record = await db.GetAssessmentAsync(scope.AssessmentId);
        Assert.NotNull(record);
        Assert.Equal(operatorLabel, record!.OperatorIdentity);
    }
}
