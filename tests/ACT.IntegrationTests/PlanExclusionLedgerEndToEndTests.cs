using ACT.Cli;
using ACT.Cli.Composition;
using ACT.Contracts;
using ACT.Core;
using ACT.Persistence;
using ACT.Tls.Checks;
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

        // The launcher's composition decisions are stored facts too: on this URL-addressable
        // scope the repository-only analyses were never composed, and each omission carries its
        // own persisted TARGET_TYPE_MISMATCH decision - worded exactly like the orchestrator's.
        foreach (var repoCheckId in new[] { "ACT-SRC-SCAN-001", "ACT-DEP-AUDIT-001" })
        {
            var row = Assert.Single(stored, s => s.CheckId == repoCheckId);
            Assert.Equal("TARGET_TYPE_MISMATCH", row.ReasonCode);
            Assert.Equal("Check does not support asset kind Url.", row.Detail);
        }

        // The TLS inspection battery is composed for every URL origin but requires a Tls-
        // protocol service; against this plain-http origin each member's exclusion is a stored
        // PROTOCOL_MISMATCH fact instead of an invisible omission.
        foreach (var tlsCheckId in new[] { "ACT-TLS-CERT-001", "ACT-TLS-PROTOCOL-002", "ACT-TLS-CIPHER-003" })
        {
            var tlsRow = Assert.Single(stored, s => s.CheckId == tlsCheckId);
            Assert.Equal("PROTOCOL_MISMATCH", tlsRow.ReasonCode);
        }

        // A production-path launch leaves NO registered check without either a recorded
        // execution or a stored reason: the unexplained column is empty by construction.
        Assert.Empty(snapshot.UnexplainedNeverExecuted);
    }

    [Fact]
    public async Task HttpsOrigin_ExecutesTlsInspectionBatteryAndReportsCertificateFindings()
    {
        var directory = Path.Combine(Path.GetTempPath(), "act-plan-e2e", Guid.NewGuid().ToString("N"));
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
        await using var provider = services.BuildServiceProvider();

        var db = provider.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();

        var allowed = Enum.GetValues<CheckCategory>().Where(c => c != CheckCategory.Authorization).ToArray();
        var scope = new ScopeDefinition(
            ScopeId: Guid.NewGuid(), AssessmentId: Guid.NewGuid(),
            OperatorIdentity: "tls-e2e-operator", Organization: "artemis-e2e",
            TargetType: TargetTypeKind.Localhost,
            AllowlistedTargets: ["localhost", "127.0.0.1"], ExcludedTargets: [],
            PermittedProtocols: [ProtocolKind.Tcp, ProtocolKind.Http, ProtocolKind.Https, ProtocolKind.Tls],
            PermittedPorts: [PortRange.Single(lab.BaseUrl.Port), PortRange.Single(lab.HttpsBaseUrl.Port)],
            RequestsPerSecond: 50, ConcurrencyLimit: 4, MaxRuntime: TimeSpan.FromMinutes(5),
            MaxRequests: 500, AllowedCategories: allowed, ProhibitedCategories: [CheckCategory.Authorization],
            EmergencyStopEnabled: true, EvidenceRetentionPeriod: TimeSpan.FromDays(7),
            DataRedactionPolicy: RedactionPolicy.Standard,
            AuthorizationStatement: "HTTPS E2E authorization statement for the local test lab.");

        var summary = await AssessmentLauncher.LaunchAsync(
            provider, scope, lab.HttpsBaseUrl, AuthorizationFixtureSet.None, CancellationToken.None);

        Assert.Equal(AssessmentRunState.Completed, summary.FinalState);

        // The handshake battery ran through the pinned-DNS safe path and observed the lab's
        // self-signed certificate chain.
        Assert.Contains(summary.CheckResults, r => r.CheckId == CertificateTrustCheck.CheckIdentifier
            && r.Status is CheckExecutionStatus.Completed or CheckExecutionStatus.CompletedWithWarnings);
        // Whichever trust state the lab's chain classifies as (self-signed, incomplete chain,
        // ...), the certificate inspection must contribute an actual finding - silence about a
        // served identity is never acceptable for this battery.
        Assert.Contains(summary.Findings, f => f.CheckId == CertificateTrustCheck.CheckIdentifier);

        Assert.True(summary.ChecksExecuted > 0);
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
