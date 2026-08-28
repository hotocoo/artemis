using ACT.Cli;
using ACT.Contracts;
using ACT.Persistence;
using Microsoft.Data.Sqlite;
using Xunit;

namespace ACT.Tests;

/// <summary>
/// Wave 1 gap fixes: the launch path must persist every asset and service observation it
/// records (the asset inventory is unreachable otherwise), and finding identifiers must be
/// resolvable from exactly what `artemis finding list` prints.
/// </summary>
public sealed class CliLedgerAndFindingTests
{
    [Fact]
    public async Task PersistingLedger_RecordsAssetsIntoTheDatabase()
    {
        await using var fixture = await PersistFixture.CreateAsync();
        var assessment = await CreatePairedAsync(fixture.Database);
        var ledger = new PersistingAssessmentLedger(fixture.Database);
        var asset = MakeAsset(assessment.AssessmentId, "http://127.0.0.1:47391");

        var returned = await ledger.RecordAssetAsync(asset, CancellationToken.None);

        Assert.Equal(asset.AssetId, returned.AssetId);
        var stored = await fixture.Database.ListAssetsAsync(assessment.AssessmentId, 500);
        Assert.Single(stored);
        Assert.Equal(asset.CanonicalTarget, stored[0].CanonicalTarget);
    }

    [Fact]
    public async Task PersistingLedger_ReRecordingResolvesTheStoredAssetRow()
    {
        await using var fixture = await PersistFixture.CreateAsync();
        var assessment = await CreatePairedAsync(fixture.Database);
        var ledger = new PersistingAssessmentLedger(fixture.Database);
        var first = await ledger.RecordAssetAsync(
            MakeAsset(assessment.AssessmentId, "http://127.0.0.1:47391"), CancellationToken.None);

        // A schedule tick re-runs the same assessment id and builds a fresh AssetRecord with a
        // new Guid. The ledger must hand back the stored row: service observations foreign-key
        // to it and INSERT OR IGNORE does not suppress foreign-key violations.
        var second = await ledger.RecordAssetAsync(
            MakeAsset(assessment.AssessmentId, "http://127.0.0.1:47391"), CancellationToken.None);

        Assert.Equal(first.AssetId, second.AssetId);
        var stored = await fixture.Database.ListAssetsAsync(assessment.AssessmentId, 500);
        Assert.Single(stored);

        var service = new ServiceObservation(
            Guid.NewGuid(), second.AssetId, 47391, ProtocolKind.Http, Banner: null,
            TlsNegotiated: false, DateTimeOffset.UtcNow, new CheckId("ACT-NET-DISCOVERY-001"));
        await ledger.RecordServiceAsync(service, CancellationToken.None);
        var services = await fixture.Database.ListServicesAsync(assessment.AssessmentId, 100);
        Assert.Single(services);
        Assert.Equal(first.AssetId, services[0].AssetId);
    }

    [Fact]
    public async Task PersistingLedger_ServiceDuplicatesStaySingle()
    {
        await using var fixture = await PersistFixture.CreateAsync();
        var assessment = await CreatePairedAsync(fixture.Database);
        var ledger = new PersistingAssessmentLedger(fixture.Database);
        var asset = await ledger.RecordAssetAsync(
            MakeAsset(assessment.AssessmentId, "http://127.0.0.1:47391"), CancellationToken.None);

        ServiceObservation Observation(int port, CheckId source) => new(
            Guid.NewGuid(), asset.AssetId, port, ProtocolKind.Http, Banner: null,
            TlsNegotiated: false, DateTimeOffset.UtcNow, source);
        await ledger.RecordServiceAsync(Observation(47391, new CheckId("ACT-NET-DISCOVERY-001")), CancellationToken.None);
        await ledger.RecordServiceAsync(Observation(47391, new CheckId("ACT-NET-DISCOVERY-001")), CancellationToken.None);
        await ledger.RecordServiceAsync(Observation(47392, new CheckId("ACT-TLS-CERT-001")), CancellationToken.None);

        Assert.Equal(2, ledger.ObservedServices().Count);
        var services = await fixture.Database.ListServicesAsync(assessment.AssessmentId, 100);
        Assert.Equal(2, services.Count);
    }

    [Fact]
    public void FindingIdentifier_GuidMatchesExactly()
    {
        var finding = MakeFinding("e8b7c3d2a1944567890abcdef1234567aabbccddeeff00112233445566778899");
        var other = MakeFinding("1111111111114567890abcdef1234567aabbccddeeff00112233445566778899");

        var (resolved, _) = FindingCommands.FindingIdentifier.Resolve([finding, other], finding.FindingId.ToString());

        Assert.Same(finding, resolved);
    }

    [Fact]
    public void FindingIdentifier_FullHashAndUniquePrefixResolve()
    {
        var finding = MakeFinding("e8b7c3d2a1944567890abcdef1234567aabbccddeeff00112233445566778899");
        var other = MakeFinding("7777c3d2a1944567890abcdef1234567aabbccddeeff00112233445566778899");

        var (byHash, _) = FindingCommands.FindingIdentifier.Resolve([finding, other], finding.Fingerprint.Hash);
        var (byPrefix, _) = FindingCommands.FindingIdentifier.Resolve([finding, other], finding.Fingerprint.Hash[..12]);

        Assert.Same(finding, byHash);
        Assert.Same(finding, byPrefix);
    }

    [Fact]
    public void FindingIdentifier_AmbiguousPrefixIsItsOwnOutcome()
    {
        var first = MakeFinding("aaaac3d2a1944567890abcdef1234567aabbccddeeff00112233445566778899");
        var second = MakeFinding("aaaac3d2a1944567890abcdef1234568aabbccddeeff00112233445566778899");

        var (resolved, prefixMatches) = FindingCommands.FindingIdentifier.Resolve([first, second], "aaaa");

        Assert.Null(resolved);
        Assert.Equal(2, prefixMatches);
    }

    [Fact]
    public void FindingIdentifier_UnknownIdentifierResolvesToNothing()
    {
        var finding = MakeFinding("e8b7c3d2a1944567890abcdef1234567aabbccddeeff00112233445566778899");

        var (resolved, prefixMatches) = FindingCommands.FindingIdentifier.Resolve([finding], "beef");

        Assert.Null(resolved);
        Assert.Equal(0, prefixMatches);
    }

    private static AssetRecord MakeAsset(Guid assessmentId, string canonicalTarget) => new(
        Guid.NewGuid(), assessmentId, AssetKind.Url, "127.0.0.1", canonicalTarget,
        [], DateTimeOffset.UtcNow, WithinScope: true);

    private static Finding MakeFinding(string fingerprintHash) => new(
        Guid.NewGuid(), Guid.NewGuid(), new CheckId("ACT-WEB-HSTS-001"), "http://target", null,
        CheckCategory.Http, "title", "description", Severity.Medium, ConfidenceLevel.Medium, 0.5,
        ExploitabilityIndicator: false, BusinessImpactLevel.Limited, "why", "explanation",
        new RemediationGuidance("summary", [], []), DateTimeOffset.UtcNow, DateTimeOffset.UtcNow,
        FindingStatus.New, new FindingFingerprint(fingerprintHash), RegressionTestId: null,
        CvssVector: null, CvssBaseScore: null);

    private static async Task<AssessmentRecord> CreatePairedAsync(ActDatabase db)
    {
        var assessmentId = Guid.NewGuid();
        var scopeId = Guid.NewGuid();
        var assessment = new AssessmentRecord(
            assessmentId, scopeId, "cli-ledger-assessment", AssessmentRunState.Completed,
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow,
            "unit-test-operator", "unit-test-org");
        var scope = new ScopeDefinition(
            scopeId, assessmentId, "unit-test-operator", "unit-test-org", TargetTypeKind.Localhost,
            ["localhost"], [], [ProtocolKind.Http], [PortRange.Single(47391)], 5, 2,
            TimeSpan.FromMinutes(30), 500, Enum.GetValues<CheckCategory>(), [],
            EmergencyStopEnabled: true, EvidenceRetentionPeriod: TimeSpan.FromDays(30),
            DataRedactionPolicy: RedactionPolicy.Standard,
            AuthorizationStatement: "unit test authorization");
        await db.CreateAssessmentAsync(assessment, scope);
        return assessment;
    }
}
