using ACT.Cli;
using ACT.Contracts;
using ACT.Persistence;
using ACT.Reporting;
using Xunit;

namespace ACT.Tests;

/// <summary>
/// Security baselines end to end: finding-level drift analysis, baseline persistence reads, and
/// the shared create/compare operations including their audited fail-closed edges.
/// </summary>
public class BaselineTests
{
    // ---------- analyzer ----------

    private static Finding MakeFinding(
        string classification,
        Severity severity = Severity.High,
        FindingStatus status = FindingStatus.New,
        Guid? assessmentId = null) =>
        FindingFactory.Create(
            assessmentId ?? Guid.NewGuid(),
            CheckId.From("CHK-TST"),
            "svc.local:8443",
            CheckCategory.Tls,
            "Title " + classification,
            "Description " + classification,
            severity,
            ConfidenceLevel.High,
            exploitabilityIndicator: false,
            BusinessImpactLevel.Limited,
            "why it matters",
            "technical explanation",
            new RemediationGuidance("Fix it.", ["step-one"], []),
            new FingerprintComponents(CheckId.From("CHK-TST"), "target.local", "resource", classification))
        with
        { Status = status };

    private static SecurityBaseline MakeBaseline(params string[] accepted) => new(
        Guid.NewGuid(),
        Guid.NewGuid(),
        "unit baseline",
        [],
        accepted,
        DateTimeOffset.UtcNow);

    [Fact]
    public void Drift_NewFindingReportedAtItsOwnSeverity()
    {
        var finding = MakeFinding("open-admin-panel", Severity.Critical);
        var observations = DriftAnalyzer.CompareFindings(MakeBaseline(), [finding]);

        var observation = Assert.Single(observations);
        Assert.Equal(DriftAnalyzer.NewFinding, observation.Kind);
        Assert.Equal(Severity.Critical, observation.SuggestedSeverity);
        Assert.Contains(finding.Fingerprint.Hash[..16], observation.Detail);
        // The suffix is an opaque correlation token derived from baseline+kind+fingerprint.
        Assert.Matches("^[0-9a-f]{16}$", observation.FingerprintSuffix);
    }

    [Fact]
    public void Drift_TriagedAcceptanceSuppressesNoiseButFlagsAbsenceHonestly()
    {
        var acceptedFinding = MakeFinding("accepted-risk-item");
        var baseline = MakeBaseline(acceptedFinding.Fingerprint.Hash);

        // Re-observation of an explicitly dispositioned finding is the steady state, not drift.
        Assert.Empty(DriftAnalyzer.CompareFindings(baseline, [acceptedFinding]));

        // Its disappearance is reported - but never dressed up as a confirmed fix.
        var observations = DriftAnalyzer.CompareFindings(baseline, []);
        var observation = Assert.Single(observations);
        Assert.Equal(DriftAnalyzer.ResolvedFinding, observation.Kind);
        Assert.Equal(Severity.Informational, observation.SuggestedSeverity);
        Assert.Contains("Confirm the relevant checks actually ran", observation.Detail);
    }

    [Fact]
    public void Drift_ReobservedRemediatedFindingIsRegressed()
    {
        var regressed = MakeFinding("regressed-issue", Severity.Medium, FindingStatus.Regressed);
        var observations = DriftAnalyzer.CompareFindings(MakeBaseline(), [regressed]);

        var observation = Assert.Single(observations);
        Assert.Equal(DriftAnalyzer.RegressedFinding, observation.Kind);
        Assert.Equal(Severity.Medium, observation.SuggestedSeverity);
        Assert.Contains("detected again", observation.Detail);
    }

    [Fact]
    public void Drift_OutputOrderIsDeterministic()
    {
        var baseline = MakeBaseline("absent-fingerprint");
        var low = MakeFinding("alpha-low", Severity.Low);
        var high = MakeFinding("zulu-high", Severity.Critical);
        var observations = DriftAnalyzer.CompareFindings(baseline, [high, low, high]);

        Assert.Equal(3, observations.Count);
        Assert.Equal([DriftAnalyzer.NewFinding, DriftAnalyzer.NewFinding, DriftAnalyzer.ResolvedFinding],
            observations.Select(static o => o.Kind));
        Assert.Equal(observations.OrderBy(static o => o.Kind, StringComparer.Ordinal)
            .ThenBy(static o => o.Detail, StringComparer.Ordinal), observations);
    }

    [Fact]
    public void Drift_ServiceComparisonStillDetectsProhibitedAndMissing()
    {
        var baseline = MakeBaseline() with
        {
            ExpectedServices =
            [
                new ServiceBaselineEntry(443, ProtocolKind.Https, BaselineServiceStatus.Expected),
                new ServiceBaselineEntry(9000, ProtocolKind.Http, BaselineServiceStatus.Prohibited)
            ]
        };
        var observations = DriftAnalyzer.Compare(baseline,
        [
            new ServiceObservation(Guid.NewGuid(), Guid.NewGuid(), 9000, ProtocolKind.Http, "banner", false,
                DateTimeOffset.UtcNow, CheckId.From("CHK-NET"))
        ]);

        Assert.Equal(
            [DriftAnalyzer.ExpectedServiceAbsent, DriftAnalyzer.UnexpectedServiceExposed],
            observations.Select(static o => o.Kind));
    }

    // ---------- persistence ----------

    [Fact]
    public async Task Persist_BaselinesRoundTripThroughLatestByIdAndList()
    {
        var fixture = await PersistFixture.CreateAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var scopeId = Guid.NewGuid();
            var older = new SecurityBaseline(Guid.NewGuid(), scopeId, "older", [], [], DateTimeOffset.UtcNow.AddHours(-1));
            var newer = new SecurityBaseline(Guid.NewGuid(), scopeId, "newer",
                [new ServiceBaselineEntry(443, ProtocolKind.Https, BaselineServiceStatus.Expected)],
                ["abc"], DateTimeOffset.UtcNow);
            await db.SaveBaselineAsync(older);
            await db.SaveBaselineAsync(newer);

            var latest = await db.GetLatestBaselineAsync(scopeId);
            Assert.Equal(newer.BaselineId, latest!.BaselineId);

            var byId = await db.GetBaselineAsync(scopeId, older.BaselineId);
            Assert.Equal("older", byId!.Name);
            Assert.Null(await db.GetBaselineAsync(scopeId, Guid.NewGuid()));

            var listed = await db.ListBaselinesAsync(scopeId);
            Assert.Equal(["older", "newer"], listed.Select(static b => b.Name));

            // A different scope never sees another scope's baselines.
            Assert.Empty(await db.ListBaselinesAsync(Guid.NewGuid()));
            Assert.Null(await db.GetLatestBaselineAsync(Guid.NewGuid()));
        }
    }

    // ---------- shared operations ----------

    private static AssetRecord MakeAsset(AssessmentRecord assessment) => new(
        Guid.NewGuid(), assessment.AssessmentId, AssetKind.Host, "web host", "localhost",
        ["127.0.0.1"], DateTimeOffset.UtcNow, WithinScope: true);

    [Fact]
    public async Task Operations_CreateAcceptsOnlyTriagedFingerprintsAndAudits()
    {
        var fixture = await PersistFixture.CreateAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessment = await CreatePairedAsync(db);

            var open = await Upserted(db, MakeFinding("still-open", assessmentId: assessment.AssessmentId));
            var riskAccepted = await Upserted(db, MakeFinding("risk-accepted", assessmentId: assessment.AssessmentId));
            var falsePositive = await Upserted(db, MakeFinding("false-positive", assessmentId: assessment.AssessmentId));
            await db.TriageFindingAsync(riskAccepted.FindingId, FindingStatus.AcceptedRisk, "tester", "risk sign-off", CorrelationId.New());
            await db.TriageFindingAsync(falsePositive.FindingId, FindingStatus.FalsePositive, "tester", "test data", CorrelationId.New());

            var asset = MakeAsset(assessment);
            await db.AddAssetAsync(asset);
            await db.AddServiceAsync(new ServiceObservation(
                Guid.NewGuid(), asset.AssetId, 8443, ProtocolKind.Https, "banner", true,
                DateTimeOffset.UtcNow, CheckId.From("CHK-NET")));

            var baseline = await BaselineOperations.CreateAsync(db, assessment, "nightly", "tester", CorrelationId.New());
            Assert.Equal(assessment.ScopeId, baseline.ScopeId);
            Assert.Single(baseline.ExpectedServices);
            string[] expectedAccepted = [riskAccepted.Fingerprint.Hash, falsePositive.Fingerprint.Hash];
            Assert.Equal(
                expectedAccepted.OrderBy(static h => h, StringComparer.Ordinal),
                baseline.AcceptedFindingFingerprints);
            Assert.DoesNotContain(open.Fingerprint.Hash, baseline.AcceptedFindingFingerprints);

            var events = await db.ReadRecentAuditAsync(5);
            Assert.Contains(events, static e => e.Action == "baseline.created" && e.Actor == "tester");
            Assert.True(await db.VerifyChainAsync());
        }
    }

    [Fact]
    public async Task Operations_CompareMixesServiceAndFindingDriftThenAudits()
    {
        var fixture = await PersistFixture.CreateAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessment = await CreatePairedAsync(db);

            var asset = MakeAsset(assessment);
            await db.AddAssetAsync(asset);
            await db.AddServiceAsync(new ServiceObservation(
                Guid.NewGuid(), asset.AssetId, 9000, ProtocolKind.Http, "surprise", false,
                DateTimeOffset.UtcNow, CheckId.From("CHK-NET")));
            await Upserted(db, MakeFinding("brand-new", assessmentId: assessment.AssessmentId));

            var baseline = await BaselineOperations.CreateAsync(db, assessment, "before", "tester", CorrelationId.New())
                ?? throw new InvalidOperationException("baseline creation failed");
            // Widen the stored snapshot so the fresh run shows both drift classes at once.
            var widened = baseline with
            {
                ExpectedServices = [.. baseline.ExpectedServices, new ServiceBaselineEntry(443, ProtocolKind.Https, BaselineServiceStatus.Expected)]
            };
            await db.SaveBaselineAsync(widened);

            var comparison = await BaselineOperations.CompareAsync(db, assessment.AssessmentId, null, "tester", CorrelationId.New());
            Assert.Equal(widened.BaselineId, comparison.BaselineId);
            Assert.Contains(comparison.Observations, static o => o.Kind == DriftAnalyzer.NewFinding);
            Assert.Contains(comparison.Observations, static o => o.Kind == DriftAnalyzer.ExpectedServiceAbsent);
            Assert.DoesNotContain(comparison.Observations, static o => o.Kind == DriftAnalyzer.UnexpectedServiceExposed);

            var events = await db.ReadRecentAuditAsync(5);
            Assert.Contains(events, static e => e.Action == "baseline.compared");

            // An explicit baseline identifier resolves too; an unknown one fails closed.
            var explicitComparison = await BaselineOperations.CompareAsync(db, assessment.AssessmentId, widened.BaselineId, "tester", CorrelationId.New());
            Assert.Equal(widened.BaselineId, explicitComparison.BaselineId);
            await Assert.ThrowsAsync<ActException>(() =>
                BaselineOperations.CompareAsync(db, assessment.AssessmentId, Guid.NewGuid(), "tester", CorrelationId.New()));
        }
    }

    [Fact]
    public async Task Operations_CompareFailsClosedOnUnknownAssessmentOrMissingBaseline()
    {
        var fixture = await PersistFixture.CreateAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessment = await CreatePairedAsync(db);

            await Assert.ThrowsAsync<ActException>(() =>
                BaselineOperations.CompareAsync(db, Guid.NewGuid(), null, "tester", CorrelationId.New()));
            await Assert.ThrowsAsync<ActException>(() =>
                BaselineOperations.CompareAsync(db, assessment.AssessmentId, null, "tester", CorrelationId.New()));

            // Creation itself is command-layer validated; comparison fails closed here.
        }
    }

    private static async Task<Finding> Upserted(ActDatabase db, Finding finding) =>
        await db.UpsertFindingAsync(finding);

    private static ScopeDefinition MakeScope(Guid scopeId, Guid assessmentId) => new(
        ScopeId: scopeId,
        AssessmentId: assessmentId,
        OperatorIdentity: "unit-test-operator",
        Organization: "unit-test-org",
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
        EvidenceRetentionPeriod: TimeSpan.FromDays(30),
        DataRedactionPolicy: RedactionPolicy.Standard,
        AuthorizationStatement: "I am authorized to assess these targets.");

    private static AssessmentRecord MakeAssessment() => new(
        Guid.NewGuid(),
        Guid.NewGuid(),
        "baseline-assessment",
        AssessmentRunState.Completed,
        DateTimeOffset.UtcNow,
        DateTimeOffset.UtcNow.AddMinutes(-5),
        DateTimeOffset.UtcNow,
        "unit-test-operator",
        "unit-test-org");

    /// <summary>Creates one assessment together with its matching scope definition.</summary>
    private static async Task<AssessmentRecord> CreatePairedAsync(ActDatabase db)
    {
        var assessment = MakeAssessment();
        await db.CreateAssessmentAsync(assessment, MakeScope(assessment.ScopeId, assessment.AssessmentId));
        return assessment;
    }
}
