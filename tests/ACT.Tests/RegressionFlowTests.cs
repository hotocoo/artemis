using ACT.Cli;
using ACT.Contracts;
using ACT.Core;
using ACT.Persistence;
using Xunit;

namespace ACT.Tests;

/// <summary>
/// End-to-end unit coverage for the stored regression lifecycle: capture from fixture-backed
/// findings into durable upserted rows, refusal to store non-executable recipes, verdict
/// recording that advances the cadence, and audited enable/disable decisions.
/// </summary>
public sealed class RegressionFlowTests
{
    private static Uri BaseUrl { get; } = new("http://127.0.0.1:8080");

    private static async Task<PersistFixture> CreateDatabaseAsync() => await PersistFixture.CreateAsync();

    private static async Task<AssessmentRecord> CreatePairedAsync(ActDatabase db)
    {
        var assessmentId = Guid.NewGuid();
        var scopeId = Guid.NewGuid();
        var scope = new ScopeDefinition(
            scopeId, assessmentId, "unit-test-operator", "unit-test-org", TargetTypeKind.Localhost,
            ["localhost"], [], [ProtocolKind.Https], [PortRange.Single(8443)],
            5, 2, TimeSpan.FromMinutes(30), 500, Enum.GetValues<CheckCategory>(), [], true,
            TimeSpan.FromDays(30), RedactionPolicy.Standard, "I am authorized to assess these targets.");
        var assessment = new AssessmentRecord(
            assessmentId, scopeId, "assessment", AssessmentRunState.Completed,
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow,
            "unit-test-operator", "unit-test-org");
        await db.CreateAssessmentAsync(assessment, scope);
        return assessment;
    }

    private static Finding MakeFinding(Guid assessmentId, CheckCategory category, string classification)
    {
        var checkId = CheckId.From("CHK-TST");
        return FindingFactory.Create(
            assessmentId, checkId, "svc.local:8443", category,
            "Title " + classification, "Description " + classification, Severity.High,
            ConfidenceLevel.High, exploitabilityIndicator: false, BusinessImpactLevel.Severe,
            "why it matters", "technical explanation",
            new RemediationGuidance("Fix it.", ["step-one"], ["ref-one"]),
            new FingerprintComponents(checkId, "target.local", "resource", classification))
            with
        { PriorityScore = 90 };
    }

    private static AuthorizationFixtureSet CrossTenantFixtures() => new(
        [
            new TestPrincipal("alice", "tenant-a", "member", new Dictionary<string, string> { ["X-Auth-User"] = "alice" }),
            new TestPrincipal("mallory", "tenant-b", "member", new Dictionary<string, string> { ["X-Auth-User"] = "mallory" }),
        ],
        [new ObjectFixture("obj-1", "tenant-a", "/api/objects/{id}")],
        []);

    [Fact]
    public async Task Capture_StoresOneExecutableTestPerAuthorizationFinding_AndUpsertsOnRepeat()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessment = await CreatePairedAsync(db);
            var authzOne = MakeFinding(assessment.AssessmentId, CheckCategory.Authorization, "cross-tenant-read");
            var authzTwo = MakeFinding(assessment.AssessmentId, CheckCategory.Authorization, "privilege-escalation");
            var plainTls = MakeFinding(assessment.AssessmentId, CheckCategory.Tls, "weak-cipher");
            foreach (var finding in new[] { authzOne, authzTwo, plainTls })
            {
                await db.UpsertFindingAsync(finding);
            }

            var stored = await RegressionOperations.CaptureForFindingsAsync(
                db, assessment.AssessmentId, new[] { authzOne, authzTwo, plainTls },
                CrossTenantFixtures(), BaseUrl, "tester", CorrelationId.New());

            Assert.Equal(2, stored.Count); // only fixture-backed executable regressions exist
            Assert.All(stored, t => Assert.NotNull(t.RecipeJson));
            Assert.All(stored, t => Assert.True(t.Enabled));

            // Pausing a test is an operator decision a later capture must not silently undo.
            var paused = stored[0];
            await RegressionOperations.SetEnabledAsync(db, paused.RegressionTestId, false, "tester", CorrelationId.New());

            var recaptured = await RegressionOperations.CaptureForFindingsAsync(
                db, assessment.AssessmentId, new[] { authzOne, authzTwo },
                CrossTenantFixtures(), BaseUrl, "tester", CorrelationId.New());

            Assert.Equal(2, recaptured.Count);
            Assert.Equal(stored.Select(t => t.RegressionTestId).OrderBy(g => g),
                         recaptured.Select(t => t.RegressionTestId).OrderBy(g => g)); // upsert, no duplicates
            var refreshedPaused = recaptured.Single(t => t.RegressionTestId == paused.RegressionTestId);
            Assert.False(refreshedPaused.Enabled);
            Assert.NotEqual(paused.RecipeJson, refreshedPaused.RecipeJson); // recipe refreshed

            var audit = await db.ReadRecentAuditAsync(50);
            Assert.Contains(audit, e => e.Action == "regression.test_created");
            Assert.Contains(audit, e => e.Action == "regression.test_updated");
            Assert.Contains(audit, e => e.Action == "regression.test_disabled");
        }
    }

    [Fact]
    public async Task Capture_WithoutFixturesOrBaseUrl_ProducesNothingHonestly()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessment = await CreatePairedAsync(db);
            var finding = MakeFinding(assessment.AssessmentId, CheckCategory.Authorization, "cross-tenant-read");

            Assert.Empty(await RegressionOperations.CaptureForFindingsAsync(
                db, assessment.AssessmentId, [finding], AuthorizationFixtureSet.None, BaseUrl, "t", CorrelationId.New()));
            Assert.Empty(await RegressionOperations.CaptureForFindingsAsync(
                db, assessment.AssessmentId, [finding], CrossTenantFixtures(), null, "t", CorrelationId.New()));
            Assert.Empty(await db.ListRegressionTestsAsync(100));
        }
    }

    [Fact]
    public async Task StoreForFinding_RefusesNonExecutableTemplate_FailClosed()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessment = await CreatePairedAsync(db);
            var tlsFinding = MakeFinding(assessment.AssessmentId, CheckCategory.Tls, "weak-cipher");

            // Without fixtures the generator can only offer a replay-check placeholder - storing
            // it would promise executability the runner does not have.
            var generated = RegressionGenerator.TryGenerate(tlsFinding, AuthorizationFixtureSet.None, BaseUrl);
            Assert.NotNull(generated);
            Assert.Null(generated.HttpExpectation);

            await Assert.ThrowsAsync<ActException>(() => RegressionOperations.StoreForFindingAsync(
                db, assessment.AssessmentId, tlsFinding, generated, "tester", CorrelationId.New()));
        }
    }

    [Fact]
    public async Task RecordRunOutcome_AdvancesCadence_AndAuditsPassAndFail()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessment = await CreatePairedAsync(db);
            var finding = MakeFinding(assessment.AssessmentId, CheckCategory.Authorization, "cross-tenant-read");
            await db.UpsertFindingAsync(finding);

            var generated = RegressionGenerator.TryGenerate(finding, CrossTenantFixtures(), BaseUrl)!;
            var test = await RegressionOperations.StoreForFindingAsync(
                db, assessment.AssessmentId, finding, generated, "tester", CorrelationId.New(),
                TimeSpan.FromDays(7));

            var passResult = new RegressionRunResult(
                generated.RegressionTestId, finding.FindingId, Passed: true,
                "Status 403 within expected 400..404.", DateTimeOffset.UtcNow);
            var passRun = await RegressionOperations.RecordRunOutcomeAsync(db, test, passResult, "tester", CorrelationId.New());
            Assert.Equal(VerificationState.Tested, passRun.Result);

            var failResult = new RegressionRunResult(
                generated.RegressionTestId, finding.FindingId, Passed: false,
                "Status 200 OUTSIDE expected 400..404: invariant violated.", DateTimeOffset.UtcNow.AddHours(1));
            var failRun = await RegressionOperations.RecordRunOutcomeAsync(db, test, failResult, "tester", CorrelationId.New());
            Assert.Equal(VerificationState.Confirmed, failRun.Result); // the issue came back

            var afterRuns = await db.GetRegressionTestAsync(test.RegressionTestId);
            Assert.NotNull(afterRuns);
            Assert.Equal(failResult.RanUtc.AddDays(7), afterRuns.NextRunUtc); // schedule advanced from last verdict

            var runs = await db.ListTestRunsAsync(test.RegressionTestId, 10);
            Assert.Equal(2, runs.Count);
            Assert.Equal(VerificationState.Confirmed, runs[0].Result); // newest first

            var audit = await db.ReadRecentAuditAsync(20);
            Assert.Contains(audit, e => e.Action == "regression.run_recorded" && e.Result.StartsWith("PASS"));
            Assert.Contains(audit, e => e.Action == "regression.run_recorded" && e.Result.StartsWith("FAIL"));
        }
    }

    [Fact]
    public async Task SetEnabled_FailsClosedOnUnknownTest()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            await Assert.ThrowsAsync<ActException>(() => RegressionOperations.SetEnabledAsync(
                db, Guid.NewGuid(), enabled: true, "tester", CorrelationId.New()));
        }
    }
}
