using ACT.Cli;
using ACT.Contracts;
using ACT.Persistence;
using ACT.Reporting;

namespace ACT.Tests;

/// <summary>
/// The check execution ledger surface end to end: every outcome the engine records (completed,
/// skipped, failed closed, timed out) reads back exactly as stored, verification counts derive
/// from those rows only - zeros when nothing ran, never fabricated numbers - registered checks
/// with no recorded execution stay visible, and generated reports carry the same honest counts.
/// </summary>
public class CoverageSurfaceTests
{
    // ---------- persistence round trip ----------

    [Fact]
    public async Task ListCheckRuns_MapsEveryOutcomeFiltersByAssessmentAndHonorsLimit()
    {
        var fixture = await PersistFixture.CreateAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var first = await CreatePairedAsync(db);
            var second = await CreatePairedAsync(db);

            var statuses = new[]
            {
                CheckExecutionStatus.Completed,
                CheckExecutionStatus.CompletedWithWarnings,
                CheckExecutionStatus.Skipped_NotApplicable,
                CheckExecutionStatus.Skipped_PolicyDenied,
                CheckExecutionStatus.Skipped_OutOfScope,
                CheckExecutionStatus.Failed_FailedClosed,
                CheckExecutionStatus.TimedOut
            };
            for (var i = 0; i < statuses.Length; i++)
            {
                await db.RecordCheckRunAsync(
                    Run(CheckId.From("CHK-" + i), statuses[i],
                        started: DateTimeOffset.UtcNow.AddMinutes(-30 + i),
                        requests: i * 3, targets: i, note: i % 2 == 0 ? "contained safely" : null),
                    first.AssessmentId);
            }

            await db.RecordCheckRunAsync(
                Run(CheckId.From("CHK-OTHER"), CheckExecutionStatus.Completed,
                    DateTimeOffset.UtcNow, 1, 1), second.AssessmentId);

            var rows = await db.ListCheckRunsAsync(first.AssessmentId, 100);
            Assert.Equal(statuses.Length, rows.Count);
            Assert.All(rows, r => Assert.Equal(first.AssessmentId, r.AssessmentId));
            // Newest execution first.
            Assert.Equal(CheckExecutionStatus.TimedOut, rows[0].Status);
            Assert.True(rows[0].StartedUtc >= rows[^1].StartedUtc);

            var byId = rows.ToDictionary(static r => r.CheckId, static r => r);
            var timedOut = byId["CHK-6"];
            Assert.Equal(18, timedOut.RequestCount);
            Assert.Equal(6, timedOut.TargetsExamined);
            Assert.Null(byId["CHK-1"].FailureSummarySafe);
            Assert.Equal("contained safely", byId["CHK-6"].FailureSummarySafe);

            var everything = await db.ListCheckRunsAsync(null, 100);
            Assert.Equal(statuses.Length + 1, everything.Count);

            var limited = await db.ListCheckRunsAsync(null, 3);
            Assert.Equal(3, limited.Count);
        }
    }

    // ---------- honest coverage math ----------

    [Fact]
    public void ComputeVerificationCoverage_MapsEveryLedgerOutcomeWithoutInventingCounts()
    {
        CheckRunRecord Row(string id, CheckExecutionStatus status) => new(
            Guid.NewGuid(), Guid.NewGuid(), id, status,
            DateTimeOffset.UtcNow.AddSeconds(-5), DateTimeOffset.UtcNow, null, 1, 1);

        var runs = new[]
        {
            Row("a", CheckExecutionStatus.Completed),
            Row("b", CheckExecutionStatus.Completed),
            Row("c", CheckExecutionStatus.CompletedWithWarnings),
            Row("d", CheckExecutionStatus.Skipped_NotApplicable),
            Row("e", CheckExecutionStatus.Skipped_OutOfScope),
            Row("f", CheckExecutionStatus.Skipped_PolicyDenied),
            Row("g", CheckExecutionStatus.TimedOut),
            Row("h", CheckExecutionStatus.Failed_FailedClosed)
        };

        var findings = new List<Finding>
        {
            MakeFinding("confirmed-high-confidence", status: FindingStatus.Confirmed),
            MakeFinding("open-low-confidence") with
            {
                Confidence = ConfidenceLevel.Low,
                ConfidenceScore = 0.2
            },
            MakeFinding("open-high-confidence")
        };

        var coverage = CoverageOperations.ComputeVerificationCoverage(runs, findings);
        Assert.Equal(3, coverage.Tested);          // completed + warnings actually examined targets
        Assert.Equal(3, coverage.NotTested);       // all three skip classes examined nothing
        Assert.Equal(1, coverage.Inaccessible);    // timeout waiting on the target
        Assert.Equal(1, coverage.Inconclusive);    // fail-closed containment yields no verdict
        Assert.Equal(1, coverage.Confirmed);
        Assert.Equal(1, coverage.Inferred);        // exactly the sub-High-confidence finding

        var empty = CoverageOperations.ComputeVerificationCoverage([], []);
        Assert.Equal(new VerificationCoverage(0, 0, 0, 0, 0, 0), empty);
    }

    [Fact]
    public void Summarize_AggregatesRequestsTargetsAndOutcomeCounts()
    {
        CheckRunRecord Row(long requests, int targets) => new(
            Guid.NewGuid(), Guid.NewGuid(), "chk", CheckExecutionStatus.Completed,
            DateTimeOffset.UtcNow.AddSeconds(-5), DateTimeOffset.UtcNow, null, requests, targets);

        var summary = CoverageOperations.Summarize([Row(4, 2), Row(7, 3), Row(1, 1)]);
        Assert.Equal(3, summary.TotalRuns);
        Assert.Equal(3, summary.Executed);
        Assert.Equal(12, summary.RequestsSent);
        Assert.Equal(6, summary.TargetsExamined);
    }

    // ---------- catalog join ----------

    [Fact]
    public void UnexecutedCatalogChecks_ListsOnlyCatalogIdsAbsentFromTheLedger()
    {
        var executedId = "ACT-WEB-HSTS-001";
        var catalog = new List<SecurityCheckMetadata>
        {
            Meta(executedId),
            Meta("ACT-WEB-CSP-001"),
            Meta("ACT-SRC-RULES-001")
        };
        var runs = new[]
        {
            new CheckRunRecord(Guid.NewGuid(), Guid.NewGuid(), executedId,
                CheckExecutionStatus.Completed, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, null, 1, 1),
            // An id that is not in today's catalog must not resurrect anything or crash the join.
            new CheckRunRecord(Guid.NewGuid(), Guid.NewGuid(), "ACT-RETIRED-001",
                CheckExecutionStatus.Completed, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, null, 1, 1)
        };

        var unexecuted = CoverageOperations.UnexecutedCatalogChecks(catalog, runs);
        Assert.Equal(["ACT-SRC-RULES-001", "ACT-WEB-CSP-001"],
            unexecuted.Select(static m => m.Id.Value).ToArray());
    }

    // ---------- shared snapshot ----------

    [Fact]
    public async Task Build_FailsClosedOnUnknownAssessmentAndAggregatesRealRows()
    {
        var fixture = await PersistFixture.CreateAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            await Assert.ThrowsAsync<ActException>(() =>
                CoverageOperations.BuildAsync(db, Guid.NewGuid()));

            var assessment = await CreatePairedAsync(db);
            var catalogCount = CheckRegistry.Catalog().Count;
            Assert.True(catalogCount > 1, "catalog should list several built-in checks");

            var firstId = CheckRegistry.Catalog()[0].Id.Value;
            var now = DateTimeOffset.UtcNow;
            await db.RecordCheckRunAsync(Run(CheckId.From(firstId), CheckExecutionStatus.Completed,
                now.AddMinutes(-2), 9, 2), assessment.AssessmentId);
            await db.RecordCheckRunAsync(Run(CheckId.From("ACT-RETIRED-002"),
                CheckExecutionStatus.Failed_FailedClosed, now.AddMinutes(-1), 3, 1, "refused"), assessment.AssessmentId);

            var snapshot = await CoverageOperations.BuildAsync(db, assessment.AssessmentId);
            Assert.Equal(2, snapshot.Summary.TotalRuns);
            Assert.Equal(1, snapshot.Summary.Executed);
            Assert.Equal(1, snapshot.Summary.FailedClosed);
            Assert.Equal(12, snapshot.Summary.RequestsSent);
            Assert.Equal(3, snapshot.Summary.TargetsExamined);
            Assert.Equal(1, snapshot.Coverage.Tested);
            Assert.Equal(1, snapshot.Coverage.Inconclusive);
            Assert.Equal(catalogCount - 1, snapshot.NeverExecuted.Count);
            Assert.DoesNotContain(snapshot.NeverExecuted, m => m.Id.Value == firstId);

            var line = CoverageOperations.VerificationCountsLine(snapshot.Coverage);
            Assert.Contains("tested 1", line, StringComparison.Ordinal);
            Assert.Contains("inconclusive 1", line, StringComparison.Ordinal);
        }
    }

    // ---------- reports inherit the same honesty ----------

    [Fact]
    public async Task Generate_ReportsCarryCoverageDerivedFromTheCheckLedger()
    {
        var fixture = await PersistFixture.CreateAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessment = await CreatePairedAsync(db);
            await db.UpsertFindingAsync(MakeFinding("ledger-reported", assessmentId: assessment.AssessmentId));

            var now = DateTimeOffset.UtcNow;
            await db.RecordCheckRunAsync(Run(CheckId.From("chk-a"), CheckExecutionStatus.Completed, now.AddMinutes(-4), 5, 1), assessment.AssessmentId);
            await db.RecordCheckRunAsync(Run(CheckId.From("chk-b"), CheckExecutionStatus.CompletedWithWarnings, now.AddMinutes(-3), 2, 1), assessment.AssessmentId);
            await db.RecordCheckRunAsync(Run(CheckId.From("chk-c"), CheckExecutionStatus.Skipped_OutOfScope, now.AddMinutes(-2), 0, 0), assessment.AssessmentId);
            await db.RecordCheckRunAsync(Run(CheckId.From("chk-d"), CheckExecutionStatus.TimedOut, now.AddMinutes(-1), 4, 1), assessment.AssessmentId);
            await db.RecordCheckRunAsync(Run(CheckId.From("chk-e"), CheckExecutionStatus.Failed_FailedClosed, now, 1, 1), assessment.AssessmentId);

            var json = (await ReportOperations.GenerateAsync(
                db, assessment.AssessmentId, ReportFormat.Json, "tester", CorrelationId.New())).Content;
            using var document = System.Text.Json.JsonDocument.Parse(json);
            var coverage = document.RootElement.GetProperty("coverage");
            Assert.Equal(2, coverage.GetProperty("tested").GetInt32());
            Assert.Equal(1, coverage.GetProperty("notTested").GetInt32());
            Assert.Equal(1, coverage.GetProperty("inaccessible").GetInt32());
            Assert.Equal(1, coverage.GetProperty("inconclusive").GetInt32());

            var markdown = (await ReportOperations.GenerateAsync(
                db, assessment.AssessmentId, ReportFormat.Markdown, "tester", CorrelationId.New())).Content;
            Assert.Contains("Coverage counts: tested 2, not tested 1, inaccessible 1, inconclusive 1",
                markdown, StringComparison.Ordinal);
        }
    }

    // ---------- helpers ----------

    private static SecurityCheckResult Run(
        CheckId id, CheckExecutionStatus status, DateTimeOffset started, long requests, int targets, string? note = null) =>
        new(id, status, started, started.AddSeconds(2), [], [], note, requests, targets);

    private static SecurityCheckMetadata Meta(string id) => new(
        CheckId.From(id), "name " + id, "1.0", CheckCategory.Http, Severity.Medium,
        SafetyLevel.SafeRequestOnly, PermissionRequirement.None,
        new HashSet<ProtocolKind>(), new HashSet<TargetTypeKind>(),
        new NetworkBehaviorProfile(0, 1, false, false, false), [], true, false, "d");

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
        with { Status = status };

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
        "coverage-assessment",
        AssessmentRunState.Completed,
        DateTimeOffset.UtcNow,
        DateTimeOffset.UtcNow.AddMinutes(-5),
        DateTimeOffset.UtcNow,
        "unit-test-operator",
        "unit-test-org");

    /// <summary>Seeds one assessment together with its scope copy exactly like a real run.</summary>
    private static async Task<AssessmentRecord> CreatePairedAsync(ActDatabase db)
    {
        var assessment = MakeAssessment();
        var scope = MakeScope(assessment.ScopeId, assessment.AssessmentId);
        await db.CreateAssessmentAsync(assessment, scope);
        await db.SetConfigAsync("scope:" + assessment.AssessmentId.ToString("N"), scope);
        return assessment;
    }
}
