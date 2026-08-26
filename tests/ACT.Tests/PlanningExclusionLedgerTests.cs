using ACT.Cli;
using ACT.Contracts;
using ACT.Core;
using ACT.Persistence;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace ACT.Tests;

/// <summary>
/// The planning-exclusion ledger end to end at the unit tier: the engine persists WHY every
/// excluded check was kept out of the plan BEFORE any work runs, the store round-trips those
/// rows exactly as decided and fails closed on malformed ones, and every coverage surface
/// derives its "why did this never run" answer strictly from stored decisions - never guesses.
/// </summary>
public class PlanningExclusionLedgerTests
{
    // ---------- store round trip ----------

    [Fact]
    public async Task SavePlanExclusions_RoundTripsFiltersByAssessmentAndHonorsLimit()
    {
        var fixture = await PersistFixture.CreateAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            // Real parent rows first: the foreign key refuses orphans by design.
            var first = (await CreatePairedAsync(db)).AssessmentId;
            var second = (await CreatePairedAsync(db)).AssessmentId;
            var now = DateTimeOffset.UtcNow;

            await db.SavePlanExclusionsAsync(
            [
                Excl(first, "CHK-API-001", "CATEGORY_NOT_PERMITTED", "Category Api is not permitted by this scope.", now.AddSeconds(-3)),
                Excl(first, "CHK-API-001", "TARGET_TYPE_MISMATCH", "Check does not support asset kind Url.", now.AddSeconds(-2)),
                Excl(first, "CHK-TLS-001", "PROTOCOL_MISMATCH", "Check requires Https; target speaks Http.", now.AddSeconds(-1)),
                Excl(second, "CHK-SRC-001", "BUDGET_EXHAUSTED", "Remaining request budget could not cover this footprint.", now)
            ]);

            var onlyFirst = await db.ListPlanExclusionsAsync(first);
            Assert.Equal(3, onlyFirst.Count);
            Assert.All(onlyFirst, r => Assert.Equal(first, r.AssessmentId));
            // Newest decision first within the assessment.
            Assert.Equal("CHK-TLS-001", onlyFirst[0].CheckId);
            Assert.Equal("PROTOCOL_MISMATCH", onlyFirst[0].ReasonCode);

            var everything = await db.ListPlanExclusionsAsync(null);
            Assert.Equal(4, everything.Count);

            var limited = await db.ListPlanExclusionsAsync(first, 2);
            Assert.Equal(2, limited.Count);
        }
    }

    [Fact]
    public async Task SavePlanExclusions_FailsClosedOnEmptyBatchAndMalformedRows()
    {
        var fixture = await PersistFixture.CreateAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessmentId = Guid.NewGuid();

            await Assert.ThrowsAsync<ActException>(() =>
                db.SavePlanExclusionsAsync([]));

            await Assert.ThrowsAsync<ActException>(() =>
                db.SavePlanExclusionsAsync([Excl(assessmentId, "", "REASON", "detail", DateTimeOffset.UtcNow)]));

            await Assert.ThrowsAsync<ActException>(() =>
                db.SavePlanExclusionsAsync([Excl(assessmentId, "CHK-X", " ", "detail", DateTimeOffset.UtcNow)]));

            await Assert.ThrowsAsync<ActException>(() =>
                db.SavePlanExclusionsAsync([Excl(assessmentId, "CHK-X", "REASON", "", DateTimeOffset.UtcNow)]));

            // Nothing was written by any of the refused calls.
            Assert.Empty(await db.ListPlanExclusionsAsync(assessmentId));
        }
    }

    [Fact]
    public async Task Migrations_CreatePlanExclusionsTableWithRecordedV4Entry()
    {
        var fixture = await PersistFixture.CreateAsync();
        await using (fixture)
        {
            await fixture.Database.InitializeAsync();
            // The table exists and starts empty...
            Assert.Equal(0, await CountAsync(fixture, "SELECT COUNT(*) FROM plan_exclusions"));
            // ...and the shipped v4 migration is recorded under its frozen checksum.
            Assert.Equal(1, await CountAsync(fixture,
                "SELECT COUNT(*) FROM schema_migrations WHERE version = 4 AND name = 'plan-exclusions'"));
        }
    }

    // ---------- engine persists the plan's exclusions before any work ----------

    [Fact]
    public async Task Engine_PersistsEveryPlanningExclusionBeforeExecutingAnyWork()
    {
        var recorder = new CapturingRecorder();
        var sink = new CapturingAuditSink();
        var scope = MakeScope();

        // A gate that denies both checks deterministically: the plan will contain two
        // exclusions and zero executable work items.
        var gate = new DenyingGate("SCOPE_CATEGORY_NOT_PERMITTED", "The category policy excludes this check.");
        var engine = new AssessmentEngine(gate, recorder, sink, NullLogger.Instance);

        var summary = await engine.RunAsync(new AssessmentRunRequest(
            scope.AssessmentId, CorrelationId.New(), scope,
            ResourceBudget.FromScope(scope, EngineDefaults.Conservative),
            [FakeCheck("ACT-BENCH-A-001"), FakeCheck("ACT-BENCH-B-002")],
            [], PreexistingFindings: null, Scorer: null), CancellationToken.None);

        // The run itself proves the honesty invariant: nothing executed...
        Assert.Empty(summary.CheckResults);
        Assert.Equal(0, summary.ChecksExecuted);
        // ...yet every exclusion is a stored fact, not a log line.
        Assert.Equal(2, summary.Exclusions.Count);
        Assert.Equal(2, recorder.PlanExclusions.Count);
        Assert.All(recorder.PlanExclusions, e => Assert.Equal(scope.AssessmentId, e.AssessmentId));
        Assert.Equal(
            [.. summary.Exclusions.Select(e => (e.CheckId, e.ReasonCode)).OrderBy(x => x.CheckId, StringComparer.Ordinal)],
            [.. recorder.PlanExclusions.Select(e => (e.CheckId, e.ReasonCode)).OrderBy(x => x.CheckId, StringComparer.Ordinal)]);

        // And the decision is tamper-evident in the audit chain like every lifecycle event.
        Assert.Contains(sink.Drafts, d => d.Action == "plan.exclusions"
            && d.ObjectId == scope.AssessmentId.ToString()
            && d.Result.Contains("2 checks excluded", StringComparison.Ordinal));
    }

    [Fact]
    public async Task Engine_WithNoExclusions_PersistsNothingRatherThanAnEmptyBatch()
    {
        var recorder = new CapturingRecorder();
        var scope = MakeScope();
        var gate = new AllowingGate();
        var engine = new AssessmentEngine(gate, recorder, new CapturingAuditSink(), NullLogger.Instance);

        await engine.RunAsync(new AssessmentRunRequest(
            scope.AssessmentId, CorrelationId.New(), scope,
            ResourceBudget.FromScope(scope, EngineDefaults.Conservative),
            [FakeCheck("ACT-BENCH-C-003")],
            [], PreexistingFindings: null, Scorer: null), CancellationToken.None);

        Assert.Empty(recorder.PlanExclusions);
    }

    // ---------- coverage surfaces read stored reasons, never guesses ----------

    [Fact]
    public async Task CoverageSnapshot_SurfacesPersistedReasonsAndLeavesGapsVisible()
    {
        var fixture = await PersistFixture.CreateAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessment = await CreatePairedAsync(db);
            var catalogCount = CheckRegistry.Catalog().Count;
            var excludedCatalogId = CheckRegistry.Catalog()[^1].Id.Value;
            var now = DateTimeOffset.UtcNow;

            // One check executed, one catalog check was excluded at planning time (twice -
            // two contexts), the rest have no reason recorded.
            await db.RecordCheckRunAsync(Run(CheckId.From(CheckRegistry.Catalog()[0].Id.Value),
                CheckExecutionStatus.Completed, now.AddMinutes(-1), 5, 1), assessment.AssessmentId);
            await db.SavePlanExclusionsAsync(
            [
                Excl(assessment.AssessmentId, excludedCatalogId, "CATEGORY_NOT_PERMITTED", "not permitted here", now.AddSeconds(-2)),
                Excl(assessment.AssessmentId, excludedCatalogId, "CATEGORY_NOT_PERMITTED", "not permitted here", now.AddSeconds(-1))
            ]);

            var snapshot = await CoverageOperations.BuildAsync(db, assessment.AssessmentId);

            Assert.Equal(2, snapshot.PlanExclusions.Count);
            var grouped = CoverageOperations.SummarizeExclusions(snapshot.PlanExclusions);
            var row = Assert.Single(grouped);
            Assert.Equal(excludedCatalogId, row.CheckId);
            Assert.Equal("CATEGORY_NOT_PERMITTED", row.ReasonCode);
            Assert.Equal(2, row.Occurrences);
            Assert.Equal("not permitted here", row.Detail);

            // The excluded check stays in the raw never-executed list - that fact is unchanged -
            // but it leaves the UNEXPLAINED view because its reason is now a stored row.
            Assert.Contains(snapshot.NeverExecuted, m => m.Id.Value == excludedCatalogId);
            Assert.DoesNotContain(snapshot.UnexplainedNeverExecuted, m => m.Id.Value == excludedCatalogId);
            // Exactly catalogCount - 2 remain an HONEST gap: no execution recorded AND no stored
            // reason - the surface refuses to invent one.
            Assert.Equal(catalogCount - 2, snapshot.UnexplainedNeverExecuted.Count);
        }
    }

    [Fact]
    public void SummarizeExclusions_IsDeterministicAcrossEqualInputs()
    {
        var now = DateTimeOffset.UtcNow;
        var assessmentId = Guid.NewGuid();
        PlanExclusionRecord Row(string check, string reason, int seconds) =>
            Excl(assessmentId, check, reason, "detail " + check, now.AddSeconds(seconds));

        var input = new[] { Row("b", "R2", 3), Row("a", "R1", 9), Row("b", "R1", 1), Row("a", "R1", 5), Row("b", "R1", 7) };
        var first = CoverageOperations.SummarizeExclusions(input);
        var second = CoverageOperations.SummarizeExclusions(input.Reverse().ToList());

        Assert.Equal(
            [("a", "R1"), ("b", "R1"), ("b", "R2")],
            first.Select(r => (r.CheckId, r.ReasonCode)).ToArray());
        Assert.Equal(first, second);
        Assert.All(first.Where(r => r.CheckId == "a" && r.ReasonCode == "R1"), r => Assert.Equal(2, r.Occurrences));
    }

    // ---------- helpers ----------

    private static PlanExclusionRecord Excl(Guid assessmentId, string checkId, string reason, string detail, DateTimeOffset when) =>
        new(Guid.NewGuid(), assessmentId, checkId, reason, detail, when);

    private static SecurityCheckResult Run(CheckId id, CheckExecutionStatus status, DateTimeOffset started, long requests, int targets) =>
        new(id, status, started, started.AddSeconds(1), [], [], null, requests, targets);

    private sealed record DenyingGate(string Code, string Message) : ICheckGate
    {
        public GateDecision Evaluate(ScopeDefinition scope, SecurityCheckMetadata metadata) =>
            GateDecision.Deny(Code, Message);
    }

    private sealed class AllowingGate : ICheckGate
    {
        public GateDecision Evaluate(ScopeDefinition scope, SecurityCheckMetadata metadata) => GateDecision.Allow();
    }

    private static ISecurityCheck FakeCheck(string id) => new StubCheck(Meta(id));

    private sealed class StubCheck(SecurityCheckMetadata metadata) : ISecurityCheck
    {
        public SecurityCheckMetadata Metadata { get; } = metadata;

        public Task<SecurityCheckResult> ExecuteAsync(SecurityCheckContext context, CancellationToken cancellationToken) =>
            throw new InvalidOperationException("the stub must never execute; the gate denies it");
    }

    private static SecurityCheckMetadata Meta(string id) => new(
        CheckId.From(id), "name " + id, "1.0", CheckCategory.Http, Severity.Medium,
        SafetyLevel.SafeRequestOnly, PermissionRequirement.None,
        new HashSet<ProtocolKind>(), new HashSet<TargetTypeKind>(),
        new NetworkBehaviorProfile(0, 1, false, false, false), [], true, false, "d");

    private sealed class CapturingRecorder : IAssessmentRecorder
    {
        public List<StoredExclusion> PlanExclusions { get; } = [];

        public Task RecordPlanExclusionsAsync(Guid assessmentId, IReadOnlyList<ExclusionDecision> exclusions, CancellationToken cancellationToken)
        {
            foreach (var exclusion in exclusions)
            {
                PlanExclusions.Add(new StoredExclusion(assessmentId, exclusion.CheckId, exclusion.ReasonCode));
            }

            return Task.CompletedTask;
        }

        public sealed record StoredExclusion(Guid AssessmentId, string CheckId, string ReasonCode);

        public Task UpsertFindingAsync(Finding finding, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task RecordEvidenceBatchAsync(IReadOnlyList<EvidenceItem> items, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task RecordCheckRunAsync(SecurityCheckResult result, Guid assessmentId, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task SetAssessmentStateAsync(Guid assessmentId, AssessmentRunState state, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task<AssetRecord> RecordAssetAsync(AssetRecord asset, CancellationToken cancellationToken) => Task.FromResult(asset);

        public Task<ServiceObservation> RecordServiceAsync(ServiceObservation service, CancellationToken cancellationToken) => Task.FromResult(service);

        public IReadOnlyList<ServiceObservation> ObservedServices() => [];
    }

    private sealed class CapturingAuditSink : IAuditSink
    {
        public List<AuditDraft> Drafts { get; } = [];

        public Task<AuditEvent> AppendAsync(AuditDraft draft, CancellationToken cancellationToken)
        {
            Drafts.Add(draft);
            return Task.FromResult(new AuditEvent(
                Sequence: Drafts.Count, TimestampUtc: DateTimeOffset.UtcNow, draft.Actor, draft.Action,
                draft.ObjectType, draft.ObjectId, draft.Result, draft.Correlation,
                PreviousEventHash: "prev", EventHash: "hash"));
        }

        public Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(int limit, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<AuditEvent>>([]);

        public Task<bool> VerifyChainAsync(CancellationToken cancellationToken) => Task.FromResult(true);
    }

    private static ScopeDefinition MakeScope() => new(
        ScopeId: Guid.NewGuid(),
        AssessmentId: Guid.NewGuid(),
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
        AuthorizationStatement: "unit test authorization");

    private static async Task<long> CountAsync(PersistFixture fixture, string sql)
    {
        await using var connection = new Microsoft.Data.Sqlite.SqliteConnection("Data Source=" + fixture.DatabasePath);
        await connection.OpenAsync();
        var command = connection.CreateCommand();
        command.CommandText = sql;
        var raw = await command.ExecuteScalarAsync();
        return Convert.ToInt64(raw, System.Globalization.CultureInfo.InvariantCulture);
    }

    /// <summary>Seeds one assessment together with its scope copy exactly like a real run.</summary>
    private static async Task<AssessmentRecord> CreatePairedAsync(ActDatabase db)
    {
        var assessmentId = Guid.NewGuid();
        var scopeId = Guid.NewGuid();
        var assessment = new AssessmentRecord(
            assessmentId, scopeId, "plan-ledger-assessment", AssessmentRunState.Completed,
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow,
            "unit-test-operator", "unit-test-org");
        var scope = MakeScope() with { ScopeId = scopeId, AssessmentId = assessmentId };
        await db.CreateAssessmentAsync(assessment, scope);
        return assessment;
    }
}
