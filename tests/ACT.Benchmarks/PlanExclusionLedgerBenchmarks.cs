using ACT.Contracts;
using ACT.Persistence;
using BenchmarkDotNet.Attributes;
using Microsoft.Data.Sqlite;

namespace ACT.Benchmarks;

/// <summary>
/// The persisted planning-exclusion ledger's hot paths at realistic scale: listing across
/// every assessment and filtered to one assessment over 1_000 seeded decisions, plus one
/// typical save batch (50 rows - roughly one assessment's worth of per-context exclusions).
/// Every iteration of the save benchmark measures an identical insert: its own rows are
/// deleted again before the next one runs. Run explicitly via:
///   dotnet run -c Release --project tests/ACT.Benchmarks -- --filter *PlanExclusion*
/// </summary>
[MemoryDiagnoser]
public class PlanExclusionLedgerBenchmarks
{
    private const int SeedAssessments = 10;
    private const int RowsPerAssessment = 100;

    private ActDatabase _database = null!;
    private string _directory = null!;
    private Guid[] _assessmentIds = null!;
    private Guid _saveAssessmentId;
    private Guid _saveRunId;

    [GlobalSetup]
    public async Task SetupAsync()
    {
        _directory = Path.Combine(Path.GetTempPath(), "act-bench-plan", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(_directory);
        var databasePath = Path.Combine(_directory, "bench.db");
        _database = new ActDatabase(databasePath, new StorageOptions { DatabasePath = databasePath, WalEnabled = false });
        await _database.InitializeAsync();

        _assessmentIds = Enumerable.Range(0, SeedAssessments).Select(_ => Guid.NewGuid()).ToArray();
        foreach (var assessmentId in _assessmentIds)
        {
            // Real parent rows first: the ledger's foreign key refuses orphan exclusions by
            // design, exactly as it does in production.
            var scopeId = Guid.NewGuid();
            await _database.CreateAssessmentAsync(new ACT.Contracts.AssessmentRecord(
                assessmentId, scopeId, "bench", ACT.Contracts.AssessmentRunState.Completed,
                DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow,
                "bench-operator", "bench-org"), Scope(scopeId, assessmentId));
            await _database.SavePlanExclusionsAsync(Seed(assessmentId, RowsPerAssessment));
        }

        // One dedicated parent for the save benchmark so every invocation inserts against a
        // real assessment row while [IterationCleanup] keeps its footprint at zero.
        _saveAssessmentId = Guid.NewGuid();
        var saveScopeId = Guid.NewGuid();
        await _database.CreateAssessmentAsync(new ACT.Contracts.AssessmentRecord(
            _saveAssessmentId, saveScopeId, "bench-save", ACT.Contracts.AssessmentRunState.Completed,
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow,
            "bench-operator", "bench-org"), Scope(saveScopeId, _saveAssessmentId));
    }

    [GlobalCleanup]
    public async Task CleanupAsync()
    {
        await _database.DisposeAsync();
        SqliteConnection.ClearAllPools();
        try { Directory.Delete(_directory, recursive: true); } catch (IOException) { }
    }

    [Benchmark]
    public async Task<int> List_AllTenAssessmentsOneThousandRows()
    {
        var rows = await _database.ListPlanExclusionsAsync(null, 10_000);
        return rows.Count;
    }

    [Benchmark]
    public async Task<int> List_SingleAssessmentHundredRows()
    {
        var rows = await _database.ListPlanExclusionsAsync(_assessmentIds[0], 10_000);
        return rows.Count;
    }

    [Benchmark]
    public async Task Save_TypicalBatchOfFiftyDecisions()
    {
        // Identical 50-row batch per invocation against the dedicated parent assessment;
        // [IterationCleanup] deletes exactly these rows before the next one runs.
        await _database.SavePlanExclusionsAsync(Seed(_saveAssessmentId, 50));
    }

    [IterationCleanup(Target = nameof(Save_TypicalBatchOfFiftyDecisions))]
    public void DeleteSavedBatch()
    {
        if (_saveRunId == Guid.Empty)
        {
            return;
        }

        using var connection = new SqliteConnection("Data Source=" + Path.Combine(_directory, "bench.db"));
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM plan_exclusions WHERE assessment_id = $id";
        command.Parameters.AddWithValue("$id", _saveRunId.ToString());
        command.ExecuteNonQuery();
        _saveRunId = Guid.Empty;
    }

    private static ACT.Contracts.ScopeDefinition Scope(Guid scopeId, Guid assessmentId) => new(
        ScopeId: scopeId,
        AssessmentId: assessmentId,
        OperatorIdentity: "bench-operator",
        Organization: "bench-org",
        TargetType: ACT.Contracts.TargetTypeKind.Localhost,
        AllowlistedTargets: ["localhost"],
        ExcludedTargets: [],
        PermittedProtocols: [ACT.Contracts.ProtocolKind.Https],
        PermittedPorts: [ACT.Contracts.PortRange.Single(8443)],
        RequestsPerSecond: 5,
        ConcurrencyLimit: 2,
        MaxRuntime: TimeSpan.FromMinutes(30),
        MaxRequests: 500,
        AllowedCategories: Enum.GetValues<ACT.Contracts.CheckCategory>(),
        ProhibitedCategories: [],
        EmergencyStopEnabled: true,
        EvidenceRetentionPeriod: TimeSpan.FromDays(30),
        DataRedactionPolicy: ACT.Contracts.RedactionPolicy.Standard,
        AuthorizationStatement: "benchmark authorization");

    private static List<PlanExclusionRecord> Seed(Guid assessmentId, int count) =>
        Enumerable.Range(0, count).Select(i => new PlanExclusionRecord(
            Guid.NewGuid(),
            assessmentId,
            "ACT-BENCH-" + (i % 9).ToString("000"),
            i % 2 == 0 ? "TARGET_TYPE_MISMATCH" : "PROTOCOL_MISMATCH",
            "Deterministic bench decision " + i,
            DateTimeOffset.UtcNow.AddSeconds(-i))).ToList();
}
