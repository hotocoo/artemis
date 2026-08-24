using System.Globalization;
using System.Text.Json;
using ACT.Contracts;
using ACT.Persistence;
using Microsoft.Data.Sqlite;
using Xunit;

namespace ACT.Tests;

/// <summary>Integration tests for the SQLite persistence layer against unique temporary databases.</summary>
public sealed class PersistenceTests
{
    // ---------- fixture ----------

    private static async Task<PersistFixture> CreateDatabaseAsync() => await PersistFixture.CreateAsync();

    private static ScopeDefinition MakeScope(Guid scopeId, Guid assessmentId, TimeSpan? retention = null) => new(
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
        EvidenceRetentionPeriod: retention ?? TimeSpan.FromDays(30),
        DataRedactionPolicy: RedactionPolicy.Standard,
        AuthorizationStatement: "I am authorized to assess these targets.");

    private static AssessmentRecord MakeAssessment(string name = "assessment") => new(
        AssessmentId: Guid.NewGuid(),
        ScopeId: Guid.NewGuid(),
        Name: name,
        State: AssessmentRunState.Created,
        CreatedUtc: DateTimeOffset.UtcNow,
        StartedUtc: null,
        CompletedUtc: null,
        OperatorIdentity: "unit-test-operator",
        Organization: "unit-test-org");

    /// <summary>Creates one assessment together with its matching scope definition.</summary>
    private static async Task<AssessmentRecord> CreatePairedAsync(
        ActDatabase db, string name = "assessment", TimeSpan? retention = null)
    {
        var assessmentId = Guid.NewGuid();
        var scopeId = Guid.NewGuid();
        var assessment = MakeAssessment(name) with { AssessmentId = assessmentId, ScopeId = scopeId };
        await db.CreateAssessmentAsync(assessment, MakeScope(scopeId, assessmentId, retention));
        return assessment;
    }

    private static Finding MakeFinding(Guid assessmentId, string classification, Severity severity = Severity.Medium)
    {
        var finding = FindingFactory.Create(
            assessmentId,
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
            new RemediationGuidance("Fix it.", ["step-one", "step-two"], ["ref-one"]),
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
        Attributes: new Dictionary<string, string> { ["source"] = "unit-test" });

    private static async Task<long> RawCountAsync(PersistFixture fixture, string sql)
    {
        await using var connection = new SqliteConnection("Data Source=" + fixture.DatabasePath);
        await connection.OpenAsync();
        var command = connection.CreateCommand();
        command.CommandText = sql;
        var raw = await command.ExecuteScalarAsync();
        return Convert.ToInt64(raw, CultureInfo.InvariantCulture);
    }

    /// <summary>Runs one storage-level statement for arrange phases that must bypass the API.</summary>
    private static async Task ExecAsync(PersistFixture fixture, string sql)
    {
        await using var connection = new SqliteConnection("Data Source=" + fixture.DatabasePath);
        await connection.OpenAsync();
        var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }

    // ---------- migrations ----------

    [Fact]
    public async Task Persist_MigrateTwiceIsIdempotent()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            await fixture.Database.InitializeAsync();
            var tablesAfterFirst = await RawCountAsync(fixture,
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'");
            var migrationRows = await RawCountAsync(fixture, "SELECT COUNT(*) FROM schema_migrations");
            await fixture.Database.InitializeAsync();
            var tablesAfterSecond = await RawCountAsync(fixture,
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'");

            Assert.Equal(2, migrationRows);
            Assert.Equal(tablesAfterFirst, tablesAfterSecond);
        }
    }

    [Fact]
    public async Task Persist_MigrationV2UpgradesV1DatabaseInPlace()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessment = await CreatePairedAsync(db);
            var finding = MakeFinding(assessment.AssessmentId, "upgrade-class");
            await db.UpsertFindingAsync(finding);

            // Rewind the file to a v1 state: drop the triage columns and forget migration 2.
            // This is exactly what a database written by an older build looks like.
            await using (var connection = new SqliteConnection("Data Source=" + fixture.DatabasePath))
            {
                await connection.OpenAsync();
                foreach (var column in new[] { "triage_note", "triaged_by", "triaged_utc" })
                {
                    var drop = connection.CreateCommand();
                    drop.CommandText = "ALTER TABLE findings DROP COLUMN " + column;
                    await drop.ExecuteNonQueryAsync();
                }

                var forget = connection.CreateCommand();
                forget.CommandText = "DELETE FROM schema_migrations WHERE version = 2";
                await forget.ExecuteNonQueryAsync();
            }

            await db.DisposeAsync();

            var upgraded = new ActDatabase(fixture.DatabasePath, new StorageOptions
            {
                DatabasePath = fixture.DatabasePath,
                WalEnabled = true,
                RetentionDays = 90
            });
            await using (upgraded)
            {
                await upgraded.InitializeAsync();

                var versions = new List<long>();
                await using (var connection =
                    new SqliteConnection("Data Source=" + fixture.DatabasePath))
                {
                    await connection.OpenAsync();
                    var query = connection.CreateCommand();
                    query.CommandText = "SELECT version FROM schema_migrations ORDER BY version";
                    await using var reader = await query.ExecuteReaderAsync();
                    while (await reader.ReadAsync())
                    {
                        versions.Add(reader.GetInt64(0));
                    }
                }

                Assert.Equal([1, 2], versions);

                // Pre-existing rows survive untouched; the lifecycle works on them immediately.
                Assert.Null(await upgraded.GetTriageAsync(finding.FindingId));
                var (_, triage) = await upgraded.TriageFindingAsync(
                    finding.FindingId, FindingStatus.AcceptedRisk, "upgrade-op",
                    "risk accepted by change 42", CorrelationId.New());
                Assert.Equal(FindingStatus.AcceptedRisk, triage.Status);
                Assert.Equal("risk accepted by change 42", triage.Note);
                Assert.True(await upgraded.VerifyChainAsync());
            }
        }
    }

    // ---------- assessments / assets / services ----------

    [Fact]
    public async Task Persist_AssessmentAssetServiceRoundTrip()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessmentId = Guid.NewGuid();
            var scopeId = Guid.NewGuid();
            var assessment = MakeAssessment() with { AssessmentId = assessmentId, ScopeId = scopeId };
            var scope = MakeScope(scopeId, assessmentId);
            await db.CreateAssessmentAsync(assessment, scope);

            var loaded = await db.GetAssessmentAsync(assessment.AssessmentId);
            Assert.NotNull(loaded);
            Assert.Equivalent(assessment, loaded);

            var assetId = Guid.NewGuid();
            var firstInsert = await db.AddAssetAsync(new AssetRecord(
                assetId, assessment.AssessmentId, AssetKind.Host, "web host", "localhost",
                ["127.0.0.1"], DateTimeOffset.UtcNow, WithinScope: true));
            var duplicateInsert = await db.AddAssetAsync(new AssetRecord(
                Guid.NewGuid(), assessment.AssessmentId, AssetKind.Host, "web host dup", "localhost",
                [], DateTimeOffset.UtcNow, WithinScope: true));
            Assert.True(firstInsert);
            Assert.False(duplicateInsert);

            var service = new ServiceObservation(
                Guid.NewGuid(), assetId, 8443, ProtocolKind.Https, "test banner", TlsNegotiated: true,
                DateTimeOffset.UtcNow, CheckId.From("CHK-TST"));
            Assert.True(await db.AddServiceAsync(service));
            Assert.False(await db.AddServiceAsync(new ServiceObservation(
                Guid.NewGuid(), assetId, 8443, ProtocolKind.Https, null, false,
                DateTimeOffset.UtcNow, CheckId.From("CHK-TST"))));

            var services = await RawCountAsync(fixture, "SELECT COUNT(*) FROM services WHERE asset_id = '"
                + assetId.ToString("D") + "'");
            Assert.Equal(1, services);

            var list = await db.ListAssessmentsAsync(10);
            Assert.Single(list);

            await db.UpdateAssessmentStateAsync(assessment.AssessmentId, AssessmentRunState.Running);
            var running = await db.GetAssessmentAsync(assessment.AssessmentId);
            Assert.Equal(AssessmentRunState.Running, running!.State);
            Assert.Null(await db.GetAssessmentAsync(Guid.NewGuid()));
        }
    }

    // ---------- findings ----------

    [Fact]
    public async Task Persist_UpsertDedupeMergesLastSeenWithoutDuplicateRow()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessment = await CreatePairedAsync(db);

            var original = MakeFinding(assessment.AssessmentId, "tls-expired");
            var stored = await db.UpsertFindingAsync(original);
            Assert.Equal(original.FindingId, stored.FindingId);

            var reobservation = original with { LastSeenUtc = original.LastSeenUtc.AddHours(2) };
            var merged = await db.UpsertFindingAsync(reobservation);

            Assert.Equal(original.FirstSeenUtc, merged.FirstSeenUtc);
            Assert.Equal(reobservation.LastSeenUtc, merged.LastSeenUtc);
            Assert.Equal(original.Status, merged.Status);
            Assert.Equal(1, await RawCountAsync(fixture, "SELECT COUNT(*) FROM findings"));
        }
    }

    [Fact]
    public async Task Persist_TerminalStatusesAreNeverResurrected()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            foreach (var terminal in new[] { FindingStatus.AcceptedRisk, FindingStatus.FalsePositive, FindingStatus.Remediated })
            {
                var assessment = await CreatePairedAsync(db, "terminal-" + terminal);
                var finding = MakeFinding(assessment.AssessmentId, "class-" + terminal);
                await db.UpsertFindingAsync(finding);
                await db.TriageFindingAsync(
                    finding.FindingId, terminal, "triage-operator", note: null, CorrelationId.New());

                var lateObservation = finding with { LastSeenUtc = finding.LastSeenUtc.AddDays(5) };
                var result = await db.UpsertFindingAsync(lateObservation);

                Assert.Equal(terminal, result.Status);
                Assert.Equal(finding.LastSeenUtc, result.LastSeenUtc);
                Assert.Equal(1, await RawCountAsync(fixture,
                    "SELECT COUNT(*) FROM findings WHERE assessment_id = '"
                    + assessment.AssessmentId.ToString("D") + "'"));
            }
        }
    }

    [Fact]
    public async Task Persist_ListFindingsAppliesFilters()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessment = await CreatePairedAsync(db);

            var low = MakeFinding(assessment.AssessmentId, "low-class", Severity.Low);
            var medium = MakeFinding(assessment.AssessmentId, "medium-class", Severity.Medium);
            var high = MakeFinding(assessment.AssessmentId, "high-class", Severity.High);
            high = high with { Status = FindingStatus.Confirmed };
            await db.UpsertFindingAsync(low);
            await db.UpsertFindingAsync(medium);
            await db.UpsertFindingAsync(high);

            var all = await db.ListFindingsAsync(limit: 50);
            Assert.Equal(3, all.Count);

            var openOnly = await db.ListFindingsAsync(status: FindingStatus.New, limit: 50);
            Assert.Equal(2, openOnly.Count);

            var mediumPlus = await db.ListFindingsAsync(minSeverity: Severity.Medium, limit: 50);
            Assert.Equal(2, mediumPlus.Count);
            Assert.DoesNotContain(mediumPlus, f => f.TechnicalSeverity == Severity.Low);

            var confirmedHigh = await db.ListFindingsAsync(
                assessmentId: assessment.AssessmentId, status: FindingStatus.Confirmed, limit: 50);
            Assert.Equal([high.FindingId], confirmedHigh.Select(f => f.FindingId).ToList());

            Assert.Single(await db.ListFindingsAsync(limit: 1));
            var otherAssessment = await db.ListFindingsAsync(assessmentId: Guid.NewGuid(), limit: 50);
            Assert.Empty(otherAssessment);
        }
    }

    [Fact]
    public async Task Persist_TriageWritesDecisionAndAuditsIt()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessment = await CreatePairedAsync(db);
            var finding = MakeFinding(assessment.AssessmentId, "status-class");
            await db.UpsertFindingAsync(finding);

            Assert.Null(await db.GetTriageAsync(finding.FindingId));

            var correlation = CorrelationId.New();
            var (updated, triage) = await db.TriageFindingAsync(
                finding.FindingId, FindingStatus.Confirmed, "triage-op", "verified against lab", correlation);

            Assert.Equal(FindingStatus.Confirmed, updated.Status);
            Assert.Equal(FindingStatus.Confirmed, triage.Status);
            Assert.Equal("triage-op", triage.TriagedBy);
            Assert.Equal("verified against lab", triage.Note);
            Assert.NotNull(triage.TriagedUtc);

            var stored = (await db.GetTriageAsync(finding.FindingId))!;
            Assert.Equal(triage, stored);

            var listed = await db.ListFindingsAsync(status: FindingStatus.Confirmed, limit: 10);
            Assert.Equal(finding.FindingId, listed.Single().FindingId);

            var recent = await db.ReadRecentAuditAsync(5);
            var triageEntry = Assert.Single(recent, e => e.Action == "finding.triaged");
            Assert.Equal("finding.triaged", triageEntry.Action);
            Assert.Equal("triage-op", triageEntry.Actor);
            Assert.Equal(finding.FindingId.ToString(), triageEntry.ObjectId);
            Assert.Equal("New -> Confirmed: verified against lab", triageEntry.Result);
            Assert.Equal(correlation, triageEntry.Correlation);

            Assert.True(await db.VerifyChainAsync());

            await Assert.ThrowsAsync<ActException>(() =>
                db.TriageFindingAsync(Guid.NewGuid(), FindingStatus.Confirmed, "triage-op", null, CorrelationId.New()));
        }
    }

    [Fact]
    public async Task Persist_TriageEnforcesDeterministicTransitionMatrix()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;

            // Every refused edge in the policy, exhaustively: seed the row straight into 'from'
            // (storage-level arrange, since several statuses are engine-assigned), then require
            // the transition to 'to' to fail closed as Configuration with the current state named.
            foreach (var (from, to) in RefusedEdges())
            {
                var assessment = await CreatePairedAsync(db, "matrix-" + from + "-" + to);
                var finding = MakeFinding(assessment.AssessmentId, "class-" + from + "-" + to);
                await db.UpsertFindingAsync(finding);
                await ExecAsync(fixture,
                    "UPDATE findings SET status = '" + from + "' WHERE assessment_id = '"
                    + assessment.AssessmentId.ToString("D") + "'");

                var exception = await Assert.ThrowsAsync<ActException>(() =>
                    db.TriageFindingAsync(finding.FindingId, to, "matrix-op", null, CorrelationId.New()));
                Assert.Equal(ErrorCategory.Configuration, exception.Category);
                Assert.Contains("allowed targets", exception.DiagnosticDetail, StringComparison.Ordinal);
                Assert.Contains(from.ToString(), exception.DiagnosticDetail, StringComparison.Ordinal);

                // A refused decision changes nothing on the row.
                Assert.Null(await db.GetTriageAsync(finding.FindingId));
                var unchanged = await db.ListFindingsAsync(assessmentId: assessment.AssessmentId, limit: 5);
                Assert.Equal(from, unchanged.Single().Status);
            }

            // No-op repeats fail closed even though 'same status' feels harmless.
            var noOpAssessment = await CreatePairedAsync(db, "matrix-noop");
            var noOpFinding = MakeFinding(noOpAssessment.AssessmentId, "class-noop");
            await db.UpsertFindingAsync(noOpFinding);
            await db.TriageFindingAsync(
                noOpFinding.FindingId, FindingStatus.Confirmed, "noop-op", null, CorrelationId.New());
            await Assert.ThrowsAsync<ActException>(() =>
                db.TriageFindingAsync(noOpFinding.FindingId, FindingStatus.Confirmed, "noop-op", null, CorrelationId.New()));

            // Every legal edge in the policy actually executes end to end.
            foreach (var (from, to) in LegalEdges())
            {
                var assessment = await CreatePairedAsync(db, "legal-" + from + "-" + to);
                var finding = MakeFinding(assessment.AssessmentId, "legal-" + from + "-" + to);
                await db.UpsertFindingAsync(finding);
                if (from != FindingStatus.New)
                {
                    await ExecAsync(fixture,
                        "UPDATE findings SET status = '" + from + "' WHERE assessment_id = '"
                        + assessment.AssessmentId.ToString("D") + "'");
                }

                var (_, triage) = await db.TriageFindingAsync(
                    finding.FindingId, to, "legal-op", null, CorrelationId.New());
                Assert.Equal(to, triage.Status);
                Assert.Equal("legal-op", triage.TriagedBy);
            }

            Assert.True(await db.VerifyChainAsync());
        }
    }

    private static IEnumerable<(FindingStatus From, FindingStatus To)> RefusedEdges()
    {
        foreach (var from in Enum.GetValues<FindingStatus>())
        {
            var allowed = FindingTransitions.AllowedTargets(from);
            foreach (var to in Enum.GetValues<FindingStatus>())
            {
                if (to != from && !allowed.Contains(to))
                {
                    yield return (from, to);
                }
            }
        }
    }

    private static IEnumerable<(FindingStatus From, FindingStatus To)> LegalEdges()
    {
        foreach (var from in Enum.GetValues<FindingStatus>())
        {
            foreach (var to in FindingTransitions.AllowedTargets(from))
            {
                yield return (from, to);
            }
        }
    }

    [Fact]
    public async Task Persist_ReopenedFindingIsReobservedNotResurrected()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessment = await CreatePairedAsync(db);
            var finding = MakeFinding(assessment.AssessmentId, "reopen-class");
            await db.UpsertFindingAsync(finding);

            await db.TriageFindingAsync(
                finding.FindingId, FindingStatus.Remediated, "rem-op", "fixed in build 2", CorrelationId.New());

            // While terminal, reobservation must not touch the row at all.
            var whileTerminal = await db.UpsertFindingAsync(
                finding with { LastSeenUtc = finding.LastSeenUtc.AddDays(1) });
            Assert.Equal(FindingStatus.Remediated, whileTerminal.Status);

            // The operator reopens; the next observation refreshes recency but keeps the
            // reopened state - it never silently resets to New or claims the old verdict.
            var (reopened, _) = await db.TriageFindingAsync(
                finding.FindingId, FindingStatus.Reopened, "reopen-op", "regression suspected", CorrelationId.New());
            Assert.Equal(FindingStatus.Reopened, reopened.Status);

            var lateObservation = finding with { LastSeenUtc = finding.LastSeenUtc.AddDays(3) };
            var merged = await db.UpsertFindingAsync(lateObservation);
            Assert.Equal(FindingStatus.Reopened, merged.Status);
            Assert.Equal(lateObservation.LastSeenUtc, merged.LastSeenUtc);
        }
    }

    // ---------- evidence and retention ----------

    [Fact]
    public async Task Persist_RetentionDeletesOnlyOldEvidence()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessment = await CreatePairedAsync(db);
            var finding = MakeFinding(assessment.AssessmentId, "evidence-class");
            await db.UpsertFindingAsync(finding);

            var now = DateTimeOffset.UtcNow;
            var fresh = MakeEvidence(finding.FindingId, "fresh-header", now);
            var stale = MakeEvidence(finding.FindingId, "stale-header", now.AddDays(-14));
            var ancient = MakeEvidence(finding.FindingId, "ancient-header", now.AddDays(-40));
            Assert.Equal(3, await db.AddEvidenceBatchAsync([fresh, stale, ancient]));

            var sweeper = new RetentionSweeper(db);
            var deleted = await sweeper.DeleteEvidenceOlderThanAsync(TimeSpan.FromDays(7), secureWipe: false);
            Assert.Equal(2, deleted);
            Assert.Equal(1, await RawCountAsync(fixture, "SELECT COUNT(*) FROM evidence"));

            var secondPass = await sweeper.DeleteEvidenceOlderThanAsync(TimeSpan.FromDays(7), secureWipe: true);
            Assert.Equal(0, secondPass);
            Assert.Equal(1, await RawCountAsync(fixture, "SELECT COUNT(*) FROM evidence"));
        }
    }

    [Fact]
    public async Task Persist_RepeatedAssessmentOnSameScopeUpsertsScopeRow()
    {
        // Scheduled fires reuse ONE frozen scope id across fresh assessment ids; the scopes table
        // keys on scope_id, so a plain insert would make every second fire fail closed.
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var first = await CreatePairedAsync(db, "first-fire");

            var secondId = Guid.NewGuid();
            var second = MakeAssessment("second-fire") with { AssessmentId = secondId, ScopeId = first.ScopeId };
            var scopeSnapshot = MakeScope(first.ScopeId, secondId) with { AssessmentId = secondId };
            await db.CreateAssessmentAsync(second, scopeSnapshot);

            Assert.Equal(1, await RawCountAsync(fixture, "SELECT COUNT(*) FROM scopes"));
            Assert.Equal(2, await RawCountAsync(fixture, "SELECT COUNT(*) FROM assessments"));

            var definitions = await db.ListScopeDefinitionsAsync();
            var stored = Assert.Single(definitions);
            Assert.Equal(first.ScopeId, stored.ScopeId);
            Assert.Equal(secondId, stored.AssessmentId);
        }
    }

    [Fact]
    public async Task Persist_ListScopeDefinitionsRejectsColumnDefinitionMismatch()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessment = await CreatePairedAsync(db);

            // Corrupt the stored definition so its scopeId disagrees with the authoritative column.
            await using (var connection = new SqliteConnection("Data Source=" + fixture.DatabasePath))
            {
                await connection.OpenAsync();
                var read = connection.CreateCommand();
                read.CommandText = "SELECT definition_json FROM scopes WHERE scope_id = $id";
                read.Parameters.AddWithValue("$id", assessment.ScopeId.ToString());
                var raw = (string?)await read.ExecuteScalarAsync();
                Assert.NotNull(raw);

                var tampered = raw!.Replace(assessment.ScopeId.ToString("D"), Guid.NewGuid().ToString("D"));
                var write = connection.CreateCommand();
                write.CommandText = "UPDATE scopes SET definition_json = $json WHERE scope_id = $id";
                write.Parameters.AddWithValue("$json", tampered);
                write.Parameters.AddWithValue("$id", assessment.ScopeId.ToString());
                await write.ExecuteNonQueryAsync();
            }

            await Assert.ThrowsAsync<ActException>(() => db.ListScopeDefinitionsAsync());
        }
    }

    [Fact]
    public async Task Persist_RetentionPreviewReportsExpiredCountsPerScope()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var shortWindow = await CreatePairedAsync(db, "short", TimeSpan.FromDays(7));

            var finding = MakeFinding(shortWindow.AssessmentId, "preview-class");
            await db.UpsertFindingAsync(finding);
            var now = DateTimeOffset.UtcNow;
            await db.AddEvidenceBatchAsync(
            [
                MakeEvidence(finding.FindingId, "expired-a", now.AddDays(-10)),
                MakeEvidence(finding.FindingId, "inside-window", now.AddDays(-6)),
                MakeEvidence(finding.FindingId, "fresh", now)
            ]);

            var preview = await new RetentionSweeper(db).PreviewAsync();
            var row = Assert.Single(preview);
            Assert.Equal(shortWindow.ScopeId, row.ScopeId);
            Assert.Equal(TimeSpan.FromDays(7), row.RetentionPeriod);
            // Only the strictly-older-than-cutoff item counts; the sweep recomputes its cutoff at
            // run time, so tests keep a two-day margin instead of probing exact equality.
            Assert.Equal(1, row.ExpiredCount);
        }
    }

    [Fact]
    public async Task Persist_RetentionSweepHonorsEachScopeConfiguredWindow()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var shortScope = await CreatePairedAsync(db, "short-window", TimeSpan.FromDays(7));
            var longScope = await CreatePairedAsync(db, "long-window", TimeSpan.FromDays(30));

            var shortFinding = MakeFinding(shortScope.AssessmentId, "short-class");
            var longFinding = MakeFinding(longScope.AssessmentId, "long-class");
            await db.UpsertFindingAsync(shortFinding);
            await db.UpsertFindingAsync(longFinding);

            var now = DateTimeOffset.UtcNow;
            await db.AddEvidenceBatchAsync(
            [
                // Expired under BOTH windows.
                MakeEvidence(shortFinding.FindingId, "s-ancient", now.AddDays(-40)),
                MakeEvidence(longFinding.FindingId, "l-ancient", now.AddDays(-40)),
                // Expired only under the seven-day window; the thirty-day scope keeps it.
                MakeEvidence(shortFinding.FindingId, "s-middle", now.AddDays(-14)),
                MakeEvidence(longFinding.FindingId, "l-middle", now.AddDays(-14)),
                // Fresh under every window.
                MakeEvidence(shortFinding.FindingId, "s-fresh", now),
                MakeEvidence(longFinding.FindingId, "l-fresh", now)
            ]);

            var result = await new RetentionSweeper(db).SweepAsync(secureWipe: false);
            Assert.Equal(3, result.TotalDeleted);
            Assert.False(result.SecureWipe);

            var shortDeletion = result.Scopes.Single(scope => scope.ScopeId == shortScope.ScopeId);
            var longDeletion = result.Scopes.Single(scope => scope.ScopeId == longScope.ScopeId);
            Assert.Equal(2, shortDeletion.DeletedCount);
            Assert.Equal(TimeSpan.FromDays(7), shortDeletion.RetentionPeriod);
            Assert.Equal(1, longDeletion.DeletedCount);
            Assert.Equal(TimeSpan.FromDays(30), longDeletion.RetentionPeriod);

            Assert.Equal(3, await RawCountAsync(fixture, "SELECT COUNT(*) FROM evidence"));
            Assert.Equal(0, await RawCountAsync(fixture,
                "SELECT COUNT(*) FROM evidence WHERE key LIKE 's-%' AND key != 's-fresh'"));
            Assert.Equal(1, await RawCountAsync(fixture,
                "SELECT COUNT(*) FROM evidence WHERE key = 'l-middle'"));

            // Idempotent: nothing is left past its window, so a second sweep deletes nothing.
            var secondPass = await new RetentionSweeper(db).SweepAsync(secureWipe: true);
            Assert.Equal(0, secondPass.TotalDeleted);
            Assert.True(secondPass.SecureWipe);
            Assert.Equal(3, await RawCountAsync(fixture, "SELECT COUNT(*) FROM evidence"));
        }
    }


    // ---------- audit chain ----------

    [Fact]
    public async Task Persist_AuditChainVerifiesWhenUntampered()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var appended = new List<AuditEvent>();
            for (var index = 0; index < 5; index++)
            {
                appended.Add(await db.AppendAuditAsync(new AuditDraft(
                    Actor: "operator",
                    Action: "ASSESSMENT_START",
                    ObjectType: "assessment",
                    ObjectId: Guid.NewGuid().ToString(),
                    Result: "OK",
                    Correlation: CorrelationId.New())));
            }

            Assert.True(await db.VerifyChainAsync());
            Assert.Equal(appended[0].Sequence + 4, appended[^1].Sequence);
            Assert.Equal(ActDatabase.GenesisAuditHash, appended[0].PreviousEventHash);
            for (var index = 1; index < appended.Count; index++)
            {
                Assert.Equal(appended[index - 1].EventHash, appended[index].PreviousEventHash);
            }

            var recent = await db.ReadRecentAuditAsync(3);
            Assert.Equal(3, recent.Count);
            Assert.Equal(appended[^1].EventHash, recent[0].EventHash);
            Assert.Equal(appended[^2].EventHash, recent[1].EventHash);
        }
    }

    [Fact]
    public async Task Persist_TamperedAuditBreaksChainVerification()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            for (var index = 0; index < 3; index++)
            {
                await db.AppendAuditAsync(new AuditDraft(
                    Actor: "operator",
                    Action: "FINDING_STATUS_SET",
                    ObjectType: "finding",
                    ObjectId: Guid.NewGuid().ToString(),
                    Result: "OK",
                    Correlation: CorrelationId.New()));
            }

            Assert.True(await db.VerifyChainAsync());

            await using (var connection = new SqliteConnection("Data Source=" + fixture.DatabasePath))
            {
                await connection.OpenAsync();
                var command = connection.CreateCommand();
                command.CommandText =
                    "UPDATE audit_events SET result = 'unexpected-result' WHERE sequence = 2";
                Assert.Equal(1, await command.ExecuteNonQueryAsync());
            }

            Assert.False(await db.VerifyChainAsync());
        }
    }

    // ---------- dashboard ----------

    [Fact]
    public async Task Persist_DashboardAggregatesMatchSeededData()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessment = await CreatePairedAsync(db);

            for (var index = 0; index < 3; index++)
            {
                await db.AddAssetAsync(new AssetRecord(
                    Guid.NewGuid(), assessment.AssessmentId, AssetKind.Host, "host-" + index,
                    "host-" + index + ".lab", [], DateTimeOffset.UtcNow, WithinScope: true));
            }

            var assetId = await FirstAssetIdAsync(fixture);
            foreach (var port in new[] { 443, 8080 })
            {
                await db.AddServiceAsync(new ServiceObservation(
                    Guid.NewGuid(), assetId, port, ProtocolKind.Https, null,
                    TlsNegotiated: true, DateTimeOffset.UtcNow, CheckId.From("CHK-TST")));
            }

            var seeded = new (string Class, Severity Severity, FindingStatus Status, double Priority)[]
            {
                ("dash-high", Severity.High, FindingStatus.New, 80),
                ("dash-critical", Severity.Critical, FindingStatus.New, 95),
                ("dash-medium-open", Severity.Medium, FindingStatus.New, 40),
                ("dash-confirmed", Severity.Low, FindingStatus.Confirmed, 30),
                ("dash-remediated", Severity.High, FindingStatus.Remediated, 70),
                ("dash-false-positive", Severity.Informational, FindingStatus.FalsePositive, 0),
                ("dash-regressed", Severity.Medium, FindingStatus.Regressed, 55),
            };
            foreach (var seed in seeded)
            {
                await db.UpsertFindingAsync(MakeFinding(assessment.AssessmentId, seed.Class, seed.Severity)
                    with
                { Status = seed.Status, PriorityScore = seed.Priority });
            }

            var checkStatuses = new[]
            {
                CheckExecutionStatus.Completed,
                CheckExecutionStatus.CompletedWithWarnings,
                CheckExecutionStatus.Failed_FailedClosed
            };
            foreach (var status in checkStatuses)
            {
                await db.RecordCheckRunAsync(SecurityCheckResult.Empty(
                    new SecurityCheckMetadata(
                        CheckId.From("CHK-TST"), "t", "1.0", CheckCategory.Tls, Severity.High,
                        SafetyLevel.SafeRequestOnly, PermissionRequirement.None,
                        new HashSet<ProtocolKind>(), new HashSet<TargetTypeKind>(),
                        new NetworkBehaviorProfile(0, 1, false, false, false), [], true, false, "d"),
                    DateTimeOffset.UtcNow, status), assessment.AssessmentId);
            }

            await db.SaveScanMetricsAsync(new ScanMetricsRecord(
                assessment.AssessmentId, 100, 2, 0, 3, TimeSpan.FromSeconds(600), 4096));
            var secondAssessment = await CreatePairedAsync(db, "metrics-second");
            await db.SaveScanMetricsAsync(new ScanMetricsRecord(
                secondAssessment.AssessmentId, 50, 1, 1, 1, TimeSpan.FromSeconds(1200), 2048));

            var snapshot = await db.DashboardAsync();
            Assert.Equal(2, snapshot.AssessmentsTotal);
            Assert.Equal(3, snapshot.AssetsAssessed);
            Assert.Equal(2, snapshot.ServicesObserved);
            Assert.Equal(5, snapshot.FindingsOpen);
            Assert.Equal(2, snapshot.FindingsCriticalOrHigh);
            Assert.Equal(1, snapshot.FindingsConfirmed);
            Assert.Equal(1, snapshot.FindingsRemediated);
            Assert.Equal(1, snapshot.RegressionsDetected);
            Assert.Equal(1, snapshot.FalsePositives);
            Assert.Equal(3, snapshot.ChecksExecuted);
            Assert.Equal(1, snapshot.ChecksFailed);
            Assert.Equal(15.0, snapshot.AverageScanDurationMinutes, precision: 6);
            Assert.Equal(150, snapshot.RequestCount);
            Assert.Equal(95, snapshot.CurrentRiskScore);
        }
    }

    private static async Task<Guid> FirstAssetIdAsync(PersistFixture fixture)
    {
        await using var connection = new SqliteConnection("Data Source=" + fixture.DatabasePath);
        await connection.OpenAsync();
        var command = connection.CreateCommand();
        command.CommandText = "SELECT asset_id FROM assets LIMIT 1";
        var raw = await command.ExecuteScalarAsync();
        return Guid.Parse((string)raw!);
    }

    // ---------- scan metrics ----------

    [Fact]
    public async Task Persist_ScanMetricsRoundTripAndReplace()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessment = await CreatePairedAsync(db);

            await db.SaveScanMetricsAsync(new ScanMetricsRecord(
                assessment.AssessmentId, 10, 2, 0, 1, TimeSpan.FromSeconds(90), 1024));
            var loaded = await db.GetMetricsAsync(assessment.AssessmentId);
            Assert.NotNull(loaded);
            Assert.Equal(10, loaded.RequestsSent);
            Assert.Equal(TimeSpan.FromSeconds(90), loaded.TotalDuration);

            await db.SaveScanMetricsAsync(new ScanMetricsRecord(
                assessment.AssessmentId, 20, 3, 1, 2, TimeSpan.FromMinutes(3), 2048));
            var replaced = await db.GetMetricsAsync(assessment.AssessmentId);
            Assert.Equal(20, replaced!.RequestsSent);
            Assert.Equal(TimeSpan.FromMinutes(3), replaced.TotalDuration);
            Assert.Null(await db.GetMetricsAsync(Guid.NewGuid()));
        }
    }

    // ---------- configuration store ----------

    private sealed record Preference(bool Verbose, int Level);

    [Fact]
    public async Task Persist_ConfigStoreRoundTripsTypedValues()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            await db.SetConfigAsync("limits.requests", 250);
            await db.SetConfigAsync("ui.title", "console");
            await db.SetConfigAsync("ops.pref", new Preference(true, 3));

            Assert.Equal(250, await db.GetConfigAsync<int>("limits.requests"));
            Assert.Equal("console", await db.GetConfigAsync<string>("ui.title"));
            Assert.Equal(new Preference(true, 3), await db.GetConfigAsync<Preference>("ops.pref"));

            await db.SetConfigAsync("limits.requests", 999);
            Assert.Equal(999, await db.GetConfigAsync<int>("limits.requests"));

            Assert.Equal(0, await db.GetConfigAsync<int>("missing.key"));
            Assert.Null(await db.GetConfigAsync<string>("missing.key"));

            await Assert.ThrowsAsync<ActException>(() => db.SetConfigAsync("", 1));
        }
    }

    // ---------- schedules ----------

    [Fact]
    public async Task Persist_ScheduleLifecyclePersistsEnablementAndRuns()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var scheduleScopeId = Guid.NewGuid();
            var scope = MakeScope(scheduleScopeId, Guid.NewGuid());
            var schedule = new ScheduleDefinition(
                ScheduleId: Guid.NewGuid(), Name: "nightly", ScopeId: scheduleScopeId,
                CronExpression: "0 3 * * *", Trigger: ScheduleTriggerKind.Scheduled,
                Enabled: true, CreatedUtc: DateTimeOffset.UtcNow, LastRunUtc: null);
            await db.SaveScheduleAsync(schedule);

            var disabled = schedule with { ScheduleId = Guid.NewGuid(), Name = "paused", Enabled = false };
            await db.SaveScheduleAsync(disabled);

            var enabled = await db.ListEnabledSchedulesAsync();
            Assert.Single(enabled);
            Assert.Equal(schedule.ScheduleId, enabled[0].ScheduleId);

            var ranAt = DateTimeOffset.UtcNow.AddHours(-1);
            await db.MarkScheduleRanAsync(schedule.ScheduleId, ranAt);
            var afterRun = await db.ListEnabledSchedulesAsync();
            Assert.Equal(ranAt, afterRun[0].LastRunUtc);

            var updated = schedule with { CronExpression = "30 4 * * *" };
            await db.SaveScheduleAsync(updated);
            Assert.Equal(1, await RawCountAsync(fixture,
                "SELECT COUNT(*) FROM schedules WHERE schedule_id = '"
                + schedule.ScheduleId.ToString("D") + "'"));
            var reloadedEnabled = await db.ListEnabledSchedulesAsync();
            Assert.Equal("30 4 * * *", reloadedEnabled[0].CronExpression);

            await Assert.ThrowsAsync<ActException>(() =>
                db.MarkScheduleRanAsync(Guid.NewGuid(), DateTimeOffset.UtcNow));
        }
    }

    [Fact]
    public async Task Persist_GetScheduleAndListAllIncludeDisabledRows()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var scopeId = Guid.NewGuid();
            var enabled = new ScheduleDefinition(
                ScheduleId: Guid.NewGuid(), Name: "active", ScopeId: scopeId,
                CronExpression: "*/15 * * * *", Trigger: ScheduleTriggerKind.Scheduled,
                Enabled: true, CreatedUtc: DateTimeOffset.UtcNow, LastRunUtc: null);
            var disabled = new ScheduleDefinition(
                ScheduleId: Guid.NewGuid(), Name: "paused", ScopeId: scopeId,
                CronExpression: "0 3 * * *", Trigger: ScheduleTriggerKind.Manual,
                Enabled: false, CreatedUtc: DateTimeOffset.UtcNow, LastRunUtc: null);
            await db.SaveScheduleAsync(enabled);
            await db.SaveScheduleAsync(disabled);

            var all = await db.ListAllSchedulesAsync();
            Assert.Equal(2, all.Count);
            Assert.Contains(all, s => s.ScheduleId == disabled.ScheduleId && !s.Enabled);

            var fetched = await db.GetScheduleAsync(disabled.ScheduleId);
            Assert.NotNull(fetched);
            Assert.Equal("paused", fetched!.Name);
            Assert.Equal(ScheduleTriggerKind.Manual, fetched.Trigger);
            Assert.Null(await db.GetScheduleAsync(Guid.NewGuid()));
        }
    }

    // ---------- baselines ----------

    [Fact]
    public async Task Persist_LatestBaselineReturnsMostRecentForScope()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var scopeId = Guid.NewGuid();
            var older = new SecurityBaseline(
                Guid.NewGuid(), scopeId, "base-1",
                [new ServiceBaselineEntry(443, ProtocolKind.Https, BaselineServiceStatus.Expected)],
                [], DateTimeOffset.UtcNow.AddDays(-7));
            var newer = new SecurityBaseline(
                Guid.NewGuid(), scopeId, "base-2",
                [new ServiceBaselineEntry(443, ProtocolKind.Https, BaselineServiceStatus.Expected)],
                ["accepted-fingerprint"], DateTimeOffset.UtcNow);
            await db.SaveBaselineAsync(older);
            await db.SaveBaselineAsync(newer);

            var latest = await db.GetLatestBaselineAsync(scopeId);
            Assert.NotNull(latest);
            Assert.Equal(newer.BaselineId, latest.BaselineId);
            Assert.Contains("accepted-fingerprint", latest.AcceptedFindingFingerprints);

            Assert.Null(await db.GetLatestBaselineAsync(Guid.NewGuid()));
        }
    }

    // ---------- regression tests ----------

    [Fact]
    public async Task Persist_RegressionTestsReportDueOnlyWithinCadence()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessment = await CreatePairedAsync(db);
            var finding = MakeFinding(assessment.AssessmentId, "regression-class");
            await db.UpsertFindingAsync(finding);

            var created = DateTimeOffset.UtcNow.AddDays(-30);
            var test = new RegressionTestRecord(
                Guid.NewGuid(), assessment.AssessmentId, finding.FindingId, "verify-tls",
                "Re-run TLS verification", Severity.High, TimeSpan.FromDays(7), Enabled: true,
                created, LastRunUtc: null, NextRunUtc: default);
            await db.SaveRegressionTestAsync(test);

            var stored = await db.GetRegressionTestAsync(test.RegressionTestId);
            Assert.NotNull(stored);
            Assert.Equal(created.AddDays(7), stored.NextRunUtc);

            var dueBeforeWindow = await db.ListDueRegressionsAsync([finding.FindingId], created.AddDays(6));
            Assert.Empty(dueBeforeWindow);

            var dueAtWindow = await db.ListDueRegressionsAsync([finding.FindingId], created.AddDays(7));
            Assert.Single(dueAtWindow);

            var ranAt = created.AddDays(8);
            var run = await db.RecordTestRunAsync(test.RegressionTestId, ranAt, VerificationState.Tested, "clean run");
            Assert.Equal(ranAt.AddDays(7), (await db.GetRegressionTestAsync(test.RegressionTestId))!.NextRunUtc);
            var dueAfterRunBeforeCadence =
                await db.ListDueRegressionsAsync([finding.FindingId], ranAt.AddDays(6));
            Assert.Empty(dueAfterRunBeforeCadence);
            Assert.Single(await db.ListDueRegressionsAsync([finding.FindingId], ranAt.AddDays(8)));

            Assert.Single(await db.ListRegressionsForAssessmentAsync(assessment.AssessmentId));
            Assert.Empty(await db.ListRegressionsForAssessmentAsync(Guid.NewGuid()));
            Assert.Empty(await db.ListDueRegressionsAsync([], DateTimeOffset.UtcNow));

            await Assert.ThrowsAsync<ActException>(() =>
                db.RecordTestRunAsync(Guid.NewGuid(), ranAt, VerificationState.Tested, "orphan"));
        }
    }

    // ---------- feeds ----------

    [Fact]
    public async Task Persist_FeedVersionsTrackLatestCurrentGeneration()
    {
        var fixture = await CreateDatabaseAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var updated = DateTimeOffset.UtcNow;
            await db.UpsertFeedAsync(new FeedRecord(
                "osv-lab", AdvisoryFeedKind.OfflineFile, "/tmp/lab/osv-snapshot.json", Enabled: true, updated));

            var firstRetrieved = DateTimeOffset.UtcNow.AddDays(-2);
            var secondRetrieved = DateTimeOffset.UtcNow;
            await db.RecordFeedVersionAsync("osv-lab", firstRetrieved, "hash-one", isCurrent: true, "initial pull");
            await db.RecordFeedVersionAsync("osv-lab", secondRetrieved, "hash-two", isCurrent: true, "refresh");

            var latest = await db.LatestFeedVersionAsync("osv-lab");
            Assert.NotNull(latest);
            Assert.Equal("hash-two", latest.MetadataHash);
            Assert.True(latest.IsCurrent);

            Assert.Equal(1, await RawCountAsync(fixture,
                "SELECT COUNT(*) FROM feed_versions WHERE feed_name = 'osv-lab' AND is_current = 1"));

            Assert.Null(await db.LatestFeedVersionAsync("never-configured"));

            await Assert.ThrowsAsync<ActException>(() =>
                db.RecordFeedVersionAsync("ghost-feed", DateTimeOffset.UtcNow, "hash-x", true, "no such feed"));
        }
    }
}

/// <summary>Isolated per-test database in a temporary directory that is removed on disposal.</summary>
public sealed class PersistFixture : IAsyncDisposable
{
    private readonly string _directory;

    private PersistFixture(string directory, ActDatabase database, string databasePath)
    {
        _directory = directory;
        Database = database;
        DatabasePath = databasePath;
    }

    /// <summary>The initialized database under test.</summary>
    public ActDatabase Database { get; }

    /// <summary>Absolute path of the database file, usable for raw verification commands.</summary>
    public string DatabasePath { get; }

    /// <summary>Creates a unique temporary database with schema v1 applied.</summary>
    public static async Task<PersistFixture> CreateAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), "act-persist-tests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var databasePath = Path.Combine(directory, "act.db");
        var database = new ActDatabase(databasePath, new StorageOptions
        {
            DatabasePath = databasePath,
            WalEnabled = true,
            RetentionDays = 90
        });
        await database.InitializeAsync();
        return new PersistFixture(directory, database, databasePath);
    }

    /// <summary>Closes the database and deletes the temporary directory.</summary>
    public async ValueTask DisposeAsync()
    {
        await Database.DisposeAsync();
        SqliteConnection.ClearAllPools();
        try
        {
            Directory.Delete(_directory, recursive: true);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
