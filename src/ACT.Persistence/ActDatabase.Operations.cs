using System.Data.Common;
using ACT.Contracts;
using Microsoft.Data.Sqlite;

namespace ACT.Persistence;

public sealed partial class ActDatabase
{
    private const string BaselineKeyPrefix = "baseline:";

    // ---------- schedules ----------

    /// <summary>Persists one schedule; an existing id is updated without touching creation or run bookkeeping.</summary>
    public Task SaveScheduleAsync(ScheduleDefinition schedule, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(schedule);
        if (string.IsNullOrWhiteSpace(schedule.Name) || string.IsNullOrWhiteSpace(schedule.CronExpression))
        {
            throw ActException.FailClosed(ErrorCategory.Persistence,
                "The schedule is missing required fields.",
                $"Schedule {schedule.ScheduleId} requires a name and a cron expression.");
        }

        return WriteAsync(async (connection, transaction, token) =>
        {
            await using var command = Command(connection, transaction, """
                INSERT INTO schedules(schedule_id, name, scope_id, cron_expression, trigger, enabled,
                                      created_utc, last_run_utc)
                VALUES($id, $name, $scope_id, $cron_expression, $trigger, $enabled, $created_utc, $last_run_utc)
                ON CONFLICT(schedule_id) DO UPDATE SET
                    name = $name, scope_id = $scope_id, cron_expression = $cron_expression,
                    trigger = $trigger, enabled = $enabled
                """);
            command.Parameters.AddWithValue("$id", schedule.ScheduleId.ToString());
            command.Parameters.AddWithValue("$name", schedule.Name);
            command.Parameters.AddWithValue("$scope_id", schedule.ScopeId.ToString());
            command.Parameters.AddWithValue("$cron_expression", schedule.CronExpression);
            command.Parameters.AddWithValue("$trigger", schedule.Trigger.ToString());
            command.Parameters.AddWithValue("$enabled", Db(schedule.Enabled));
            command.Parameters.AddWithValue("$created_utc", Db(schedule.CreatedUtc));
            command.Parameters.AddWithValue("$last_run_utc", DbOptional(schedule.LastRunUtc));
            await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
        }, cancellationToken);
    }

    /// <summary>Returns every enabled schedule in creation order.</summary>
    public Task<IReadOnlyList<ScheduleDefinition>> ListEnabledSchedulesAsync(CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            command.CommandText =
                "SELECT * FROM schedules WHERE enabled = 1 ORDER BY created_utc ASC";
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            var schedules = new List<ScheduleDefinition>();
            while (await reader.ReadAsync(token).ConfigureAwait(false))
            {
                schedules.Add(MapSchedule(reader));
            }

            return (IReadOnlyList<ScheduleDefinition>)schedules;
        }, cancellationToken);

    /// <summary>Returns every schedule regardless of enabled state, in creation order.</summary>
    public Task<IReadOnlyList<ScheduleDefinition>> ListAllSchedulesAsync(CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            command.CommandText = "SELECT * FROM schedules ORDER BY created_utc ASC";
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            var schedules = new List<ScheduleDefinition>();
            while (await reader.ReadAsync(token).ConfigureAwait(false))
            {
                schedules.Add(MapSchedule(reader));
            }

            return (IReadOnlyList<ScheduleDefinition>)schedules;
        }, cancellationToken);

    /// <summary>Returns one schedule by identifier or null when unknown.</summary>
    public Task<ScheduleDefinition?> GetScheduleAsync(Guid scheduleId, CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            command.CommandText = "SELECT * FROM schedules WHERE schedule_id = $id";
            command.Parameters.AddWithValue("$id", scheduleId.ToString());
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            return await reader.ReadAsync(token).ConfigureAwait(false) ? MapSchedule(reader) : null;
        }, cancellationToken);

    /// <summary>Records that a schedule ran. Fails closed when the schedule does not exist.</summary>
    public Task MarkScheduleRanAsync(Guid scheduleId, DateTimeOffset ranUtc, CancellationToken cancellationToken = default) =>
        WriteAsync(async (connection, transaction, token) =>
        {
            await using var command = Command(connection, transaction,
                "UPDATE schedules SET last_run_utc = $ran WHERE schedule_id = $id");
            command.Parameters.AddWithValue("$ran", Db(ranUtc));
            command.Parameters.AddWithValue("$id", scheduleId.ToString());
            var changes = await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
            RequireRows(changes, $"schedule {scheduleId}", "run marking");
        }, cancellationToken);

    private static ScheduleDefinition MapSchedule(SqliteDataReader row) => new(
        ScheduleId: row.GuidOf("schedule_id"),
        Name: row.Str("name"),
        ScopeId: row.GuidOf("scope_id"),
        CronExpression: row.Str("cron_expression"),
        Trigger: ActValues.Enum<ScheduleTriggerKind>(row.Str("trigger"), "trigger"),
        Enabled: row.BoolOf("enabled"),
        CreatedUtc: row.TimeOf("created_utc"),
        LastRunUtc: row.TimeOrNull("last_run_utc"));

    // ---------- baselines (stored through the configuration store; no dedicated table in schema v1) ----------

    /// <summary>Stores one security baseline snapshot for drift detection.</summary>
    public Task SaveBaselineAsync(SecurityBaseline baseline, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(baseline);
        if (baseline.BaselineId == Guid.Empty || baseline.ScopeId == Guid.Empty)
        {
            throw ActException.FailClosed(ErrorCategory.Persistence,
                "The baseline is missing required identifiers.",
                "SecurityBaseline requires non-empty BaselineId and ScopeId.");
        }

        return WriteAsync(async (connection, transaction, token) =>
        {
            await using var command = Command(connection, transaction, """
                INSERT INTO configurations(key, value_json, updated_utc)
                VALUES($key, $value_json, $updated_utc)
                ON CONFLICT(key) DO UPDATE SET value_json = $value_json, updated_utc = $updated_utc
                """);
            command.Parameters.AddWithValue("$key", BaselineKey(baseline.ScopeId, baseline.BaselineId));
            command.Parameters.AddWithValue("$value_json", ActJson.Serialize(baseline));
            command.Parameters.AddWithValue("$updated_utc", ActTime.Write(DateTimeOffset.UtcNow));
            await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
        }, cancellationToken);
    }

    /// <summary>Returns the most recently created baseline for one scope or null when none exists.</summary>
    public Task<SecurityBaseline?> GetLatestBaselineAsync(Guid scopeId, CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            command.CommandText =
                "SELECT value_json FROM configurations WHERE key LIKE $prefix ORDER BY updated_utc ASC";
            command.Parameters.AddWithValue("$prefix", BaselineKeyPrefix + scopeId.ToString("N") + ":%");
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            SecurityBaseline? latest = null;
            while (await reader.ReadAsync(token).ConfigureAwait(false))
            {
                var candidate = ActJson.Deserialize<SecurityBaseline>(reader.GetString(0), "baseline value_json");
                if (latest is null || candidate.CreatedUtc > latest.CreatedUtc)
                {
                    latest = candidate;
                }
            }

            return latest;
        }, cancellationToken);

    /// <summary>Returns one baseline by identifier within a scope, or null when unknown.</summary>
    public Task<SecurityBaseline?> GetBaselineAsync(Guid scopeId, Guid baselineId, CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            command.CommandText =
                "SELECT value_json FROM configurations WHERE key = $key";
            command.Parameters.AddWithValue("$key", BaselineKey(scopeId, baselineId));
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            return await reader.ReadAsync(token).ConfigureAwait(false)
                ? ActJson.Deserialize<SecurityBaseline>(reader.GetString(0), "baseline value_json")
                : null;
        }, cancellationToken);

    /// <summary>Returns every stored baseline for one scope, oldest first.</summary>
    public Task<IReadOnlyList<SecurityBaseline>> ListBaselinesAsync(Guid scopeId, CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            command.CommandText =
                "SELECT value_json FROM configurations WHERE key LIKE $prefix ORDER BY updated_utc ASC";
            command.Parameters.AddWithValue("$prefix", BaselineKeyPrefix + scopeId.ToString("N") + ":%");
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            var baselines = new List<SecurityBaseline>();
            while (await reader.ReadAsync(token).ConfigureAwait(false))
            {
                baselines.Add(ActJson.Deserialize<SecurityBaseline>(reader.GetString(0), "baseline value_json"));
            }

            return (IReadOnlyList<SecurityBaseline>)[.. baselines.OrderBy(static b => b.CreatedUtc)];
        }, cancellationToken);

    private static string BaselineKey(Guid scopeId, Guid baselineId) =>
        BaselineKeyPrefix + scopeId.ToString("N") + ":" + baselineId.ToString("N");

    // ---------- regression tests ----------

    /// <summary>Stores one regression test recipe; an existing id is updated.</summary>
    public Task SaveRegressionTestAsync(RegressionTestRecord test, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(test);
        if (test.Cadence <= TimeSpan.Zero)
        {
            throw ActException.FailClosed(ErrorCategory.Persistence,
                "The regression test cadence must be positive.",
                $"Regression test {test.RegressionTestId} declares a non-positive cadence.");
        }

        var nextRun = test.NextRunUtc != default
            ? test.NextRunUtc
            : (test.LastRunUtc ?? test.CreatedUtc) + test.Cadence;
        return WriteAsync(async (connection, transaction, token) =>
        {
            await using var command = Command(connection, transaction, """
                INSERT INTO regression_tests(regression_test_id, finding_id, assessment_id, name, description,
                                             suggested_severity, cadence_seconds, enabled, created_utc,
                                             last_run_utc, next_run_utc, recipe_json)
                VALUES($id, $finding_id, $assessment_id, $name, $description, $severity, $cadence_seconds,
                       $enabled, $created_utc, $last_run_utc, $next_run_utc, $recipe_json)
                ON CONFLICT(regression_test_id) DO UPDATE SET
                    finding_id = $finding_id, assessment_id = $assessment_id, name = $name,
                    description = $description, suggested_severity = $severity,
                    cadence_seconds = $cadence_seconds, enabled = $enabled,
                    last_run_utc = $last_run_utc, next_run_utc = $next_run_utc,
                    recipe_json = $recipe_json
                """);
            command.Parameters.AddWithValue("$id", test.RegressionTestId.ToString());
            command.Parameters.AddWithValue("$finding_id", test.FindingId.ToString());
            command.Parameters.AddWithValue("$assessment_id", test.OriginAssessmentId.ToString());
            command.Parameters.AddWithValue("$name", test.Name);
            command.Parameters.AddWithValue("$description", test.Description);
            command.Parameters.AddWithValue("$severity", (long)test.SuggestedSeverity);
            command.Parameters.AddWithValue("$cadence_seconds", test.Cadence.TotalSeconds);
            command.Parameters.AddWithValue("$enabled", Db(test.Enabled));
            command.Parameters.AddWithValue("$created_utc", Db(test.CreatedUtc));
            command.Parameters.AddWithValue("$last_run_utc", DbOptional(test.LastRunUtc));
            command.Parameters.AddWithValue("$next_run_utc", Db(nextRun));
            command.Parameters.AddWithValue("$recipe_json", DbOptional(test.RecipeJson));
            await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
        }, cancellationToken);
    }

    /// <summary>Returns one regression test or null when the identifier is unknown.</summary>
    public Task<RegressionTestRecord?> GetRegressionTestAsync(Guid regressionTestId, CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            command.CommandText = "SELECT * FROM regression_tests WHERE regression_test_id = $id";
            command.Parameters.AddWithValue("$id", regressionTestId.ToString());
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            return await reader.ReadAsync(token).ConfigureAwait(false) ? MapRegressionTest(reader) : null;
        }, cancellationToken);

    /// <summary>
    /// Returns the enabled regression tests for the given findings whose scheduled verification
    /// time (next_run_utc) has elapsed as of asOfUtc.
    /// </summary>
    public Task<IReadOnlyList<RegressionTestRecord>> ListDueRegressionsAsync(
        IReadOnlyList<Guid> findingIds, DateTimeOffset asOfUtc, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(findingIds);
        if (findingIds.Count == 0)
        {
            return Task.FromResult<IReadOnlyList<RegressionTestRecord>>([]);
        }

        return ReadAsync(async (command, token) =>
        {
            var parameters = new List<string>();
            for (var index = 0; index < findingIds.Count; index++)
            {
                var name = "$finding" + index;
                parameters.Add(name);
                command.Parameters.AddWithValue(name, findingIds[index].ToString());
            }

            command.CommandText =
                "SELECT * FROM regression_tests WHERE enabled = 1 AND finding_id IN ("
                + string.Join(", ", parameters)
                + ") AND next_run_utc <= $as_of ORDER BY next_run_utc ASC";
            command.Parameters.AddWithValue("$as_of", Db(asOfUtc));
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            var due = new List<RegressionTestRecord>();
            while (await reader.ReadAsync(token).ConfigureAwait(false))
            {
                due.Add(MapRegressionTest(reader));
            }

            return (IReadOnlyList<RegressionTestRecord>)due;
        }, cancellationToken);
    }

    /// <summary>
    /// Records one regression verification run and advances the test's schedule by its cadence.
    /// Fails closed when the test does not exist.
    /// </summary>
    public Task<RegressionTestRunRecord> RecordTestRunAsync(
        Guid regressionTestId,
        DateTimeOffset ranAtUtc,
        VerificationState result,
        string detail,
        CancellationToken cancellationToken = default) =>
        WriteAsync(async (connection, transaction, token) =>
        {
            double cadenceSeconds;
            await using (var query = Command(connection, transaction,
                "SELECT cadence_seconds FROM regression_tests WHERE regression_test_id = $id"))
            {
                query.Parameters.AddWithValue("$id", regressionTestId.ToString());
                var raw = await query.ExecuteScalarAsync(token).ConfigureAwait(false);
                if (raw is null || raw is DBNull)
                {
                    throw ActException.FailClosed(ErrorCategory.Persistence,
                        "The regression test does not exist.",
                        $"RecordTestRun found no regression test {regressionTestId}.");
                }

                cadenceSeconds = Convert.ToDouble(raw, System.Globalization.CultureInfo.InvariantCulture);
            }

            await using var insert = Command(connection, transaction, """
                INSERT INTO test_runs(regression_test_id, ran_utc, result, detail)
                VALUES($test_id, $ran_utc, $result, $detail)
                """);
            insert.Parameters.AddWithValue("$test_id", regressionTestId.ToString());
            insert.Parameters.AddWithValue("$ran_utc", Db(ranAtUtc));
            insert.Parameters.AddWithValue("$result", result.ToString());
            insert.Parameters.AddWithValue("$detail", detail);
            await insert.ExecuteNonQueryAsync(token).ConfigureAwait(false);

            await using var update = Command(connection, transaction, """
                UPDATE regression_tests
                SET last_run_utc = $ran_utc, next_run_utc = $next_run
                WHERE regression_test_id = $test_id
                """);
            update.Parameters.AddWithValue("$ran_utc", Db(ranAtUtc));
            update.Parameters.AddWithValue("$next_run", Db(ranAtUtc.AddSeconds(cadenceSeconds)));
            update.Parameters.AddWithValue("$test_id", regressionTestId.ToString());
            await update.ExecuteNonQueryAsync(token).ConfigureAwait(false);

            await using var identity = Command(connection, transaction, "SELECT last_insert_rowid()");
            var runId = Convert.ToInt64(
                await identity.ExecuteScalarAsync(token).ConfigureAwait(false),
                System.Globalization.CultureInfo.InvariantCulture);
            return new RegressionTestRunRecord(runId, regressionTestId, ranAtUtc, result, detail);
        }, cancellationToken);

    /// <summary>Returns every regression test originating from findings of one assessment.</summary>
    public Task<IReadOnlyList<RegressionTestRecord>> ListRegressionsForAssessmentAsync(
        Guid assessmentId, CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            command.CommandText = """
                SELECT r.regression_test_id, r.finding_id, r.assessment_id, r.name, r.description,
                       r.suggested_severity, r.cadence_seconds, r.enabled, r.created_utc, r.last_run_utc,
                       r.next_run_utc, r.recipe_json
                FROM regression_tests r
                JOIN findings f ON f.finding_id = r.finding_id
                WHERE f.assessment_id = $assessment_id
                ORDER BY r.created_utc ASC
                """;
            command.Parameters.AddWithValue("$assessment_id", assessmentId.ToString());
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            var tests = new List<RegressionTestRecord>();
            while (await reader.ReadAsync(token).ConfigureAwait(false))
            {
                tests.Add(MapRegressionTest(reader));
            }

            return (IReadOnlyList<RegressionTestRecord>)tests;
        }, cancellationToken);

    /// <summary>
    /// Returns the stored regression test for one finding, or null when none exists. Used to
    /// upsert by finding so repeated captures update one durable test instead of piling rows.
    /// </summary>
    public Task<RegressionTestRecord?> GetRegressionTestForFindingAsync(Guid findingId, CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            command.CommandText = "SELECT * FROM regression_tests WHERE finding_id = $finding ORDER BY created_utc ASC LIMIT 1";
            command.Parameters.AddWithValue("$finding", findingId.ToString());
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            return await reader.ReadAsync(token).ConfigureAwait(false) ? MapRegressionTest(reader) : null;
        }, cancellationToken);

    /// <summary>
    /// Lists stored regression tests newest-schedule-first across every assessment. The console
    /// and 'regression list' read exclusively through this; the limit is a hard page bound.
    /// </summary>
    public Task<IReadOnlyList<RegressionTestRecord>> ListRegressionTestsAsync(int limit, CancellationToken cancellationToken = default)
    {
        if (limit < 1)
        {
            throw ActException.FailClosed(ErrorCategory.Persistence,
                "The regression test listing requires a positive page size.",
                $"ListRegressionTests called with limit {limit}.");
        }

        return ReadAsync(async (command, token) =>
        {
            command.CommandText =
                "SELECT * FROM regression_tests ORDER BY enabled DESC, next_run_utc ASC LIMIT $limit";
            command.Parameters.AddWithValue("$limit", limit);
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            var tests = new List<RegressionTestRecord>();
            while (await reader.ReadAsync(token).ConfigureAwait(false))
            {
                tests.Add(MapRegressionTest(reader));
            }

            return (IReadOnlyList<RegressionTestRecord>)tests;
        }, cancellationToken);
    }

    /// <summary>Returns the most recent verification runs of one regression test, newest first.</summary>
    public Task<IReadOnlyList<RegressionTestRunRecord>> ListTestRunsAsync(
        Guid regressionTestId, int limit, CancellationToken cancellationToken = default)
    {
        if (limit < 1)
        {
            throw ActException.FailClosed(ErrorCategory.Persistence,
                "The regression run listing requires a positive page size.",
                $"ListTestRuns called with limit {limit}.");
        }

        return ReadAsync(async (command, token) =>
        {
            command.CommandText =
                "SELECT * FROM test_runs WHERE regression_test_id = $id ORDER BY ran_utc DESC, test_run_id DESC LIMIT $limit";
            command.Parameters.AddWithValue("$id", regressionTestId.ToString());
            command.Parameters.AddWithValue("$limit", limit);
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            var runs = new List<RegressionTestRunRecord>();
            while (await reader.ReadAsync(token).ConfigureAwait(false))
            {
                runs.Add(MapTestRun(reader));
            }

            return (IReadOnlyList<RegressionTestRunRecord>)runs;
        }, cancellationToken);
    }

    private static RegressionTestRunRecord MapTestRun(SqliteDataReader row) => new(
        TestRunId: row.IntOf("test_run_id"),
        RegressionTestId: row.GuidOf("regression_test_id"),
        RanAtUtc: row.TimeOf("ran_utc"),
        Result: ActValues.Enum<VerificationState>(row.Str("result"), "result"),
        Detail: row.Str("detail"));

    /// <summary>
    /// Enables or disables one regression test in place. Disabling keeps the row and its run
    /// history - an operator pausing a cadence must not lose the evidence of past verdicts.
    /// Fails closed when the test does not exist.
    /// </summary>
    public Task SetRegressionTestEnabledAsync(Guid regressionTestId, bool enabled, CancellationToken cancellationToken = default) =>
        WriteAsync(async (connection, transaction, token) =>
        {
            await using var command = Command(connection, transaction,
                "UPDATE regression_tests SET enabled = $enabled WHERE regression_test_id = $id");
            command.Parameters.AddWithValue("$enabled", Db(enabled));
            command.Parameters.AddWithValue("$id", regressionTestId.ToString());
            var touched = await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
            if (touched == 0)
            {
                throw ActException.FailClosed(ErrorCategory.Persistence,
                    "The regression test to enable or disable does not exist.",
                    $"SetRegressionTestEnabled found no regression test {regressionTestId}.");
            }
        }, cancellationToken);

    private static RegressionTestRecord MapRegressionTest(SqliteDataReader row) => new(
        RegressionTestId: row.GuidOf("regression_test_id"),
        OriginAssessmentId: row.GuidOf("assessment_id"),
        FindingId: row.GuidOf("finding_id"),
        Name: row.Str("name"),
        Description: row.Str("description"),
        SuggestedSeverity: ActValues.Enum<Severity>(row.IntOf("suggested_severity"), "suggested_severity"),
        Cadence: TimeSpan.FromSeconds(row.RealOf("cadence_seconds")),
        Enabled: row.BoolOf("enabled"),
        CreatedUtc: row.TimeOf("created_utc"),
        LastRunUtc: row.TimeOrNull("last_run_utc"),
        NextRunUtc: row.TimeOf("next_run_utc"),
        RecipeJson: row.StrOrNull("recipe_json"));

    // ---------- advisory feeds ----------

    /// <summary>Persists one feed source definition; an existing name is updated.</summary>
    public Task UpsertFeedAsync(FeedRecord feed, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(feed);
        if (string.IsNullOrWhiteSpace(feed.Name))
        {
            throw ActException.FailClosed(ErrorCategory.Persistence,
                "The feed name is missing.",
                "Feed records require a non-empty name.");
        }

        return WriteAsync(async (connection, transaction, token) =>
        {
            await using var command = Command(connection, transaction, """
                INSERT INTO feeds(name, kind, endpoint_or_path, enabled, updated_utc)
                VALUES($name, $kind, $endpoint_or_path, $enabled, $updated_utc)
                ON CONFLICT(name) DO UPDATE SET
                    kind = $kind, endpoint_or_path = $endpoint_or_path, enabled = $enabled,
                    updated_utc = $updated_utc
                """);
            command.Parameters.AddWithValue("$name", feed.Name);
            command.Parameters.AddWithValue("$kind", feed.Kind.ToString());
            command.Parameters.AddWithValue("$endpoint_or_path", feed.EndpointOrPath);
            command.Parameters.AddWithValue("$enabled", Db(feed.Enabled));
            command.Parameters.AddWithValue("$updated_utc", Db(feed.UpdatedUtc));
            await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
        }, cancellationToken);
    }

    /// <summary>
    /// Records one retrieval generation of a feed. When marked current, all earlier generations of
    /// that feed are demoted so freshness claims stay honest.
    /// </summary>
    public Task<FeedVersionRecord> RecordFeedVersionAsync(
        string feedName,
        DateTimeOffset retrievedUtc,
        string metadataHash,
        bool isCurrent,
        string note,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(feedName) || string.IsNullOrWhiteSpace(metadataHash))
        {
            throw ActException.FailClosed(ErrorCategory.Persistence,
                "The feed version is missing required fields.",
                "Recording a feed version requires a feed name and a metadata hash.");
        }

        return WriteAsync(async (connection, transaction, token) =>
        {
            await using var insert = Command(connection, transaction, """
                INSERT INTO feed_versions(feed_name, retrieved_utc, metadata_hash, is_current, note)
                VALUES($feed_name, $retrieved_utc, $metadata_hash, $is_current, $note)
                """);
            insert.Parameters.AddWithValue("$feed_name", feedName);
            insert.Parameters.AddWithValue("$retrieved_utc", Db(retrievedUtc));
            insert.Parameters.AddWithValue("$metadata_hash", metadataHash);
            insert.Parameters.AddWithValue("$is_current", Db(isCurrent));
            insert.Parameters.AddWithValue("$note", note);
            await insert.ExecuteNonQueryAsync(token).ConfigureAwait(false);

            if (isCurrent)
            {
                await using var demote = Command(connection, transaction,
                    "UPDATE feed_versions SET is_current = 0 WHERE feed_name = $feed_name AND retrieved_utc <> $retrieved_utc");
                demote.Parameters.AddWithValue("$feed_name", feedName);
                demote.Parameters.AddWithValue("$retrieved_utc", Db(retrievedUtc));
                await demote.ExecuteNonQueryAsync(token).ConfigureAwait(false);
            }

            return new FeedVersionRecord(feedName, retrievedUtc, metadataHash, isCurrent, note);
        }, cancellationToken);
    }

    /// <summary>
    /// Returns the current generation of one feed, falling back to its newest stored generation,
    /// or null when nothing was ever recorded.
    /// </summary>
    public Task<FeedVersionRecord?> LatestFeedVersionAsync(string feedName, CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            command.CommandText = """
                SELECT feed_name, retrieved_utc, metadata_hash, is_current, note
                FROM feed_versions WHERE feed_name = $feed_name AND is_current = 1
                LIMIT 1
                """;
            command.Parameters.AddWithValue("$feed_name", feedName);
            FeedVersionRecord? current = null;
            await using (var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false))
            {
                if (await reader.ReadAsync(token).ConfigureAwait(false))
                {
                    current = MapFeedVersion(reader);
                }
            }

            if (current is not null)
            {
                return current;
            }

            command.Parameters.Clear();
            command.CommandText = """
                SELECT feed_name, retrieved_utc, metadata_hash, is_current, note
                FROM feed_versions WHERE feed_name = $feed_name
                ORDER BY retrieved_utc DESC LIMIT 1
                """;
            command.Parameters.AddWithValue("$feed_name", feedName);
            await using var fallbackReader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            return await fallbackReader.ReadAsync(token).ConfigureAwait(false) ? MapFeedVersion(fallbackReader) : null;
        }, cancellationToken);

    private static FeedVersionRecord MapFeedVersion(SqliteDataReader row) => new(
        FeedName: row.Str("feed_name"),
        RetrievedUtc: row.TimeOf("retrieved_utc"),
        MetadataHash: row.Str("metadata_hash"),
        IsCurrent: row.BoolOf("is_current"),
        Note: row.Str("note"));

    // ---------- planning exclusions ----------

    /// <summary>
    /// Persists one assessment's planning exclusions in ONE transaction: every check the
    /// orchestrator kept out of the execution plan, exactly as decided, with its deterministic
    /// reason. Rows are plain inserts - a repeated save for the same assessment would duplicate
    /// rows visibly rather than silently overwrite history. Fails closed on empty identifiers.
    /// </summary>
    public Task SavePlanExclusionsAsync(
        IReadOnlyList<PlanExclusionRecord> exclusions, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(exclusions);
        if (exclusions.Count == 0)
        {
            throw ActException.FailClosed(ErrorCategory.Persistence,
                "The planning-exclusion batch is empty.",
                "SavePlanExclusions requires at least one recorded exclusion; an empty plan is simply not saved.");
        }

        foreach (var exclusion in exclusions)
        {
            if (exclusion.ExclusionId == Guid.Empty || string.IsNullOrWhiteSpace(exclusion.CheckId)
                || string.IsNullOrWhiteSpace(exclusion.ReasonCode) || string.IsNullOrWhiteSpace(exclusion.Detail))
            {
                throw ActException.FailClosed(ErrorCategory.Persistence,
                    "A planning exclusion is missing required fields.",
                    $"Exclusion {exclusion.ExclusionId} requires a non-empty check id, reason code, and detail.");
            }
        }

        return WriteAsync(async (connection, transaction, token) =>
        {
            const string sql = """
                INSERT INTO plan_exclusions(exclusion_id, assessment_id, check_id, reason_code, detail, excluded_utc)
                VALUES($id, $assessment_id, $check_id, $reason_code, $detail, $excluded_utc)
                """;
            foreach (var exclusion in exclusions)
            {
                await using var command = Command(connection, transaction, sql);
                command.Parameters.AddWithValue("$id", exclusion.ExclusionId.ToString());
                command.Parameters.AddWithValue("$assessment_id", exclusion.AssessmentId.ToString());
                command.Parameters.AddWithValue("$check_id", exclusion.CheckId);
                command.Parameters.AddWithValue("$reason_code", exclusion.ReasonCode);
                command.Parameters.AddWithValue("$detail", exclusion.Detail);
                command.Parameters.AddWithValue("$excluded_utc", Db(exclusion.ExcludedUtc));
                await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
            }
        }, cancellationToken);
    }

    /// <summary>
    /// Lists persisted planning exclusions, newest first, optionally scoped to one assessment.
    /// This is the read surface that turns "registered check with no recorded execution" from a
    /// mystery into a stored fact - or, when no rows exist for a pre-v4 assessment, an honest gap.
    /// </summary>
    public Task<IReadOnlyList<PlanExclusionRecord>> ListPlanExclusionsAsync(
        Guid? assessmentId = null,
        int limit = 10_000,
        CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            RequirePositive(limit, "limit");
            if (assessmentId is { } assessment)
            {
                command.CommandText =
                    "SELECT * FROM plan_exclusions WHERE assessment_id = $assessment "
                    + "ORDER BY excluded_utc DESC, check_id ASC LIMIT $limit";
                command.Parameters.AddWithValue("$assessment", assessment.ToString());
            }
            else
            {
                command.CommandText =
                    "SELECT * FROM plan_exclusions ORDER BY excluded_utc DESC, check_id ASC LIMIT $limit";
            }

            command.Parameters.AddWithValue("$limit", (long)limit);
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            var results = new List<PlanExclusionRecord>();
            while (await reader.ReadAsync(token).ConfigureAwait(false))
            {
                results.Add(MapPlanExclusion(reader));
            }

            return (IReadOnlyList<PlanExclusionRecord>)results;
        }, cancellationToken);

    private static PlanExclusionRecord MapPlanExclusion(SqliteDataReader row) => new(
        ExclusionId: row.GuidOf("exclusion_id"),
        AssessmentId: row.GuidOf("assessment_id"),
        CheckId: row.Str("check_id"),
        ReasonCode: row.Str("reason_code"),
        Detail: row.Str("detail"),
        ExcludedUtc: row.TimeOf("excluded_utc"));

    // ---------- dashboard ----------

    /// <summary>Computes operator dashboard aggregates exclusively from persisted rows via one SQL statement.</summary>
    public Task<DashboardMetricsSnapshot> DashboardAsync(CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            command.CommandText = $"""
                SELECT
                  (SELECT COUNT(*) FROM assessments) AS assessments_total,
                  (SELECT COUNT(*) FROM assets) AS assets_total,
                  (SELECT COUNT(*) FROM services) AS services_total,
                  (SELECT COUNT(*) FROM findings WHERE status IN {OpenStatuses}) AS findings_open,
                  (SELECT COUNT(*) FROM findings WHERE status IN {OpenStatuses} AND severity >= 3)
                      AS findings_open_critical_or_high,
                  (SELECT COUNT(*) FROM findings WHERE status = 'Confirmed') AS findings_confirmed,
                  (SELECT COUNT(*) FROM findings WHERE status = 'Remediated') AS findings_remediated,
                  (SELECT COUNT(*) FROM findings WHERE status = 'Regressed') AS findings_regressed,
                  (SELECT COUNT(*) FROM check_runs) AS checks_executed,
                  (SELECT COUNT(*) FROM check_runs WHERE status IN ('Failed_FailedClosed','TimedOut'))
                      AS checks_failed,
                  (SELECT COUNT(*) FROM findings WHERE status = 'FalsePositive') AS findings_false_positive,
                  (SELECT COALESCE(AVG(total_duration_seconds), 0.0) / 60.0 FROM scan_metrics)
                      AS average_scan_minutes,
                  (SELECT COALESCE(SUM(requests_sent), 0) FROM scan_metrics) AS requests_total,
                  (SELECT COALESCE(MAX(priority_score), 0) FROM findings WHERE status IN {OpenStatuses})
                      AS current_risk_score
                """;
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            await reader.ReadAsync(token).ConfigureAwait(false);
            return new DashboardMetricsSnapshot(
                AssessmentsTotal: (int)reader.IntOf("assessments_total"),
                AssetsAssessed: (int)reader.IntOf("assets_total"),
                ServicesObserved: (int)reader.IntOf("services_total"),
                FindingsOpen: (int)reader.IntOf("findings_open"),
                FindingsCriticalOrHigh: (int)reader.IntOf("findings_open_critical_or_high"),
                FindingsConfirmed: (int)reader.IntOf("findings_confirmed"),
                FindingsRemediated: (int)reader.IntOf("findings_remediated"),
                RegressionsDetected: (int)reader.IntOf("findings_regressed"),
                ChecksExecuted: reader.IntOf("checks_executed"),
                ChecksFailed: reader.IntOf("checks_failed"),
                FalsePositives: (int)reader.IntOf("findings_false_positive"),
                AverageScanDurationMinutes: reader.RealOf("average_scan_minutes"),
                RequestCount: reader.IntOf("requests_total"),
                CurrentRiskScore: reader.RealOf("current_risk_score"),
                ComputedUtc: DateTimeOffset.UtcNow);
        }, cancellationToken);

    // ---------- retention internals ----------

    /// <summary>
    /// Lists every stored scope definition, one row per scope id. The scope_id column is the
    /// authority: a stored definition whose JSON disagrees with its column fails closed.
    /// </summary>
    public Task<IReadOnlyList<ScopeDefinition>> ListScopeDefinitionsAsync(CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            command.CommandText = "SELECT scope_id, definition_json FROM scopes ORDER BY scope_id";
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            var scopes = new List<ScopeDefinition>();
            while (await reader.ReadAsync(token).ConfigureAwait(false))
            {
                var storedId = reader.GuidOf("scope_id");
                var definition = ActJson.Deserialize<ScopeDefinition>(reader.Str("definition_json"), "scopes.definition_json");
                if (definition.ScopeId != storedId)
                {
                    throw ActException.FailClosed(ErrorCategory.Persistence,
                        "The stored scope definition does not match its record.",
                        $"Scope row {storedId} carries definition {definition.ScopeId}.");
                }

                scopes.Add(definition);
            }

            return (IReadOnlyList<ScopeDefinition>)scopes;
        }, cancellationToken);

    /// <summary>Counts evidence rows of one scope captured strictly before the cutoff.</summary>
    public Task<long> CountExpiredEvidenceAsync(
        Guid scopeId, DateTimeOffset cutoffUtc, CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            command.CommandText = """
                SELECT COUNT(*) AS expired
                FROM evidence e
                JOIN findings f ON f.finding_id = e.finding_id
                JOIN assessments a ON a.assessment_id = f.assessment_id
                WHERE a.scope_id = $scope AND e.captured_utc < $cutoff
                """;
            command.Parameters.AddWithValue("$scope", scopeId.ToString());
            command.Parameters.AddWithValue("$cutoff", Db(cutoffUtc));
            var raw = await command.ExecuteScalarAsync(token).ConfigureAwait(false);
            return Convert.ToInt64(raw, System.Globalization.CultureInfo.InvariantCulture);
        }, cancellationToken);

    /// <summary>
    /// Deletes, in ONE transaction, every evidence row that each scope's own cutoff expires.
    /// Evidence exactly at its boundary is retained; only strictly older rows are removed.
    /// Returns one deleted-row count per entry, in entry order.
    /// </summary>
    public Task<IReadOnlyList<long>> DeleteExpiredEvidenceForScopesAsync(
        IReadOnlyList<(Guid ScopeId, DateTimeOffset CutoffUtc)> entries,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(entries);
        return WriteAsync(async (connection, transaction, token) =>
        {
            const string sql = """
                DELETE FROM evidence
                WHERE evidence_id IN (
                    SELECT e.evidence_id
                    FROM evidence e
                    JOIN findings f ON f.finding_id = e.finding_id
                    JOIN assessments a ON a.assessment_id = f.assessment_id
                    WHERE a.scope_id = $scope AND e.captured_utc < $cutoff)
                """;
            var deletedCounts = new List<long>(entries.Count);
            foreach (var (scopeId, cutoffUtc) in entries)
            {
                await using var command = Command(connection, transaction, sql);
                command.Parameters.AddWithValue("$scope", scopeId.ToString());
                command.Parameters.AddWithValue("$cutoff", Db(cutoffUtc));
                deletedCounts.Add(await command.ExecuteNonQueryAsync(token).ConfigureAwait(false));
            }

            return (IReadOnlyList<long>)deletedCounts;
        }, cancellationToken);
    }

    internal async Task<long> DeleteEvidenceCoreAsync(TimeSpan age, bool secureWipe, CancellationToken cancellationToken)
    {
        ThrowIfUnready();
        if (age <= TimeSpan.Zero)
        {
            throw ActException.FailClosed(ErrorCategory.Persistence,
                "The retention period must be positive.",
                $"Evidence retention age must exceed zero; received {age}.");
        }

        var cutoffUtc = DateTimeOffset.UtcNow - age;
        var deleted = await WriteAsync(async (connection, transaction, token) =>
        {
            await using var command = Command(connection, transaction,
                "DELETE FROM evidence WHERE captured_utc < $cutoff");
            command.Parameters.AddWithValue("$cutoff", Db(cutoffUtc));
            return (long)await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
        }, cancellationToken).ConfigureAwait(false);

        if (secureWipe)
        {
            await CheckpointAsync(cancellationToken).ConfigureAwait(false);
        }

        return deleted;
    }

    internal async Task CheckpointAsync(CancellationToken cancellationToken)
    {
        ThrowIfUnready();
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_walEnabled)
            {
                await ExecutePragmaAsync(Writer, "PRAGMA wal_checkpoint(TRUNCATE);", cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }
}
