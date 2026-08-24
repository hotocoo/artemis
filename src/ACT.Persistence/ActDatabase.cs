using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using ACT.Contracts;
using Microsoft.Data.Sqlite;

namespace ACT.Persistence;

/// <summary>
/// SQLite-backed persistence for assessments, findings, evidence, the audit hash chain, schedules,
/// baselines, advisory feeds, and engine configuration. Writes serialize through one connection
/// guarded by an async write lock; readers use short-lived connections.
/// </summary>
public sealed partial class ActDatabase : IAsyncDisposable
{
    /// <summary>Previous-hash sentinel for the first audit entry ever appended.</summary>
    public const string GenesisAuditHash = "GENESIS";

    private const string OpenStatuses = "('New','Confirmed','Reopened','Regressed')";

    private readonly string _connectionString;
    private readonly string _databasePath;
    private readonly bool _walEnabled;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private SqliteConnection? _writeConnection;
    private bool _initialized;
    private bool _disposed;

    /// <summary>Creates a database bound to one SQLite file. Call InitializeAsync before use.</summary>
    public ActDatabase(string databasePath, StorageOptions options)
    {
        if (string.IsNullOrWhiteSpace(databasePath))
        {
            throw ActException.FailClosed(ErrorCategory.Persistence,
                "The database path is missing.",
                "ActDatabase requires a non-empty database path.");
        }

        ArgumentNullException.ThrowIfNull(options);
        _databasePath = Path.GetFullPath(databasePath);
        _walEnabled = options.WalEnabled;
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = _databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            ForeignKeys = true
        }.ToString();
    }

    /// <summary>The absolute path of the SQLite database file.</summary>
    public string DatabasePath => _databasePath;

    /// <summary>Applies pending migrations. Idempotent: repeated calls verify the applied schema and change nothing.</summary>
    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var directory = Path.GetDirectoryName(_databasePath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            if (_writeConnection is null)
            {
                _writeConnection = new SqliteConnection(_connectionString);
                await _writeConnection.OpenAsync(cancellationToken).ConfigureAwait(false);
            }

            await ApplyCorePragmasAsync(_writeConnection, cancellationToken).ConfigureAwait(false);
            if (_walEnabled)
            {
                await ExecutePragmaAsync(_writeConnection, "PRAGMA journal_mode=WAL;", cancellationToken)
                    .ConfigureAwait(false);
            }

            await MigrateAsync(cancellationToken).ConfigureAwait(false);
            _initialized = true;
        }
        finally
        {
            _writeLock.Release();
        }
    }

    /// <summary>Releases the pooled write connection. The instance is unusable afterwards.</summary>
    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        await _writeLock.WaitAsync().ConfigureAwait(false);
        try
        {
            if (_writeConnection is not null)
            {
                SqliteConnection.ClearPool(_writeConnection);
                await _writeConnection.DisposeAsync().ConfigureAwait(false);
                _writeConnection = null;
            }
        }
        finally
        {
            _writeLock.Release();
            _writeLock.Dispose();
        }
    }

    // ---------- lifecycle plumbing ----------

    private SqliteConnection Writer =>
        _writeConnection
        ?? throw ActException.FailClosed(ErrorCategory.Persistence,
            "The local database is not ready.",
            "Write connection requested while InitializeAsync has not completed.");

    private void ThrowIfDisposed() =>
        ObjectDisposedException.ThrowIf(_disposed, nameof(ActDatabase));

    private void ThrowIfUnready()
    {
        ThrowIfDisposed();
        if (!_initialized)
        {
            throw ActException.FailClosed(ErrorCategory.Persistence,
                "The local database is not ready.",
                "Operation attempted before InitializeAsync completed.");
        }
    }

    private static async Task ApplyCorePragmasAsync(SqliteConnection connection, CancellationToken cancellationToken)
    {
        await ExecutePragmaAsync(connection, "PRAGMA foreign_keys=ON;", cancellationToken).ConfigureAwait(false);
        await ExecutePragmaAsync(connection, "PRAGMA synchronous=NORMAL;", cancellationToken).ConfigureAwait(false);
        await ExecutePragmaAsync(connection, "PRAGMA busy_timeout=3000;", cancellationToken).ConfigureAwait(false);
    }

    private static async Task ExecutePragmaAsync(
        SqliteConnection connection, string pragma, CancellationToken cancellationToken)
    {
        await using var command = connection.CreateCommand();
        command.CommandText = pragma;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task MigrateAsync(CancellationToken cancellationToken)
    {
        var connection = Writer;

        await using (var bootstrap = connection.CreateCommand())
        {
            bootstrap.CommandText = """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version     INTEGER PRIMARY KEY,
                    name        TEXT NOT NULL,
                    checksum    TEXT NOT NULL,
                    applied_utc TEXT NOT NULL
                )
                """;
            await bootstrap.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }

        var applied = new Dictionary<int, string>();
        await using (var query = connection.CreateCommand())
        {
            query.CommandText = "SELECT version, checksum FROM schema_migrations ORDER BY version;";
            await using var reader = await query.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                applied[Convert.ToInt32(reader.GetValue(0), System.Globalization.CultureInfo.InvariantCulture)] =
                    reader.GetString(1);
            }
        }

        // Applied versions must form an unbroken prefix of this build's migration order and every
        // applied checksum must match the shipped script byte-for-byte. Gaps mean a database from
        // a different lineage; extra versions mean a newer build wrote it. Either way the engine
        // refuses to guess - schema drift is how stored evidence gets silently corrupted.
        foreach (var migration in Migrations.Ordered)
        {
            if (applied.Remove(migration.Version, out var recordedChecksum))
            {
                if (!string.Equals(recordedChecksum, migration.Checksum, StringComparison.Ordinal))
                {
                    throw ActException.FailClosed(ErrorCategory.Persistence,
                        "The stored database schema does not match this build.",
                        $"Checksum mismatch for migration {migration.Version}: recorded {recordedChecksum}."
                        + $" Expected {migration.Checksum}.");
                }

                continue;
            }

            if (applied.Count > 0)
            {
                throw ActException.FailClosed(ErrorCategory.Persistence,
                    "The database was created by an incompatible engine version.",
                    "Applied migrations [" + string.Join(", ", applied.Keys.OrderBy(v => v))
                    + "] are not a prefix of this build's order.");
            }

            await ApplyMigrationAsync(connection, migration, cancellationToken).ConfigureAwait(false);
        }

        if (applied.Count > 0)
        {
            throw ActException.FailClosed(ErrorCategory.Persistence,
                "The database was created by a newer engine version.",
                "Unknown applied migrations [" + string.Join(", ", applied.Keys.OrderBy(v => v))
                + "]; downgrade would corrupt them.");
        }
    }

    private async Task ApplyMigrationAsync(
        SqliteConnection connection,
        (int Version, string Name, string Checksum, string[] Statements) migration,
        CancellationToken cancellationToken)
    {
        await using var transaction =
            await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            foreach (var statement in migration.Statements)
            {
                await using var command = connection.CreateCommand();
                command.Transaction = (SqliteTransaction)transaction;
                command.CommandText = statement;
                await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            }

            await using var record = connection.CreateCommand();
            record.Transaction = (SqliteTransaction)transaction;
            record.CommandText = """
                INSERT INTO schema_migrations(version, name, checksum, applied_utc)
                VALUES($version, $name, $checksum, $applied_utc)
                """;
            record.Parameters.AddWithValue("$version", migration.Version);
            record.Parameters.AddWithValue("$name", migration.Name);
            record.Parameters.AddWithValue("$checksum", migration.Checksum);
            record.Parameters.AddWithValue("$applied_utc", ActTime.Write(DateTimeOffset.UtcNow));
            await record.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
            throw;
        }
    }

    private async Task WriteAsync(
        Func<SqliteConnection, DbTransaction, CancellationToken, Task> action,
        CancellationToken cancellationToken) =>
        await WriteAsync<object?>(async (connection, transaction, token) =>
        {
            await action(connection, transaction, token).ConfigureAwait(false);
            return null;
        }, cancellationToken).ConfigureAwait(false);

    private async Task<T> WriteAsync<T>(
        Func<SqliteConnection, DbTransaction, CancellationToken, Task<T>> action,
        CancellationToken cancellationToken)
    {
        ThrowIfUnready();
        await _writeLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        DbTransaction? transaction = null;
        try
        {
            var connection = Writer;
            transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
            var result = await action(connection, transaction, cancellationToken).ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            return result;
        }
        catch (SqliteException exception)
        {
            await RollbackQuietlyAsync(transaction).ConfigureAwait(false);
            throw FailClosed(exception);
        }
        catch
        {
            await RollbackQuietlyAsync(transaction).ConfigureAwait(false);
            throw;
        }
        finally
        {
            if (transaction is not null)
            {
                await transaction.DisposeAsync().ConfigureAwait(false);
            }

            _writeLock.Release();
        }
    }

    private async Task<T> ReadAsync<T>(
        Func<SqliteCommand, CancellationToken, Task<T>> action,
        CancellationToken cancellationToken)
    {
        ThrowIfUnready();
        await using var connection = new SqliteConnection(_connectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await ApplyCorePragmasAsync(connection, cancellationToken).ConfigureAwait(false);
        await using var command = connection.CreateCommand();
        try
        {
            return await action(command, cancellationToken).ConfigureAwait(false);
        }
        catch (SqliteException exception)
        {
            throw FailClosed(exception);
        }
    }

    private static SqliteCommand Command(SqliteConnection connection, DbTransaction? transaction, string sql)
    {
        var command = connection.CreateCommand();
        command.CommandText = sql;
        if (transaction is not null)
        {
            command.Transaction = (SqliteTransaction)transaction;
        }

        return command;
    }

    private static async Task RollbackQuietlyAsync(DbTransaction? transaction)
    {
        if (transaction is null)
        {
            return;
        }

        // Best-effort unwind: the original exception must reach the caller untouched.
        try
        {
            await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
        }
        catch (SqliteException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private static ActException FailClosed(SqliteException exception) =>
        ActException.FailClosed(ErrorCategory.Persistence,
            "A local database operation failed.",
            $"SQLite error {exception.SqliteErrorCode} ({exception.ErrorCode}): {exception.Message}",
            exception);

    private static object Db(bool value) => value ? 1L : 0L;

    private static object Db(DateTimeOffset value) => ActTime.Write(value);

    private static object DbOptional(string? value) => value ?? (object)DBNull.Value;

    private static object DbOptional(DateTimeOffset? value) =>
        value is null ? DBNull.Value : ActTime.Write(value.Value);

    internal static AuditEvent MapAudit(SqliteDataReader row)
    {
        return new AuditEvent(
            Sequence: row.IntOf("sequence"),
            TimestampUtc: row.TimeOf("timestamp_utc"),
            Actor: row.Str("actor"),
            Action: row.Str("action"),
            ObjectType: row.Str("object_type"),
            ObjectId: row.Str("object_id"),
            Result: row.Str("result"),
            Correlation: new CorrelationId(ActValues.Guid(row.Str("correlation"), "correlation")),
            PreviousEventHash: row.Str("previous_hash"),
            EventHash: row.Str("event_hash"));
    }

    internal static string AuditHash(string previousHash, DateTimeOffset timestampUtc, AuditDraft draft)
    {
        var canonical = string.Join('|',
            previousHash,
            ActTime.Write(timestampUtc),
            draft.Actor,
            draft.Action,
            draft.ObjectType,
            draft.ObjectId,
            draft.Result,
            draft.Correlation.ToString());
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    // ---------- assessments and scopes ----------

    /// <summary>Persists one assessment together with its frozen scope definition.</summary>
    public Task CreateAssessmentAsync(
        AssessmentRecord assessment, ScopeDefinition scope, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(assessment);
        ArgumentNullException.ThrowIfNull(scope);
        if (scope.AssessmentId != assessment.AssessmentId || scope.ScopeId != assessment.ScopeId)
        {
            throw ActException.FailClosed(ErrorCategory.Persistence,
                "The assessment and its scope do not belong together.",
                $"Assessment {assessment.AssessmentId}/scope {assessment.ScopeId} conflicts with scope record "
                + $"{scope.ScopeId}/assessment {scope.AssessmentId}.");
        }

        return WriteAsync(async (connection, transaction, token) =>
        {
            await InsertAssessmentAsync(connection, transaction, assessment, token).ConfigureAwait(false);
            // Scheduled fires reuse one frozen scope id across fresh assessment ids; the scope row
            // must upsert (not insert) or every second fire of a schedule fails on the primary key.
            await using var command = Command(connection, transaction, """
                INSERT INTO scopes(scope_id, assessment_id, definition_json)
                VALUES($scope_id, $assessment_id, $definition_json)
                ON CONFLICT(scope_id) DO UPDATE SET
                    assessment_id = $assessment_id,
                    definition_json = $definition_json
                """);
            command.Parameters.AddWithValue("$scope_id", scope.ScopeId.ToString());
            command.Parameters.AddWithValue("$assessment_id", assessment.AssessmentId.ToString());
            command.Parameters.AddWithValue("$definition_json", ActJson.Serialize(scope));
            await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
        }, cancellationToken);
    }

    /// <summary>Transitions the lifecycle state of one assessment. Fails closed when it does not exist.</summary>
    public Task UpdateAssessmentStateAsync(
        Guid assessmentId, AssessmentRunState state, CancellationToken cancellationToken = default) =>
        WriteAsync(async (connection, transaction, token) =>
        {
            await using var command = Command(connection, transaction,
                "UPDATE assessments SET state = $state WHERE assessment_id = $id");
            command.Parameters.AddWithValue("$state", state.ToString());
            command.Parameters.AddWithValue("$id", assessmentId.ToString());
            var changes = await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
            RequireRows(changes, $"assessment {assessmentId}", "state update");
        }, cancellationToken);

    /// <summary>Returns one assessment or null when the identifier is unknown.</summary>
    public Task<AssessmentRecord?> GetAssessmentAsync(Guid assessmentId, CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            command.CommandText = "SELECT * FROM assessments WHERE assessment_id = $id";
            command.Parameters.AddWithValue("$id", assessmentId.ToString());
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            return await reader.ReadAsync(token).ConfigureAwait(false) ? MapAssessment(reader) : null;
        }, cancellationToken);

    /// <summary>Returns up to limit assessments, newest first.</summary>
    public Task<IReadOnlyList<AssessmentRecord>> ListAssessmentsAsync(int limit, CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            RequirePositive(limit, "limit");
            command.CommandText = "SELECT * FROM assessments ORDER BY created_utc DESC LIMIT $limit";
            command.Parameters.AddWithValue("$limit", (long)limit);
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            var results = new List<AssessmentRecord>();
            while (await reader.ReadAsync(token).ConfigureAwait(false))
            {
                results.Add(MapAssessment(reader));
            }

            return (IReadOnlyList<AssessmentRecord>)results;
        }, cancellationToken);

    private static async Task InsertAssessmentAsync(
        SqliteConnection connection, DbTransaction transaction, AssessmentRecord assessment, CancellationToken token)
    {
        await using var command = Command(connection, transaction, """
            INSERT INTO assessments(assessment_id, scope_id, name, state, created_utc, started_utc, completed_utc,
                                     operator_identity, organization)
            VALUES($id, $scope_id, $name, $state, $created_utc, $started_utc, $completed_utc, $operator, $organization)
            """);
        command.Parameters.AddWithValue("$id", assessment.AssessmentId.ToString());
        command.Parameters.AddWithValue("$scope_id", assessment.ScopeId.ToString());
        command.Parameters.AddWithValue("$name", assessment.Name);
        command.Parameters.AddWithValue("$state", assessment.State.ToString());
        command.Parameters.AddWithValue("$created_utc", Db(assessment.CreatedUtc));
        command.Parameters.AddWithValue("$started_utc", DbOptional(assessment.StartedUtc));
        command.Parameters.AddWithValue("$completed_utc", DbOptional(assessment.CompletedUtc));
        command.Parameters.AddWithValue("$operator", assessment.OperatorIdentity);
        command.Parameters.AddWithValue("$organization", assessment.Organization);
        await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
    }

    private static AssessmentRecord MapAssessment(SqliteDataReader row) => new(
        AssessmentId: row.GuidOf("assessment_id"),
        ScopeId: row.GuidOf("scope_id"),
        Name: row.Str("name"),
        State: ActValues.Enum<AssessmentRunState>(row.Str("state"), "state"),
        CreatedUtc: row.TimeOf("created_utc"),
        StartedUtc: row.TimeOrNull("started_utc"),
        CompletedUtc: row.TimeOrNull("completed_utc"),
        OperatorIdentity: row.Str("operator_identity"),
        Organization: row.Str("organization"));

    // ---------- assets and services ----------

    /// <summary>Inserts one asset; duplicates on (assessment, canonical target) are ignored. True when newly inserted.</summary>
    public Task<bool> AddAssetAsync(AssetRecord asset, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(asset);
        return WriteAsync(async (connection, transaction, token) =>
        {
            await using var command = Command(connection, transaction, """
                INSERT OR IGNORE INTO assets(asset_id, assessment_id, kind, display_name, canonical_target,
                                             observed_ips_json, discovered_utc, within_scope)
                VALUES($id, $assessment_id, $kind, $display_name, $canonical_target, $observed_ips_json,
                       $discovered_utc, $within_scope)
                """);
            command.Parameters.AddWithValue("$id", asset.AssetId.ToString());
            command.Parameters.AddWithValue("$assessment_id", asset.AssessmentId.ToString());
            command.Parameters.AddWithValue("$kind", asset.Kind.ToString());
            command.Parameters.AddWithValue("$display_name", asset.DisplayName);
            command.Parameters.AddWithValue("$canonical_target", asset.CanonicalTarget);
            command.Parameters.AddWithValue("$observed_ips_json", ActJson.Serialize(asset.ObservedIps));
            command.Parameters.AddWithValue("$discovered_utc", Db(asset.DiscoveredAtUtc));
            command.Parameters.AddWithValue("$within_scope", Db(asset.WithinScope));
            return await command.ExecuteNonQueryAsync(token).ConfigureAwait(false) > 0;
        }, cancellationToken);
    }

    /// <summary>Inserts one service observation; duplicates on (asset, port) are ignored. True when newly inserted.</summary>
    public Task<bool> AddServiceAsync(ServiceObservation service, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(service);
        return WriteAsync(async (connection, transaction, token) =>
        {
            await using var command = Command(connection, transaction, """
                INSERT OR IGNORE INTO services(service_id, asset_id, port, protocol, banner, tls_negotiated,
                                               observed_utc, source_check)
                VALUES($id, $asset_id, $port, $protocol, $banner, $tls_negotiated, $observed_utc, $source_check)
                """);
            command.Parameters.AddWithValue("$id", service.ServiceId.ToString());
            command.Parameters.AddWithValue("$asset_id", service.AssetId.ToString());
            command.Parameters.AddWithValue("$port", (long)service.Port);
            command.Parameters.AddWithValue("$protocol", service.Protocol.ToString());
            command.Parameters.AddWithValue("$banner", DbOptional(service.Banner));
            command.Parameters.AddWithValue("$tls_negotiated", Db(service.TlsNegotiated));
            command.Parameters.AddWithValue("$observed_utc", Db(service.ObservedAtUtc));
            command.Parameters.AddWithValue("$source_check", service.SourceCheck.Value);
            return await command.ExecuteNonQueryAsync(token).ConfigureAwait(false) > 0;
        }, cancellationToken);
    }

    // ---------- check runs ----------

    /// <summary>Records one executed security check run for the dashboard and run history.</summary>
    public Task RecordCheckRunAsync(
        SecurityCheckResult result, Guid assessmentId, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        return WriteAsync(async (connection, transaction, token) =>
        {
            await using var command = Command(connection, transaction, """
                INSERT INTO check_runs(check_run_id, assessment_id, check_id, status, started_utc, completed_utc,
                                       failure_summary, request_count, targets_examined)
                VALUES($id, $assessment_id, $check_id, $status, $started_utc, $completed_utc, $failure_summary,
                       $request_count, $targets_examined)
                """);
            command.Parameters.AddWithValue("$id", Guid.NewGuid().ToString());
            command.Parameters.AddWithValue("$assessment_id", assessmentId.ToString());
            command.Parameters.AddWithValue("$check_id", result.CheckId.Value);
            command.Parameters.AddWithValue("$status", result.Status.ToString());
            command.Parameters.AddWithValue("$started_utc", Db(result.StartedUtc));
            command.Parameters.AddWithValue("$completed_utc", Db(result.CompletedUtc));
            command.Parameters.AddWithValue("$failure_summary", DbOptional(result.FailureSummarySafe));
            command.Parameters.AddWithValue("$request_count", result.RequestCount);
            command.Parameters.AddWithValue("$targets_examined", (long)result.TargetsExamined);
            await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
        }, cancellationToken);
    }

    // ---------- findings ----------

    /// <summary>
    /// Deduplicates one finding observation. New fingerprints insert; reobservations of non-terminal
    /// findings refresh last_seen and return the merged record via FindingFactory.WithReobservation;
    /// terminal statuses (FalsePositive, AcceptedRisk, Remediated) are never resurrected.
    /// </summary>
    public Task<Finding> UpsertFindingAsync(Finding finding, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(finding);
        return WriteAsync(async (connection, transaction, token) =>
        {
            Finding? existing;
            await using (var query = Command(connection, transaction,
                "SELECT * FROM findings WHERE assessment_id = $assessment_id AND fingerprint = $fingerprint"))
            {
                query.Parameters.AddWithValue("$assessment_id", finding.AssessmentId.ToString());
                query.Parameters.AddWithValue("$fingerprint", finding.Fingerprint.Hash);
                await using var reader = await query.ExecuteReaderAsync(token).ConfigureAwait(false);
                existing = await reader.ReadAsync(token).ConfigureAwait(false) ? MapFinding(reader) : null;
            }

            if (existing is null)
            {
                await InsertFindingAsync(connection, transaction, finding, token).ConfigureAwait(false);
                return finding;
            }

            if (existing.Status is FindingStatus.FalsePositive
                or FindingStatus.AcceptedRisk
                or FindingStatus.Remediated)
            {
                return existing;
            }

            var merged = FindingFactory.WithReobservation(existing, finding.LastSeenUtc);
            if (merged.LastSeenUtc == existing.LastSeenUtc)
            {
                return merged;
            }

            await using var update = Command(connection, transaction,
                "UPDATE findings SET last_seen_utc = $last_seen WHERE finding_id = $id");
            update.Parameters.AddWithValue("$last_seen", Db(merged.LastSeenUtc));
            update.Parameters.AddWithValue("$id", existing.FindingId.ToString());
            await update.ExecuteNonQueryAsync(token).ConfigureAwait(false);
            return merged;
        }, cancellationToken);
    }

    /// <summary>Lists findings with optional filters, most recently seen first.</summary>
    public Task<IReadOnlyList<Finding>> ListFindingsAsync(
        Guid? assessmentId = null,
        FindingStatus? status = null,
        Severity? minSeverity = null,
        int limit = 200,
        CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            RequirePositive(limit, "limit");
            var clauses = new List<string>();
            if (assessmentId is { } assessmentValue)
            {
                clauses.Add("assessment_id = $assessment_id");
                command.Parameters.AddWithValue("$assessment_id", assessmentValue.ToString());
            }

            if (status is { } statusValue)
            {
                clauses.Add("status = $status");
                command.Parameters.AddWithValue("$status", statusValue.ToString());
            }

            if (minSeverity is { } severityValue)
            {
                clauses.Add("severity >= $severity");
                command.Parameters.AddWithValue("$severity", (long)severityValue);
            }

            var where = clauses.Count > 0 ? " WHERE " + string.Join(" AND ", clauses) : string.Empty;
            command.CommandText = "SELECT * FROM findings" + where + " ORDER BY last_seen_utc DESC LIMIT $limit";
            command.Parameters.AddWithValue("$limit", (long)limit);
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            var findings = new List<Finding>();
            while (await reader.ReadAsync(token).ConfigureAwait(false))
            {
                findings.Add(MapFinding(reader));
            }

            return (IReadOnlyList<Finding>)findings;
        }, cancellationToken);

    /// <summary>
    /// Applies one operator triage decision inside a single transaction: validates the transition
    /// against the deterministic lifecycle policy, records who decided what and why on the row
    /// itself, and appends a tamper-evident audit entry. Fails closed on unknown findings, illegal
    /// transitions, and no-op repeats - a silent 'success' there would hide operator error.
    /// </summary>
    public Task<(Finding Finding, FindingTriage Triage)> TriageFindingAsync(
        Guid findingId,
        FindingStatus targetStatus,
        string actor,
        string? note,
        CorrelationId correlation,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(actor))
        {
            throw ActException.FailClosed(ErrorCategory.Configuration,
                "A triage decision needs a named actor.",
                $"Triage of finding {findingId} arrived with an empty actor.");
        }

        note = string.IsNullOrWhiteSpace(note) ? null : note.Trim();
        const int MaxNoteLength = 1000;
        if (note is { Length: > MaxNoteLength })
        {
            throw ActException.FailClosed(ErrorCategory.Configuration,
                $"The triage note must be at most {MaxNoteLength} characters.",
                $"Triage note for finding {findingId} was {note.Length} characters.");
        }

        return WriteAsync(async (connection, transaction, token) =>
        {
            Finding existing;
            await using (var query = Command(connection, transaction,
                "SELECT * FROM findings WHERE finding_id = $id"))
            {
                query.Parameters.AddWithValue("$id", findingId.ToString());
                await using var reader = await query.ExecuteReaderAsync(token).ConfigureAwait(false);
                if (!await reader.ReadAsync(token).ConfigureAwait(false))
                {
                    throw ActException.FailClosed(ErrorCategory.Persistence,
                        "The finding to triage does not exist.",
                        $"No finding row {findingId}; refusing to invent one.");
                }

                existing = MapFinding(reader);
            }

            if (existing.Status == targetStatus)
            {
                throw ActException.FailClosed(ErrorCategory.Configuration,
                    $"The finding is already marked {targetStatus}.",
                    $"No-op triage of finding {findingId} rejected; pick a different status.");
            }

            if (!FindingTransitions.CanTransition(existing.Status, targetStatus))
            {
                throw ActException.FailClosed(ErrorCategory.Configuration,
                    "That triage transition is not allowed.",
                    $"Finding {findingId} is {existing.Status}; allowed targets: "
                    + string.Join(", ", FindingTransitions.AllowedTargets(existing.Status)) + ".");
            }

            var triagedUtc = DateTimeOffset.UtcNow;
            await using var update = Command(connection, transaction, """
                UPDATE findings SET status = $status, triage_note = $note, triaged_by = $by, triaged_utc = $utc
                WHERE finding_id = $id
                """);
            update.Parameters.AddWithValue("$status", targetStatus.ToString());
            update.Parameters.AddWithValue("$note", DbOptional(note));
            update.Parameters.AddWithValue("$by", actor.Trim());
            update.Parameters.AddWithValue("$utc", Db(triagedUtc));
            update.Parameters.AddWithValue("$id", findingId.ToString());
            var changes = await update.ExecuteNonQueryAsync(token).ConfigureAwait(false);
            RequireRows(changes, $"finding {findingId}", "triage update");

            var auditResult = $"{existing.Status} -> {targetStatus}";
            if (note is not null)
            {
                auditResult += ": " + note[..Math.Min(120, note.Length)];
            }

            await AppendAuditCoreAsync(connection, transaction, new AuditDraft(
                Actor: actor.Trim(),
                Action: "finding.triaged",
                ObjectType: "finding",
                ObjectId: findingId.ToString(),
                Result: auditResult,
                Correlation: correlation), token).ConfigureAwait(false);

            return (existing with { Status = targetStatus },
                new FindingTriage(targetStatus, note, actor.Trim(), triagedUtc));
        }, cancellationToken);
    }

    /// <summary>
    /// Reads the triage decision recorded against one finding. Returns null both when the row does
    /// not exist and when it has never been triaged - callers that need to distinguish the two
    /// check existence independently.
    /// </summary>
    public Task<FindingTriage?> GetTriageAsync(Guid findingId, CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            command.CommandText =
                "SELECT status, triage_note, triaged_by, triaged_utc FROM findings WHERE finding_id = $id";
            command.Parameters.AddWithValue("$id", findingId.ToString());
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            if (!await reader.ReadAsync(token).ConfigureAwait(false)
                || reader.IsDBNull(reader.GetOrdinal("triaged_by")))
            {
                return null;
            }

            return new FindingTriage(
                ActValues.Enum<FindingStatus>(reader.Str("status"), "status"),
                reader.StrOrNull("triage_note"),
                reader.Str("triaged_by"),
                ActTime.Read(reader.Str("triaged_utc"), "triaged_utc"));
        }, cancellationToken);

    private static async Task InsertFindingAsync(
        SqliteConnection connection, DbTransaction transaction, Finding finding, CancellationToken token)
    {
        await using var command = Command(connection, transaction, """
            INSERT INTO findings(finding_id, assessment_id, check_id, target_display, asset_reference, category,
                                 title, description, severity, confidence, confidence_score, exploitability,
                                 business_impact, why_it_matters, technical_explanation, remediation_summary,
                                 remediation_steps_json, remediation_references_json, first_seen_utc, last_seen_utc,
                                 status, fingerprint, regression_test_id, cvss_vector, cvss_base_score, priority_score)
            VALUES($finding_id, $assessment_id, $check_id, $target_display, $asset_reference, $category,
                   $title, $description, $severity, $confidence, $confidence_score, $exploitability,
                   $business_impact, $why_it_matters, $technical_explanation, $remediation_summary,
                   $remediation_steps_json, $remediation_references_json, $first_seen_utc, $last_seen_utc,
                   $status, $fingerprint, $regression_test_id, $cvss_vector, $cvss_base_score, $priority_score)
            """);
        command.Parameters.AddWithValue("$finding_id", finding.FindingId.ToString());
        command.Parameters.AddWithValue("$assessment_id", finding.AssessmentId.ToString());
        command.Parameters.AddWithValue("$check_id", finding.CheckId.Value);
        command.Parameters.AddWithValue("$target_display", finding.TargetDisplay);
        command.Parameters.AddWithValue("$asset_reference", DbOptional(finding.AssetReference));
        command.Parameters.AddWithValue("$category", finding.Category.ToString());
        command.Parameters.AddWithValue("$title", finding.Title);
        command.Parameters.AddWithValue("$description", finding.Description);
        command.Parameters.AddWithValue("$severity", (long)finding.TechnicalSeverity);
        command.Parameters.AddWithValue("$confidence", (long)finding.Confidence);
        command.Parameters.AddWithValue("$confidence_score", finding.ConfidenceScore);
        command.Parameters.AddWithValue("$exploitability", Db(finding.ExploitabilityIndicator));
        command.Parameters.AddWithValue("$business_impact", (long)finding.BusinessImpact);
        command.Parameters.AddWithValue("$why_it_matters", finding.WhyItMatters);
        command.Parameters.AddWithValue("$technical_explanation", finding.TechnicalExplanation);
        command.Parameters.AddWithValue("$remediation_summary", finding.Remediation.Summary);
        command.Parameters.AddWithValue("$remediation_steps_json", ActJson.Serialize(finding.Remediation.Steps));
        command.Parameters.AddWithValue("$remediation_references_json", ActJson.Serialize(finding.Remediation.References));
        command.Parameters.AddWithValue("$first_seen_utc", Db(finding.FirstSeenUtc));
        command.Parameters.AddWithValue("$last_seen_utc", Db(finding.LastSeenUtc));
        command.Parameters.AddWithValue("$status", finding.Status.ToString());
        command.Parameters.AddWithValue("$fingerprint", finding.Fingerprint.Hash);
        command.Parameters.AddWithValue("$regression_test_id", DbOptional(finding.RegressionTestId?.ToString()));
        command.Parameters.AddWithValue("$cvss_vector", DbOptional(finding.CvssVector));
        command.Parameters.AddWithValue("$cvss_base_score",
            finding.CvssBaseScore is { } score ? score : DBNull.Value);
        command.Parameters.AddWithValue("$priority_score", finding.PriorityScore);
        await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
    }

    private static Finding MapFinding(SqliteDataReader row) => new(
        FindingId: row.GuidOf("finding_id"),
        AssessmentId: row.GuidOf("assessment_id"),
        CheckId: CheckId.From(row.Str("check_id")),
        TargetDisplay: row.Str("target_display"),
        AssetReference: row.StrOrNull("asset_reference"),
        Category: ActValues.Enum<CheckCategory>(row.Str("category"), "category"),
        Title: row.Str("title"),
        Description: row.Str("description"),
        TechnicalSeverity: ActValues.Enum<Severity>(row.IntOf("severity"), "severity"),
        Confidence: ActValues.Enum<ConfidenceLevel>(row.IntOf("confidence"), "confidence"),
        ConfidenceScore: row.RealOf("confidence_score"),
        ExploitabilityIndicator: row.BoolOf("exploitability"),
        BusinessImpact: ActValues.Enum<BusinessImpactLevel>(row.IntOf("business_impact"), "business_impact"),
        WhyItMatters: row.Str("why_it_matters"),
        TechnicalExplanation: row.Str("technical_explanation"),
        Remediation: new RemediationGuidance(
            Summary: row.Str("remediation_summary"),
            Steps: ActJson.Deserialize<List<string>>(row.Str("remediation_steps_json"), "remediation_steps_json"),
            References: ActJson.Deserialize<List<string>>(
                row.Str("remediation_references_json"), "remediation_references_json")),
        FirstSeenUtc: row.TimeOf("first_seen_utc"),
        LastSeenUtc: row.TimeOf("last_seen_utc"),
        Status: ActValues.Enum<FindingStatus>(row.Str("status"), "status"),
        Fingerprint: new FindingFingerprint(row.Str("fingerprint")),
        RegressionTestId: row.GuidOrNull("regression_test_id"),
        CvssVector: row.StrOrNull("cvss_vector"),
        CvssBaseScore: row.RealOrNull("cvss_base_score"))
    {
        PriorityScore = row.RealOf("priority_score")
    };

    // ---------- evidence ----------

    /// <summary>Stores a batch of redacted evidence items under one transaction. Returns the number stored.</summary>
    public Task<int> AddEvidenceBatchAsync(
        IReadOnlyList<EvidenceItem> items, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(items);
        return WriteAsync(async (connection, transaction, token) =>
        {
            var stored = 0;
            foreach (var item in items)
            {
                await using var command = Command(connection, transaction, """
                    INSERT INTO evidence(evidence_id, finding_id, kind, key, redacted_value, captured_utc,
                                         collected_by, correlation, attributes_json)
                    VALUES($id, $finding_id, $kind, $key, $redacted_value, $captured_utc, $collected_by,
                           $correlation, $attributes_json)
                    """);
                command.Parameters.AddWithValue("$id", item.EvidenceId.ToString());
                command.Parameters.AddWithValue("$finding_id", item.FindingId.ToString());
                command.Parameters.AddWithValue("$kind", item.Kind.ToString());
                command.Parameters.AddWithValue("$key", item.Key);
                command.Parameters.AddWithValue("$redacted_value", item.RedactedValue);
                command.Parameters.AddWithValue("$captured_utc", Db(item.CapturedAtUtc));
                command.Parameters.AddWithValue("$collected_by", item.CollectedBy.Value);
                command.Parameters.AddWithValue("$correlation", item.Correlation.ToString());
                command.Parameters.AddWithValue("$attributes_json", ActJson.Serialize(item.Attributes));
                stored += await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
            }

            return stored;
        }, cancellationToken);
    }

    // ---------- scan metrics ----------

    /// <summary>Stores the counters of one assessment run, replacing any previous metrics for it.</summary>
    public Task SaveScanMetricsAsync(ScanMetricsRecord metrics, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(metrics);
        return WriteAsync(async (connection, transaction, token) =>
        {
            await using var command = Command(connection, transaction, """
                INSERT INTO scan_metrics(assessment_id, requests_sent, checks_executed, checks_failed,
                                         findings_emitted, total_duration_seconds, bytes_received, updated_utc)
                VALUES($assessment_id, $requests_sent, $checks_executed, $checks_failed, $findings_emitted,
                       $total_duration_seconds, $bytes_received, $updated_utc)
                ON CONFLICT(assessment_id) DO UPDATE SET
                    requests_sent = $requests_sent,
                    checks_executed = $checks_executed,
                    checks_failed = $checks_failed,
                    findings_emitted = $findings_emitted,
                    total_duration_seconds = $total_duration_seconds,
                    bytes_received = $bytes_received,
                    updated_utc = $updated_utc
                """);
            command.Parameters.AddWithValue("$assessment_id", metrics.AssessmentId.ToString());
            command.Parameters.AddWithValue("$requests_sent", metrics.RequestsSent);
            command.Parameters.AddWithValue("$checks_executed", metrics.ChecksExecuted);
            command.Parameters.AddWithValue("$checks_failed", metrics.ChecksFailed);
            command.Parameters.AddWithValue("$findings_emitted", metrics.FindingsEmitted);
            command.Parameters.AddWithValue("$total_duration_seconds", metrics.TotalDuration.TotalSeconds);
            command.Parameters.AddWithValue("$bytes_received", metrics.BytesReceived);
            command.Parameters.AddWithValue("$updated_utc", ActTime.Write(DateTimeOffset.UtcNow));
            await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
        }, cancellationToken);
    }

    /// <summary>Returns the counters stored for one assessment or null when none were saved.</summary>
    public Task<ScanMetricsRecord?> GetMetricsAsync(Guid assessmentId, CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            command.CommandText = "SELECT * FROM scan_metrics WHERE assessment_id = $id";
            command.Parameters.AddWithValue("$id", assessmentId.ToString());
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            if (!await reader.ReadAsync(token).ConfigureAwait(false))
            {
                return null;
            }

            return new ScanMetricsRecord(
                AssessmentId: reader.GuidOf("assessment_id"),
                RequestsSent: reader.IntOf("requests_sent"),
                ChecksExecuted: reader.IntOf("checks_executed"),
                ChecksFailed: reader.IntOf("checks_failed"),
                FindingsEmitted: reader.IntOf("findings_emitted"),
                TotalDuration: TimeSpan.FromSeconds(reader.RealOf("total_duration_seconds")),
                BytesReceived: reader.IntOf("bytes_received"));
        }, cancellationToken);

    // ---------- configuration store ----------

    /// <summary>Stores one typed configuration value under a stable key, replacing any previous value.</summary>
    public Task SetConfigAsync<T>(string key, T value, CancellationToken cancellationToken = default)
        where T : notnull
    {
        ValidateConfigKey(key);
        ArgumentNullException.ThrowIfNull(value);
        return WriteAsync(async (connection, transaction, token) =>
        {
            await using var command = Command(connection, transaction, """
                INSERT INTO configurations(key, value_json, updated_utc)
                VALUES($key, $value_json, $updated_utc)
                ON CONFLICT(key) DO UPDATE SET value_json = $value_json, updated_utc = $updated_utc
                """);
            command.Parameters.AddWithValue("$key", key);
            command.Parameters.AddWithValue("$value_json", ActJson.Serialize(value));
            command.Parameters.AddWithValue("$updated_utc", ActTime.Write(DateTimeOffset.UtcNow));
            await command.ExecuteNonQueryAsync(token).ConfigureAwait(false);
        }, cancellationToken);
    }

    /// <summary>Reads one typed configuration value; unknown keys yield default(T).</summary>
    public Task<T?> GetConfigAsync<T>(string key, CancellationToken cancellationToken = default)
        where T : notnull
    {
        ValidateConfigKey(key);
        return ReadAsync(async (command, token) =>
        {
            command.CommandText = "SELECT value_json FROM configurations WHERE key = $key";
            command.Parameters.AddWithValue("$key", key);
            var raw = await command.ExecuteScalarAsync(token).ConfigureAwait(false);
            return raw is string json ? ActJson.Deserialize<T>(json, "configurations.value_json") : default;
        }, cancellationToken);
    }

    /// <summary>Removes one configuration value. Returns true when a stored value was deleted.</summary>
    public Task<bool> ClearConfigAsync(string key, CancellationToken cancellationToken = default)
    {
        ValidateConfigKey(key);
        return WriteAsync(async (connection, transaction, token) =>
        {
            await using var command = Command(connection, transaction,
                "DELETE FROM configurations WHERE key = $key");
            command.Parameters.AddWithValue("$key", key);
            return await command.ExecuteNonQueryAsync(token).ConfigureAwait(false) > 0;
        }, cancellationToken);
    }

    private static void ValidateConfigKey(string key)
    {
        if (string.IsNullOrWhiteSpace(key) || key.Length > 512)
        {
            throw ActException.FailClosed(ErrorCategory.Persistence,
                "The configuration key is invalid.",
                "Configuration keys must be 1..512 characters; received length "
                + (key?.Length ?? 0) + ".");
        }
    }

    private static void RequireRows(int changes, string subject, string operation)
    {
        if (changes == 0)
        {
            throw ActException.FailClosed(ErrorCategory.Persistence,
                "The requested record does not exist.",
                $"{operation}: no rows matched for {subject}.");
        }
    }

    private static void RequirePositive(int value, string name)
    {
        if (value <= 0)
        {
            throw ActException.FailClosed(ErrorCategory.Persistence,
                "The paging limit must be positive.",
                $"{name} must be >= 1; received {value}.");
        }
    }
}
