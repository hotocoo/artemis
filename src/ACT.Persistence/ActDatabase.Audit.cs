using System.Data.Common;
using System.Security.Cryptography;
using System.Text;
using ACT.Contracts;
using Microsoft.Data.Sqlite;

namespace ACT.Persistence;

public sealed partial class ActDatabase
{
    /// <summary>
    /// Appends one tamper-evident audit entry: its hash chains to the previous entry's hash and the
    /// first entry ever stored chains to the GENESIS sentinel.
    /// </summary>
    public Task<AuditEvent> AppendAuditAsync(AuditDraft draft, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(draft);
        return WriteAsync(async (connection, transaction, token) =>
            await AppendAuditCoreAsync(connection, transaction, draft, token).ConfigureAwait(false),
            cancellationToken);
    }

    /// <summary>Configuration key holding the newest appended event hash and sequence.</summary>
    internal const string AuditHeadKey = "audit.head";

    /// <summary>
    /// Returns up to limit recent audit entries, newest first, optionally narrowed to one action
    /// prefix (e.g. "finding." matches finding.triaged) and/or one correlation identifier. Filters
    /// narrow; they never reorder or reinterpret the ledger.
    /// </summary>
    public Task<IReadOnlyList<AuditEvent>> ListAuditEventsAsync(
        int limit,
        string? actionPrefix = null,
        Guid? correlation = null,
        CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            RequirePositive(limit, "limit");
            if (actionPrefix is not null && actionPrefix.Length == 0)
            {
                throw ActException.FailClosed(ErrorCategory.Persistence,
                    "The audit filter is invalid.",
                    "An action prefix filter must be null or a non-empty string.");
            }

            var clauses = new List<string>();
            if (actionPrefix is not null)
            {
                clauses.Add("action LIKE $prefix");
            }

            if (correlation is not null)
            {
                clauses.Add("correlation = $correlation");
            }

            var where = clauses.Count > 0 ? "WHERE " + string.Join(" AND ", clauses) : "";
            command.CommandText = $"""
                SELECT sequence, timestamp_utc, actor, action, object_type, object_id, result,
                       correlation, previous_hash, event_hash
                FROM audit_events {where} ORDER BY sequence DESC LIMIT $limit
                """;
            command.Parameters.AddWithValue("$limit", (long)limit);
            if (actionPrefix is not null)
            {
                command.Parameters.AddWithValue("$prefix", actionPrefix + "%");
            }

            if (correlation is not null)
            {
                // Stored correlations are CorrelationId.ToString(): "N" format, no hyphens.
                command.Parameters.AddWithValue("$correlation", correlation.Value.ToString("N"));
            }

            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            var events = new List<AuditEvent>();
            while (await reader.ReadAsync(token).ConfigureAwait(false))
            {
                events.Add(MapAudit(reader));
            }

            return (IReadOnlyList<AuditEvent>)events;
        }, cancellationToken);

    /// <summary>Total number of stored audit events, so surfaces can say "showing N of M" honestly.</summary>
    public Task<long> CountAuditEventsAsync(CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            command.CommandText = "SELECT COUNT(*) FROM audit_events";
            var raw = await command.ExecuteScalarAsync(token).ConfigureAwait(false);
            return Convert.ToInt64(raw, System.Globalization.CultureInfo.InvariantCulture);
        }, cancellationToken);

    /// <summary>Returns up to limit recent audit entries, newest first.</summary>
    public Task<IReadOnlyList<AuditEvent>> ReadRecentAuditAsync(int limit, CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            RequirePositive(limit, "limit");
            command.CommandText = """
                SELECT sequence, timestamp_utc, actor, action, object_type, object_id, result,
                       correlation, previous_hash, event_hash
                FROM audit_events ORDER BY sequence DESC LIMIT $limit
                """;
            command.Parameters.AddWithValue("$limit", (long)limit);
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            var events = new List<AuditEvent>();
            while (await reader.ReadAsync(token).ConfigureAwait(false))
            {
                events.Add(MapAudit(reader));
            }

            return (IReadOnlyList<AuditEvent>)events;
        }, cancellationToken);

    /// <summary>
    /// Walks the whole audit chain and reports whether every stored link and content hash verifies.
    /// Any edit, deletion, or reorder of past rows breaks verification; when verification fails the
    /// result names the FIRST broken sequence and why it broke. A recorded chain head additionally
    /// exposes deletions of the newest rows, which hash links alone cannot see.
    /// </summary>
    public Task<AuditChainVerification> VerifyChainDetailedAsync(CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            long count = 0;
            long? lastSequence = null;
            long? headSequence = null;
            var previousHash = GenesisAuditHash;
            string? headHash = null;

            // The recorded head (written in the same transaction as every append since its
            // introduction) must still be the chain's last link - or the tail was shortened.
            command.CommandText = "SELECT value_json FROM configurations WHERE key = $key";
            command.Parameters.AddWithValue("$key", AuditHeadKey);
            await using (var headReader = await command.ExecuteReaderAsync(token).ConfigureAwait(false))
            {
                if (await headReader.ReadAsync(token).ConfigureAwait(false))
                {
                    var head = ActJson.Deserialize<RecordedHead>(headReader.GetString(0), AuditHeadKey);
                    headHash = head.EventHash;
                    headSequence = head.Sequence;
                }
            }

            command.Parameters.Clear();
            command.CommandText = """
                SELECT sequence, timestamp_utc, actor, action, object_type, object_id, result,
                       correlation, previous_hash, event_hash
                FROM audit_events ORDER BY sequence ASC
                """;
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            while (await reader.ReadAsync(token).ConfigureAwait(false))
            {
                count++;
                var row = MapAudit(reader);
                if (!string.Equals(row.PreviousEventHash, previousHash, StringComparison.Ordinal))
                {
                    return new AuditChainVerification(false, count, row.Sequence,
                        "entry no longer chains to its predecessor's event hash (row edited, deleted, or reordered)");
                }

                var expected = AuditHash(previousHash, row.TimestampUtc, new AuditDraft(
                    Actor: row.Actor,
                    Action: row.Action,
                    ObjectType: row.ObjectType,
                    ObjectId: row.ObjectId,
                    Result: row.Result,
                    Correlation: row.Correlation));
                if (!string.Equals(expected, row.EventHash, StringComparison.Ordinal))
                {
                    return new AuditChainVerification(false, count, row.Sequence,
                        "content hash no longer matches the entry's own fields (payload edited in place)");
                }

                previousHash = row.EventHash;
                lastSequence = row.Sequence;
            }

            if (headHash is not null &&
                (!string.Equals(previousHash, headHash, StringComparison.Ordinal) ||
                 lastSequence is null ||
                 count == 0))
            {
                // Name the first MISSING entry - the recorded head's own sequence.
                return new AuditChainVerification(false, count, headSequence,
                    "the chain ends before the recorded head - rows were deleted from the newest end");
            }

            return new AuditChainVerification(true, count, null, null);
        }, cancellationToken);

    /// <summary>Walks the whole chain and reports whether every stored hash link verifies.</summary>
    public async Task<bool> VerifyChainAsync(CancellationToken cancellationToken = default) =>
        (await VerifyChainDetailedAsync(cancellationToken).ConfigureAwait(false)).Verified;

    /// <summary>Head pointer persisted beside every append so tail truncation becomes detectable.</summary>
    private sealed record RecordedHead(long Sequence, string EventHash);

    internal static async Task<AuditEvent> AppendAuditCoreAsync(
        SqliteConnection connection, DbTransaction transaction, AuditDraft draft, CancellationToken token)
    {
        string previousHash;
        await using (var query = Command(connection, transaction,
            "SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"))
        {
            var raw = await query.ExecuteScalarAsync(token).ConfigureAwait(false);
            previousHash = raw is string stored ? stored : GenesisAuditHash;
        }

        var timestampUtc = DateTimeOffset.UtcNow;
        var eventHash = AuditHash(previousHash, timestampUtc, draft);
        await using var insert = Command(connection, transaction, """
            INSERT INTO audit_events(timestamp_utc, actor, action, object_type, object_id, result,
                                     correlation, previous_hash, event_hash)
            VALUES($timestamp_utc, $actor, $action, $object_type, $object_id, $result,
                   $correlation, $previous_hash, $event_hash)
            """);
        insert.Parameters.AddWithValue("$timestamp_utc", ActTime.Write(timestampUtc));
        insert.Parameters.AddWithValue("$actor", draft.Actor);
        insert.Parameters.AddWithValue("$action", draft.Action);
        insert.Parameters.AddWithValue("$object_type", draft.ObjectType);
        insert.Parameters.AddWithValue("$object_id", draft.ObjectId);
        insert.Parameters.AddWithValue("$result", draft.Result);
        insert.Parameters.AddWithValue("$correlation", draft.Correlation.ToString());
        insert.Parameters.AddWithValue("$previous_hash", previousHash);
        insert.Parameters.AddWithValue("$event_hash", eventHash);
        await insert.ExecuteNonQueryAsync(token).ConfigureAwait(false);

        await using var identity = Command(connection, transaction, "SELECT last_insert_rowid()");
        var sequence = Convert.ToInt64(
            await identity.ExecuteScalarAsync(token).ConfigureAwait(false),
            System.Globalization.CultureInfo.InvariantCulture);

        // Persist the head pointer in the SAME transaction as the append: deleting the newest
        // rows leaves a hash-valid prefix, so only this recorded expectation exposes tail loss.
        await using (var head = Command(connection, transaction, """
            INSERT INTO configurations(key, value_json, updated_utc)
            VALUES($key, $value_json, $updated_utc)
            ON CONFLICT(key) DO UPDATE SET value_json = $value_json, updated_utc = $updated_utc
            """))
        {
            head.Parameters.AddWithValue("$key", AuditHeadKey);
            head.Parameters.AddWithValue("$value_json", ActJson.Serialize(
                new RecordedHead(sequence, eventHash)));
            head.Parameters.AddWithValue("$updated_utc", ActTime.Write(timestampUtc));
            await head.ExecuteNonQueryAsync(token).ConfigureAwait(false);
        }

        return new AuditEvent(
            Sequence: sequence,
            TimestampUtc: timestampUtc,
            Actor: draft.Actor,
            Action: draft.Action,
            ObjectType: draft.ObjectType,
            ObjectId: draft.ObjectId,
            Result: draft.Result,
            Correlation: draft.Correlation,
            PreviousEventHash: previousHash,
            EventHash: eventHash);
    }
}
