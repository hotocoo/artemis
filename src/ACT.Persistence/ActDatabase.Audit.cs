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
    /// Any edit, deletion, or reorder of past rows breaks verification.
    /// </summary>
    public Task<bool> VerifyChainAsync(CancellationToken cancellationToken = default) =>
        ReadAsync(async (command, token) =>
        {
            command.CommandText = """
                SELECT sequence, timestamp_utc, actor, action, object_type, object_id, result,
                       correlation, previous_hash, event_hash
                FROM audit_events ORDER BY sequence ASC
                """;
            await using var reader = await command.ExecuteReaderAsync(token).ConfigureAwait(false);
            var previousHash = GenesisAuditHash;
            while (await reader.ReadAsync(token).ConfigureAwait(false))
            {
                var row = MapAudit(reader);
                if (!string.Equals(row.PreviousEventHash, previousHash, StringComparison.Ordinal))
                {
                    return false;
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
                    return false;
                }

                previousHash = row.EventHash;
            }

            return true;
        }, cancellationToken);

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
