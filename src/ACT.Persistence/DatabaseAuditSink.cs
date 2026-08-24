
using ACT.Contracts;

namespace ACT.Persistence;

/// <summary>
/// The engine's view of the tamper-evident audit ledger: a thin adapter over
/// <see cref="ActDatabase"/>'s hash-chained audit_events table. Every engine stage event (started,
/// finding created, completed, stopped) lands in the same append-only ledger operators verify with
/// 'artemis doctor' and the console Audit Log page - there is no second audit trail.
/// </summary>
public sealed class DatabaseAuditSink(ActDatabase database) : IAuditSink
{
    /// <summary>Sequences and hashes one draft entry, chaining it to the previous entry.</summary>
    public Task<AuditEvent> AppendAsync(AuditDraft draft, CancellationToken cancellationToken) =>
        database.AppendAuditAsync(draft, cancellationToken);

    /// <summary>Returns up to <paramref name="limit"/> recent events, newest first.</summary>
    public Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(int limit, CancellationToken cancellationToken) =>
        database.ReadRecentAuditAsync(limit, cancellationToken);

    /// <summary>Walks the entire chain; false means stored history was altered.</summary>
    public Task<bool> VerifyChainAsync(CancellationToken cancellationToken) =>
        database.VerifyChainAsync(cancellationToken);
}
