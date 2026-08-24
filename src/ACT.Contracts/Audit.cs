
namespace ACT.Contracts;

/// <summary>Draft of an audit entry awaiting sequencing and hashing by the sink.</summary>
public sealed record AuditDraft(
    string Actor,
    string Action,
    string ObjectType,
    string ObjectId,
    string Result,
    CorrelationId Correlation);

/// <summary>Tamper-evident audit event: each entry hashes the previous entry's hash.</summary>
public sealed record AuditEvent(
    long Sequence,
    DateTimeOffset TimestampUtc,
    string Actor,
    string Action,
    string ObjectType,
    string ObjectId,
    string Result,
    CorrelationId Correlation,
    string PreviousEventHash,
    string EventHash);

/// <summary>Append-only audit storage with chain verification.</summary>
public interface IAuditSink
{
    Task<AuditEvent> AppendAsync(AuditDraft draft, CancellationToken cancellationToken);

    Task<IReadOnlyList<AuditEvent>> ReadRecentAsync(int limit, CancellationToken cancellationToken);

    /// <summary>Walks the whole chain and reports whether every stored hash link verifies.</summary>
    Task<bool> VerifyChainAsync(CancellationToken cancellationToken);
}
