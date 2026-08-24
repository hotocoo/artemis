using ACT.Contracts;

namespace ACT.Persistence;

/// <summary>
/// Deletes evidence rows that outlived the scope-configured retention period. Deletion removes
/// rows from the active database; with secureWipe enabled the write-ahead log is additionally
/// checkpointed with TRUNCATE so freed pages stop surviving in sidecar journals. Cryptographic
/// erasure of bytes already copied elsewhere (backups, snapshots, file-system copies) is out of
/// scope for this component.
/// </summary>
public sealed class RetentionSweeper(ActDatabase database)
{
    /// <summary>Deletes evidence captured before now - age. Returns the number of rows removed.</summary>
    public Task<long> DeleteEvidenceOlderThanAsync(TimeSpan age, bool secureWipe, CancellationToken cancellationToken = default)
        => database.DeleteEvidenceCoreAsync(age, secureWipe, cancellationToken);
}
