
namespace ACT.Persistence;

/// <summary>
/// Deletes evidence rows that outlived their scope-configured retention period. Deletion removes
/// rows from the active database; with secureWipe enabled the write-ahead log is additionally
/// checkpointed with TRUNCATE so freed pages stop surviving in sidecar journals. Cryptographic
/// erasure of bytes already copied elsewhere (backups, snapshots, file-system copies) is out of
/// scope for this component.
///
/// Two modes exist on purpose: the global age-based sweep applies ONE window to every row, while
/// <see cref="PreviewAsync"/>/<see cref="SweepAsync"/> honor EACH scope's own configured
/// EvidenceRetentionPeriod - a scope that asked for seven days never keeps evidence for thirty.
/// </summary>
public sealed class RetentionSweeper(ActDatabase database)
{
    /// <summary>Deletes evidence captured before now - age, regardless of owning scope. Returns the number of rows removed.</summary>
    public Task<long> DeleteEvidenceOlderThanAsync(TimeSpan age, bool secureWipe, CancellationToken cancellationToken = default)
        => database.DeleteEvidenceCoreAsync(age, secureWipe, cancellationToken);

    /// <summary>
    /// Per-scope outlook: every stored scope together with its configured window, the cutoff that
    /// window implies right now, and how many of its evidence rows already outlived it. Read-only.
    /// </summary>
    public async Task<IReadOnlyList<RetentionPreviewRow>> PreviewAsync(CancellationToken cancellationToken = default)
    {
        var scopes = await database.ListScopeDefinitionsAsync(cancellationToken).ConfigureAwait(false);
        var nowUtc = DateTimeOffset.UtcNow;
        var rows = new List<RetentionPreviewRow>(scopes.Count);
        foreach (var scope in scopes)
        {
            var cutoffUtc = nowUtc - scope.EvidenceRetentionPeriod;
            var expired = await database.CountExpiredEvidenceAsync(scope.ScopeId, cutoffUtc, cancellationToken)
                .ConfigureAwait(false);
            rows.Add(new RetentionPreviewRow(scope.ScopeId, scope.EvidenceRetentionPeriod, cutoffUtc, expired));
        }

        return rows;
    }

    /// <summary>
    /// Executes one sweep honoring each scope's own window. All deletions commit in a single
    /// transaction; a failure mid-sweep removes nothing. Evidence exactly at its boundary is
    /// retained - only strictly older rows are removed - so re-running an unchanged database
    /// deletes nothing further.
    /// </summary>
    public async Task<RetentionSweepResult> SweepAsync(bool secureWipe, CancellationToken cancellationToken = default)
    {
        var scopes = await database.ListScopeDefinitionsAsync(cancellationToken).ConfigureAwait(false);
        var nowUtc = DateTimeOffset.UtcNow;
        var entries = new List<(Guid ScopeId, DateTimeOffset CutoffUtc)>(scopes.Count);
        foreach (var scope in scopes)
        {
            entries.Add((scope.ScopeId, nowUtc - scope.EvidenceRetentionPeriod));
        }

        var deletedCounts = await database.DeleteExpiredEvidenceForScopesAsync(entries, cancellationToken)
            .ConfigureAwait(false);

        if (secureWipe)
        {
            await database.CheckpointAsync(cancellationToken).ConfigureAwait(false);
        }

        var perScope = new List<RetentionScopeDeletion>(scopes.Count);
        long totalDeleted = 0;
        for (var index = 0; index < scopes.Count; index++)
        {
            totalDeleted += deletedCounts[index];
            perScope.Add(new RetentionScopeDeletion(
                scopes[index].ScopeId, scopes[index].EvidenceRetentionPeriod, deletedCounts[index]));
        }

        return new RetentionSweepResult(totalDeleted, perScope, secureWipe, DateTimeOffset.UtcNow);
    }
}
