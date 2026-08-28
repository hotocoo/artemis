using ACT.Contracts;
using ACT.Persistence;

namespace ACT.Cli;

/// <summary>
/// The launch path's asset ledger: it keeps the in-memory view checks rely on AND persists every
/// asset and service observation into the database, so `artemis asset list` and the console
/// inventory report what a launch actually discovered. Re-recording an asset for an assessment
/// that already stored one (schedule ticks re-run the same assessment id) resolves the stored row
/// and returns it, because service observations foreign-key to that row and INSERT OR IGNORE does
/// not suppress foreign-key violations.
/// </summary>
public sealed class PersistingAssessmentLedger(ActDatabase database) : IAssessmentLedger
{
    private readonly List<AssetRecord> _assets = [];
    private readonly List<ServiceObservation> _services = [];
    private readonly Lock _gate = new();

    public async Task<AssetRecord> RecordAssetAsync(AssetRecord asset, CancellationToken cancellationToken)
    {
        var stored = (await database.ListAssetsAsync(asset.AssessmentId, 500, cancellationToken))
            .FirstOrDefault(existing => existing.CanonicalTarget == asset.CanonicalTarget);
        if (stored is null)
        {
            await database.AddAssetAsync(asset, cancellationToken);
            stored = asset;
        }

        lock (_gate) _assets.Add(stored);
        return stored;
    }

    public async Task<ServiceObservation> RecordServiceAsync(ServiceObservation service, CancellationToken cancellationToken)
    {
        var inserted = await database.AddServiceAsync(service, cancellationToken);
        if (inserted)
        {
            lock (_gate) _services.Add(service);
        }

        return service;
    }

    public IReadOnlyList<ServiceObservation> ObservedServices()
    {
        lock (_gate) return [.. _services];
    }
}
