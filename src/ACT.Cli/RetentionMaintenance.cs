
using ACT.Contracts;
using ACT.Persistence;
using ACT.Policy;
using Microsoft.Extensions.DependencyInjection;

namespace ACT.Cli;

/// <summary>
/// Throttled automatic evidence-retention sweeps carried by schedule ticks. The console host's
/// background ticker and external 'artemis schedule tick' invocations both pass through here, so
/// whichever process owns ticking owns sweeping too - the documented single-ticker-per-database
/// contract covers retention exactly as it covers schedules.
///
/// Honesty rules: while ANY emergency stop is armed (in-process latch or persisted flag), sweeps
/// are skipped outright - an incident may be in progress and evidence must outlive it; the skip
/// simply retries on a later tick. The throttle stamp records that maintenance ran even when it
/// deleted nothing; only actual deletions are audited, so a quiet database cannot flood the
/// hash-chained ledger with no-op entries. Manual 'artemis retention sweep' bypasses all of this
/// because explicit operator intent is its own authorization.
/// </summary>
public static class RetentionMaintenance
{
    /// <summary>Configuration key under which the last automatic sweep instant is stored.</summary>
    public const string LastSweepKey = "maintenance:retention-last-auto-sweep";

    /// <summary>Minimum interval between automatic sweeps; manual CLI sweeps ignore it entirely.</summary>
    public static readonly TimeSpan MinimumInterval = TimeSpan.FromHours(24);

    /// <summary>Persisted marker of the most recent automatic sweep.</summary>
    public sealed record AutoSweepStamp(DateTimeOffset SweptUtc);

    /// <summary>
    /// Pure throttle decision: true when no sweep has ever run or the last one is at least
    /// <see cref="MinimumInterval"/> old. A future stamp (clock moved back) never triggers early.
    /// </summary>
    public static bool ShouldAutoSweep(DateTimeOffset? lastSweepUtc, DateTimeOffset nowUtc) =>
        lastSweepUtc is null || nowUtc - lastSweepUtc.Value >= MinimumInterval;

    /// <summary>
    /// Runs one automatic sweep when the emergency stop is disarmed and the throttle allows.
    /// Returns the sweep result, or null when skipped for either reason.
    /// </summary>
    public static async Task<RetentionSweepResult?> MaybeSweepAsync(
        IServiceProvider services, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(services);
        var db = services.GetRequiredService<ActDatabase>();
        var emergency = services.GetRequiredService<EmergencyStop>();

        // Both stop surfaces must be clear: the process latch AND the persisted flag another
        // process wrote via 'artemis assessment stop'. Checking only one would let a scheduled
        // host destroy evidence during another operator's declared incident.
        var persistedStop = await db.GetConfigAsync<EmergencyStopFlag>(
            AssessmentCommands.EmergencyFlagKey, cancellationToken);
        if (emergency.IsArmed || persistedStop is not null)
        {
            return null;
        }

        var last = await db.GetConfigAsync<AutoSweepStamp>(LastSweepKey, cancellationToken);
        var nowUtc = DateTimeOffset.UtcNow;
        if (!ShouldAutoSweep(last?.SweptUtc, nowUtc))
        {
            return null;
        }

        var result = await new RetentionSweeper(db).SweepAsync(secureWipe: false, cancellationToken);
        await db.SetConfigAsync(LastSweepKey, new AutoSweepStamp(nowUtc), cancellationToken);

        if (result.TotalDeleted > 0)
        {
            await db.AppendAuditAsync(new AuditDraft(
                Actor: "maintenance",
                Action: "evidence.retention_swept",
                ObjectType: "evidence",
                ObjectId: "auto:" + Guid.NewGuid().ToString("N"),
                Result: result.TotalDeleted + " deleted across "
                    + result.Scopes.Count(scope => scope.DeletedCount > 0) + " scope(s)",
                Correlation: CorrelationId.New()), cancellationToken);
        }

        return result;
    }
}
