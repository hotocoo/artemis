
using System.Collections.Concurrent;
using ACT.Contracts;

namespace ACT.Core;

/// <summary>
/// Core-local authorization gate for checks. Implemented at the composition root by adapting
/// the configured policy evaluator, so the engine never depends on policy internals.
/// </summary>
public interface ICheckGate
{
    GateDecision Evaluate(ScopeDefinition scope, SecurityCheckMetadata metadata);
}

/// <summary>Structured gate verdict.</summary>
public sealed record GateDecision(bool Allowed, string ReasonCode, string SafeMessage)
{
    public static GateDecision Allow() => new(true, "ALLOWED", "Check authorized by policy.");
    public static GateDecision Deny(string code, string safeMessage) => new(false, code, safeMessage);
}

/// <summary>
/// Engine-local emergency stop latch. Arming it cancels every assessment running under this
/// engine instance immediately: no new work is scheduled and active tasks are cancelled.
/// Superseded sources are RETIRED, not disposed, so followers holding an earlier token keep
/// valid handles across arm/disarm cycles; everything is disposed when the latch is disposed.
/// </summary>
public sealed class EmergencyStopLatch : IDisposable
{
    private readonly object _sync = new();
    private readonly List<CancellationTokenSource> _retired = [];
    private CancellationTokenSource _cts = new();
    private string? _reason;
    private string? _actor;
    private bool _disposed;

    public bool IsArmed { get; private set; }

    /// <summary>The reason recorded by the most recent arm or disarm, if any.</summary>
    public string? Reason => _reason;

    /// <summary>The actor recorded by the most recent arm or disarm, if any.</summary>
    public string? Actor => _actor;

    /// <summary>
    /// The live token. Read under the same lock that swaps sources, so a concurrent disarm can
    /// never hand out a disposed-source exception: the returned struct stays queryable forever.
    /// </summary>
    public CancellationToken Token
    {
        get
        {
            lock (_sync)
            {
                ObjectDisposedException.ThrowIf(_disposed, this);
                return _cts.Token;
            }
        }
    }

    public void Arm(string actor, string reason)
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            IsArmed = true;
            _reason = reason;
            _actor = actor;
            _cts.Cancel();
        }
    }

    public EmergencyStopSnapshot Snapshot() =>
        new(IsArmed, Reason ?? "", Actor ?? "");

    /// <summary>Only an explicit operator action may disarm after an emergency stop.</summary>
    public void Disarm(string actor)
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            IsArmed = false;
            _reason = null;
            _actor = actor;
            // A disposed CTS cannot be reused: retire it and install a fresh one so work can
            // resume under this engine instance after the operator clears the stop.
            _retired.Add(_cts);
            _cts = new CancellationTokenSource();
        }
    }

    /// <summary>Disposes every source this latch ever created; the latch cannot be used afterwards.</summary>
    public void Dispose()
    {
        CancellationTokenSource active;
        CancellationTokenSource[] retired;
        lock (_sync)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            active = _cts;
            retired = [.. _retired];
            _retired.Clear();
        }

        foreach (var source in retired)
        {
            source.Dispose();
        }

        active.Dispose();
    }
}

/// <summary>Point-in-time view of the latch for dashboards.</summary>
public sealed record EmergencyStopSnapshot(bool Armed, string Reason, string Actor);

/// <summary>
/// Thread-safe budget accountant. Every network-consuming decision reserves from real capacity
/// first; when nothing remains, work is skipped rather than silently exceeding limits.
/// </summary>
public sealed class BudgetAccountant
{
    private long _requestsReserved;
    private long _bytesReceived;

    public ResourceBudget Budget { get; }

    public BudgetAccountant(ResourceBudget budget) => Budget = budget;

    public long RequestsReserved => Interlocked.Read(ref _requestsReserved);

    public long BytesReceived => Interlocked.Read(ref _bytesReceived);

    /// <summary>Attempts to reserve request slots; returns false when the cap would be exceeded.</summary>
    public bool TryReserveRequests(long count)
    {
        while (true)
        {
            var current = Interlocked.Read(ref _requestsReserved);
            if (current + count > Budget.MaxRequests) return false;
            if (Interlocked.CompareExchange(ref _requestsReserved, current + count, current) == current) return true;
        }
    }

    public void RecordBytes(long bytes) => Interlocked.Add(ref _bytesReceived, bytes);

    public long RemainingRequests => Math.Max(0, Budget.MaxRequests - RequestsReserved);
}

/// <summary>In-memory assessment recorder for tests and dry-runs.</summary>
public sealed class InMemoryAssessmentRecorder : IAssessmentLedger
{
    private readonly ConcurrentDictionary<Guid, AssetRecord> _assets = new();
    private readonly ConcurrentDictionary<(Guid AssetId, int Port), ServiceObservation> _services = new();

    public List<Finding> Findings { get; } = [];
    public List<SecurityCheckResult> CheckRuns { get; } = [];

    public Task<AssetRecord> RecordAssetAsync(AssetRecord asset, CancellationToken cancellationToken)
    {
        _assets[asset.AssetId] = asset;
        return Task.FromResult(asset);
    }

    public Task<ServiceObservation> RecordServiceAsync(ServiceObservation service, CancellationToken cancellationToken)
    {
        _services[(service.AssetId, service.Port)] = service;
        return Task.FromResult(service);
    }

    public IReadOnlyList<ServiceObservation> ObservedServices() => [.. _services.Values];

    public IReadOnlyList<AssetRecord> Assets => [.. _assets.Values];

    public Task UpsertFindingAsync(Finding finding, CancellationToken cancellationToken)
    {
        lock (Findings) Findings.Add(finding);
        return Task.CompletedTask;
    }

    public Task RecordCheckRunAsync(SecurityCheckResult result, Guid assessmentId, CancellationToken cancellationToken)
    {
        lock (CheckRuns) CheckRuns.Add(result);
        return Task.CompletedTask;
    }
}

/// <summary>Persistence-facing sink the composition root implements on top of the database.</summary>
public interface IAssessmentRecorder : IAssessmentLedger
{
    Task UpsertFindingAsync(Finding finding, CancellationToken cancellationToken);

    Task RecordEvidenceBatchAsync(IReadOnlyList<EvidenceItem> items, CancellationToken cancellationToken);

    Task RecordCheckRunAsync(SecurityCheckResult result, Guid assessmentId, CancellationToken cancellationToken);

    /// <summary>
    /// Persists the plan's exclusions as they were decided, BEFORE any work runs: why a registered
    /// check never records an execution must be a stored fact, not a gap every surface guesses at.
    /// </summary>
    Task RecordPlanExclusionsAsync(Guid assessmentId, IReadOnlyList<ExclusionDecision> exclusions, CancellationToken cancellationToken);

    Task SetAssessmentStateAsync(Guid assessmentId, AssessmentRunState state, CancellationToken cancellationToken);
}
