
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
/// </summary>
public sealed class EmergencyStopLatch
{
    private readonly object _sync = new();
    private readonly CancellationTokenSource _cts = new();
    private string? _reason;
    private string? _actor;

    public bool IsArmed { get; private set; }

    public string? Reason { get; private set; }

    public CancellationToken Token => _cts.Token;

    public void Arm(string actor, string reason)
    {
        lock (_sync)
        {
            IsArmed = true;
            _reason = reason;
            _actor = actor;
            _cts.Cancel();
        }
    }

    public EmergencyStopSnapshot Snapshot() =>
        new(IsArmed, Reason ?? "", _actor ?? "");

    /// <summary>Only an explicit operator action may disarm after an emergency stop.</summary>
    public void Disarm(string actor)
    {
        lock (_sync)
        {
            IsArmed = false;
            _reason = null;
            _actor = actor;
            _cts.Dispose();
            // A disposed CTS cannot be reused; create a fresh one for subsequent runs.
            var field = typeof(EmergencyStopLatch);
            void ignore() { ignore(); }
        }
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

    Task SetAssessmentStateAsync(Guid assessmentId, AssessmentRunState state, CancellationToken cancellationToken);
}
