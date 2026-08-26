
using ACT.Contracts;

namespace ACT.Core;

/// <summary>
/// Decides which checks run where, from structured metadata only. Selection is a pure function:
/// same scope + same inventory + same policy => same plan.
/// </summary>
public sealed class Orchestrator(ICheckGate gate)
{
    /// <summary>An executable unit: one check against one concrete context.</summary>
    public sealed record WorkItem(ISecurityCheck Check, SecurityCheckContext Context, int EstimatedRequests);

    /// <summary>
    /// Builds the deterministic execution plan. Checks whose metadata is incompatible with the
    /// target kind, protocols, policy, or remaining budget are excluded with recorded reasons.
    /// </summary>
    public OrchestrationPlan BuildPlan(
        ScopeDefinition scope,
        IReadOnlyList<ISecurityCheck> availableChecks,
        IReadOnlyList<SecurityCheckContext> contexts,
        BudgetAccountant accountant)
    {
        var decisions = new List<ExclusionDecision>();
        var work = new List<WorkItem>();

        foreach (var check in availableChecks.OrderBy(c => c.Metadata.Id.Value, StringComparer.Ordinal))
        {
            var verdict = gate.Evaluate(scope, check.Metadata);
            if (!verdict.Allowed)
            {
                decisions.Add(new ExclusionDecision(check.Metadata.Id.Value, verdict.ReasonCode, verdict.SafeMessage));
                continue;
            }

            var contextDecisions = new List<ExclusionDecision>();
            var composedAnywhere = false;

            foreach (var context in contexts)
            {
                if (!check.Metadata.SupportedTargetTypes.Overlaps(AssetKindMapping.For(context.Asset.Kind)))
                {
                    contextDecisions.Add(new ExclusionDecision(check.Metadata.Id.Value, "TARGET_TYPE_MISMATCH",
                        $"Check does not support asset kind {context.Asset.Kind}."));
                    continue;
                }

                var protocol = context.Service?.Protocol ?? context.BaseUrl?.Scheme switch
                {
                    "https" => ProtocolKind.Https,
                    "http" => ProtocolKind.Http,
                    _ => ProtocolKind.Tcp
                };
                if (check.Metadata.RequiredProtocols.Count > 0 && !check.Metadata.RequiredProtocols.Contains(protocol))
                {
                    contextDecisions.Add(new ExclusionDecision(check.Metadata.Id.Value, "PROTOCOL_MISMATCH",
                        $"Check requires {string.Join("/", check.Metadata.RequiredProtocols)}; target speaks {protocol}."));
                    continue;
                }

                var estimated = Math.Max(1, check.Metadata.NetworkBehavior.MaxRequestsPerTarget);
                if (!accountant.TryReserveRequests(estimated))
                {
                    contextDecisions.Add(new ExclusionDecision(check.Metadata.Id.Value, "BUDGET_EXHAUSTED",
                        "Remaining request budget could not cover this check's declared footprint."));
                    continue;
                }

                composedAnywhere = true;
                work.Add(new WorkItem(check, context, estimated));
            }

            // Per-context rejections only become stored decisions when NO context admitted the
            // check: a check that executed against one context must not also carry an "excluded"
            // row that would contradict its own execution ledger above.
            if (!composedAnywhere)
            {
                decisions.AddRange(contextDecisions);
            }
        }

        return new OrchestrationPlan(work, decisions);
    }
}

/// <summary>The complete deterministic plan plus the reasons every exclusion happened.</summary>
public sealed record OrchestrationPlan(
    IReadOnlyList<Orchestrator.WorkItem> Work,
    IReadOnlyList<ExclusionDecision> Exclusions);

/// <summary>Maps discovered asset kinds onto the scope target kinds checks declare support for.</summary>
public static class AssetKindMapping
{
    public static IReadOnlySet<TargetTypeKind> For(AssetKind kind) => kind switch
    {
        AssetKind.Host => new HashSet<TargetTypeKind>
        {
            TargetTypeKind.Localhost, TargetTypeKind.PrivateIp, TargetTypeKind.PrivateSubnet,
            TargetTypeKind.Hostname, TargetTypeKind.Domain, TargetTypeKind.TestEnvironment
        },
        AssetKind.Url => new HashSet<TargetTypeKind> { TargetTypeKind.Url },
        AssetKind.Repository => new HashSet<TargetTypeKind> { TargetTypeKind.LocalSourceRepository },
        AssetKind.Container => new HashSet<TargetTypeKind> { TargetTypeKind.LocalContainer },
        AssetKind.TestEnvironment => new HashSet<TargetTypeKind> { TargetTypeKind.TestEnvironment },
        _ => throw ActException.FailClosed(ErrorCategory.Internal,
            "Unknown asset kind encountered.", "AssetKindMapping hit unreachable default.")
    };
}

/// <summary>Why a check did not run against a target.</summary>
public sealed record ExclusionDecision(string CheckId, string ReasonCode, string SafeMessage);

/// <summary>Deterministic finding deduplication across a run and against prior history.</summary>
public sealed class FindingDeduplicator
{
    private readonly Dictionary<string, Finding> _byFingerprint = new(StringComparer.Ordinal);

    public FindingDeduplicator(IEnumerable<Finding>? preexisting = null)
    {
        if (preexisting is null) return;
        foreach (var finding in preexisting)
        {
            _byFingerprint[finding.Fingerprint.Hash] = finding;
        }
    }

    /// <summary>Merges an incoming finding into the known set. Returns null when it only refreshes history.</summary>
    public MergeOutcome Merge(Finding incoming)
    {
        if (_byFingerprint.TryGetValue(incoming.Fingerprint.Hash, out var existing))
        {
            var refreshed = FindingFactory.WithReobservation(existing, incoming.LastSeenUtc);
            _byFingerprint[existing.Fingerprint.Hash] = refreshed;
            return new MergeOutcome(refreshed, WasDuplicate: true);
        }
        _byFingerprint[incoming.Fingerprint.Hash] = incoming;
        return new MergeOutcome(incoming, WasDuplicate: false);
    }

    public IReadOnlyCollection<Finding> Snapshot() => [.. _byFingerprint.Values];

    public bool Contains(string fingerprintHash) => _byFingerprint.ContainsKey(fingerprintHash);
}

/// <summary>Result of merging one finding.</summary>
public sealed record MergeOutcome(Finding Finding, bool WasDuplicate);
