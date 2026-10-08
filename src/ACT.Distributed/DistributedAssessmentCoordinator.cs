using ACT.Contracts;

namespace ACT.Distributed;

public class DistributedAssessmentCoordinator
{
    private readonly IWorkloadBalancer _balancer;
    private readonly Dictionary<string, ScannerNode> _nodes = new();

    public DistributedAssessmentCoordinator(IWorkloadBalancer balancer)
    {
        _balancer = balancer ?? throw new ArgumentNullException(nameof(balancer));
    }

    public void RegisterNode(ScannerNode node)
    {
        _nodes[node.NodeId] = node;
    }

    public void UnregisterNode(string nodeId)
    {
        _nodes.Remove(nodeId);
    }

    public async Task<ScannerNode?> DispatchAssessmentAsync(Guid assessmentId, CancellationToken cancellationToken)
    {
        var nodes = _nodes.Values
            .Where(n => n.Status == ScannerStatus.Online && n.ActiveAssessments < n.MaxConcurrentAssessments)
            .ToArray();

        var node = await _balancer.SelectNodeAsync(nodes, cancellationToken);
        if (node != null)
        {
            // Update node's active assessments count
            var updated = node with { ActiveAssessments = node.ActiveAssessments + 1 };
            _nodes[node.NodeId] = updated;
        }

        return node;
    }
}
