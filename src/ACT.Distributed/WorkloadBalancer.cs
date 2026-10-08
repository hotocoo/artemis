using ACT.Contracts;

namespace ACT.Distributed;

public interface IWorkloadBalancer
{
    Task<ScannerNode?> SelectNodeAsync(IReadOnlyList<ScannerNode> nodes, CancellationToken cancellationToken);
    Task ReportCompletionAsync(string nodeId, CancellationToken cancellationToken);
}

public class RoundRobinWorkloadBalancer : IWorkloadBalancer
{
    private int _index;

    public Task<ScannerNode?> SelectNodeAsync(IReadOnlyList<ScannerNode> nodes, CancellationToken cancellationToken)
    {
        if (nodes.Count == 0)
        {
            return Task.FromResult<ScannerNode?>(null);
        }

        var available = nodes.Where(n => n.Status == ScannerStatus.Online && n.ActiveAssessments < n.MaxConcurrentAssessments).ToArray();
        if (available.Length == 0)
        {
            return Task.FromResult<ScannerNode?>(null);
        }

        var index = Interlocked.Increment(ref _index) % available.Length;
        return Task.FromResult<ScannerNode?>(available[index]);
    }

    public Task ReportCompletionAsync(string nodeId, CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}
