using ACT.Contracts;

namespace ACT.Distributed;

public record ScannerNode(
    string NodeId,
    string Address,
    int Port,
    ScannerStatus Status,
    int ActiveAssessments,
    int MaxConcurrentAssessments,
    DateTimeOffset LastHeartbeat);

public enum ScannerStatus
{
    Online,
    Busy,
    Offline,
    Error
}
