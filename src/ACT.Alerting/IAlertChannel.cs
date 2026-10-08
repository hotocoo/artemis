namespace ACT.Alerting;

public interface IAlertChannel
{
    string ChannelType { get; }
    Task SendAlertAsync(AlertPayload payload, CancellationToken cancellationToken);
}

public record AlertPayload(
    string Title,
    string Message,
    AlertSeverity Severity,
    IReadOnlyList<AlertFinding> Findings,
    Uri? AssessmentUrl,
    DateTimeOffset Timestamp);

public record AlertFinding(
    string Id,
    string Title,
    string Severity,
    string Description,
    string? Recommendation,
    string? Cwe,
    string? Cvss);

public enum AlertSeverity
{
    Info,
    Low,
    Medium,
    High,
    Critical
}
