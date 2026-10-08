using ACT.Contracts;

namespace ACT.Workflow;

public interface ITicketProvider
{
    string ProviderName { get; }
    Task<string> CreateTicketAsync(TicketPayload payload, CancellationToken cancellationToken);
}

public record TicketPayload(
    string Title,
    string Description,
    string Severity,
    string Assignee,
    string? Labels,
    string? Priority,
    string? DueDate);
