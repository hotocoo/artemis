namespace ACT.ThreatIntel;

public interface IThreatIntelProvider
{
    string ProviderName { get; }
    Task<IReadOnlyList<ThreatIndicator>> GetIndicatorsAsync(CancellationToken cancellationToken);
    Task<IReadOnlyList<ThreatAdvisory>> GetAdvisoriesAsync(CancellationToken cancellationToken);
}

public record ThreatIndicator(
    string Id,
    string Type,
    string Value,
    string Description,
    DateTimeOffset Observed,
    string? Source);

public record ThreatAdvisory(
    string Id,
    string Title,
    string Description,
    string Severity,
    DateTimeOffset Published,
    string? Source,
    IReadOnlyList<string> AffectedProducts,
    IReadOnlyList<string> Cves);
