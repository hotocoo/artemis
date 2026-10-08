using System.Net.Http;

namespace ACT.ThreatIntel;

public class TaxiiProvider : IThreatIntelProvider
{
    private readonly HttpClient _http;
    private readonly Uri _collectionsUrl;

    public string ProviderName => "taxii";

    public TaxiiProvider(HttpClient http, Uri collectionsUrl)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _collectionsUrl = collectionsUrl ?? throw new ArgumentNullException(nameof(collectionsUrl));
    }

    public async Task<IReadOnlyList<ThreatIndicator>> GetIndicatorsAsync(CancellationToken cancellationToken)
    {
        // TAXII 2.1 collection query
        var response = await _http.GetStringAsync(_collectionsUrl, cancellationToken);
        // Parse and return indicators
        return Array.Empty<ThreatIndicator>();
    }

    public async Task<IReadOnlyList<ThreatAdvisory>> GetAdvisoriesAsync(CancellationToken cancellationToken)
    {
        // TAXII 2.1 collection query
        var response = await _http.GetStringAsync(_collectionsUrl, cancellationToken);
        // Parse and return advisories
        return Array.Empty<ThreatAdvisory>();
    }
}
