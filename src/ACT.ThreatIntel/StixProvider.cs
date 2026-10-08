using System.Net.Http;
using System.Text.Json;

namespace ACT.ThreatIntel;

public class StixProvider : IThreatIntelProvider
{
    private static readonly JsonSerializerOptions JsonOptions = new();

    private readonly HttpClient _http;
    private readonly Uri _collectionUrl;

    public string ProviderName => "stix";

    public StixProvider(HttpClient http, Uri collectionUrl)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _collectionUrl = collectionUrl ?? throw new ArgumentNullException(nameof(collectionUrl));
    }

    public async Task<IReadOnlyList<ThreatIndicator>> GetIndicatorsAsync(CancellationToken cancellationToken)
    {
        var response = await _http.GetStringAsync(_collectionUrl, cancellationToken);
        var document = JsonDocument.Parse(response);

        var indicators = new List<ThreatIndicator>();
        if (document.RootElement.TryGetProperty("objects", out var objects))
        {
            foreach (var obj in objects.EnumerateArray())
            {
                if (obj.TryGetProperty("type", out var type) && type.GetString() == "indicator")
                {
                    indicators.Add(new ThreatIndicator(
                        Id: obj.GetProperty("id").GetString() ?? string.Empty,
                        Type: obj.TryGetProperty("indicator_types", out var types) && types.GetArrayLength() > 0
                            ? types[0].GetString() ?? "unknown"
                            : "unknown",
                        Value: obj.TryGetProperty("pattern", out var pattern)
                            ? pattern.GetString() ?? string.Empty
                            : string.Empty,
                        Description: obj.TryGetProperty("description", out var desc)
                            ? desc.GetString() ?? string.Empty
                            : string.Empty,
                        Observed: DateTimeOffset.UtcNow,
                        Source: "STIX"));
                }
            }
        }

        return indicators;
    }

    public async Task<IReadOnlyList<ThreatAdvisory>> GetAdvisoriesAsync(CancellationToken cancellationToken)
    {
        var response = await _http.GetStringAsync(_collectionUrl, cancellationToken);
        var document = JsonDocument.Parse(response);

        var advisories = new List<ThreatAdvisory>();
        if (document.RootElement.TryGetProperty("objects", out var objects))
        {
            foreach (var obj in objects.EnumerateArray())
            {
                if (obj.TryGetProperty("type", out var type) && type.GetString() == "vulnerability")
                {
                    advisories.Add(new ThreatAdvisory(
                        Id: obj.GetProperty("id").GetString() ?? string.Empty,
                        Title: obj.TryGetProperty("name", out var name)
                            ? name.GetString() ?? string.Empty
                            : string.Empty,
                        Description: obj.TryGetProperty("description", out var desc)
                            ? desc.GetString() ?? string.Empty
                            : string.Empty,
                        Severity: "unknown",
                        Published: DateTimeOffset.UtcNow,
                        Source: "STIX",
                        AffectedProducts: Array.Empty<string>(),
                        Cves: Array.Empty<string>()));
                }
            }
        }

        return advisories;
    }
}
