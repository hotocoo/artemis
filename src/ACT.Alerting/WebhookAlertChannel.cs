using System.Net.Http;
using System.Text.Json;

namespace ACT.Alerting;

public class WebhookAlertChannel : IAlertChannel
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    private readonly HttpClient _http;
    private readonly Uri _url;

    public string ChannelType => "webhook";

    public WebhookAlertChannel(HttpClient http, Uri url)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _url = url ?? throw new ArgumentNullException(nameof(url));
    }

    public async Task SendAlertAsync(AlertPayload payload, CancellationToken cancellationToken)
    {
        var envelope = new
        {
            source = "artemis",
            type = "alert",
            timestamp = payload.Timestamp,
            severity = payload.Severity.ToString().ToLowerInvariant(),
            title = payload.Title,
            message = payload.Message,
            assessment_url = payload.AssessmentUrl?.ToString(),
            findings = payload.Findings.Select(f => new
            {
                id = f.Id,
                title = f.Title,
                severity = f.Severity,
                description = f.Description,
                recommendation = f.Recommendation,
                cwe = f.Cwe,
                cvss = f.Cvss
            })
        };

        var json = JsonSerializer.Serialize(envelope, JsonOptions);
        var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");

        using var response = await _http.PostAsync(_url, content, cancellationToken);
        response.EnsureSuccessStatusCode();
    }
}
