using System.Net.Http;
using System.Text.Json;

namespace ACT.Alerting;

public class PagerDutyAlertChannel : IAlertChannel
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    private readonly HttpClient _http;
    private readonly Uri _eventsUrl;
    private readonly string _routingKey;

    public string ChannelType => "pagerduty";

    public PagerDutyAlertChannel(HttpClient http, Uri eventsUrl, string routingKey)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _eventsUrl = eventsUrl ?? throw new ArgumentNullException(nameof(eventsUrl));
        _routingKey = routingKey ?? throw new ArgumentNullException(nameof(routingKey));
    }

    public async Task SendAlertAsync(AlertPayload payload, CancellationToken cancellationToken)
    {
        var severity = payload.Severity switch
        {
            AlertSeverity.Critical => "critical",
            AlertSeverity.High => "error",
            AlertSeverity.Medium => "warning",
            AlertSeverity.Low => "info",
            _ => "info"
        };

        var body = new
        {
            routing_key = _routingKey,
            event_type = "trigger",
            dedup_key = payload.Title,
            incident_key = payload.Title,
            payload = new
            {
                summary = payload.Title,
                severity,
                source = "artemis",
                component = "security-assessment",
                group = "security",
                class_ = "vulnerability",
                custom_details = new
                {
                    message = payload.Message,
                    findings_count = payload.Findings.Count,
                    findings = payload.Findings.Take(10).Select(f => new
                    {
                        id = f.Id,
                        title = f.Title,
                        severity = f.Severity,
                        description = f.Description,
                        cwe = f.Cwe,
                        cvss = f.Cvss
                    })
                }
            }
        };

        var json = JsonSerializer.Serialize(body, JsonOptions);
        var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");

        using var response = await _http.PostAsync(_eventsUrl, content, cancellationToken);
        response.EnsureSuccessStatusCode();
    }
}
