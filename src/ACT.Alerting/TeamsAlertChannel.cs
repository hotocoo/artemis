using System.Net.Http;
using System.Text.Json;

namespace ACT.Alerting;

public class TeamsAlertChannel : IAlertChannel
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    private readonly HttpClient _http;
    private readonly Uri _webhookUrl;

    public string ChannelType => "teams";

    public TeamsAlertChannel(HttpClient http, Uri webhookUrl)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _webhookUrl = webhookUrl ?? throw new ArgumentNullException(nameof(webhookUrl));
    }

    public async Task SendAlertAsync(AlertPayload payload, CancellationToken cancellationToken)
    {
        var color = payload.Severity switch
        {
            AlertSeverity.Critical => "FF0000",
            AlertSeverity.High => "FF4444",
            AlertSeverity.Medium => "FFAA00",
            AlertSeverity.Low => "00AA00",
            _ => "0066CC"
        };

        var sections = payload.Findings.Take(10).Select(f => new
        {
            activityTitle = $"{f.Title} ({f.Severity})",
            text = f.Description,
            facts = new[]
            {
                new { name = "ID", value = f.Id },
                new { name = "Severity", value = f.Severity },
                new { name = "Recommendation", value = f.Recommendation ?? "N/A" }
            }
        }).ToArray();

        var card = new
        {
            type = "MessageCard",
            themeColor = color,
            title = payload.Title,
            text = payload.Message,
            sections,
            potentialAction = payload.AssessmentUrl != null ? new[]
            {
                new
                {
                    type = "OpenUri",
                    name = "View Assessment Report",
                    targets = new[] { new { platform = "default", uri = payload.AssessmentUrl.ToString() } }
                }
            } : null
        };

        var json = JsonSerializer.Serialize(card, JsonOptions);
        var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");

        using var response = await _http.PostAsync(_webhookUrl, content, cancellationToken);
        response.EnsureSuccessStatusCode();
    }
}
