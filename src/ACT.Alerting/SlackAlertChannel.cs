using System.Net.Http;
using System.Text.Json;

namespace ACT.Alerting;

public class SlackAlertChannel : IAlertChannel
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
    };

    private readonly HttpClient _http;
    private readonly Uri _webhookUrl;

    public string ChannelType => "slack";

    public SlackAlertChannel(HttpClient http, Uri webhookUrl)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _webhookUrl = webhookUrl ?? throw new ArgumentNullException(nameof(webhookUrl));
    }

    public async Task SendAlertAsync(AlertPayload payload, CancellationToken cancellationToken)
    {
        var emoji = payload.Severity switch
        {
            AlertSeverity.Critical => "🚨",
            AlertSeverity.High => "🔴",
            AlertSeverity.Medium => "🟡",
            AlertSeverity.Low => "🟢",
            _ => "ℹ️"
        };

        var text = $"{emoji} *{payload.Title}*\n{payload.Message}\n";
        if (payload.Findings.Count > 0)
        {
            text += $"\n*Findings ({payload.Findings.Count}):*\n";
            foreach (var f in payload.Findings.Take(10))
            {
                text += $"• {f.Title} ({f.Severity}) - {f.Description}\n";
            }
            if (payload.Findings.Count > 10)
            {
                text += $"... and {payload.Findings.Count - 10} more\n";
            }
        }
        if (payload.AssessmentUrl != null)
        {
            text += $"\n< {payload.AssessmentUrl}|View Assessment Report >";
        }

        var payloadObj = new
        {
            text,
            blocks = new[]
            {
                new
                {
                    type = "header",
                    text = new { type = "plain_text", text = $"{emoji} {payload.Title}" }
                },
                new
                {
                    type = "section",
                    text = new { type = "mrkdwn", text = payload.Message }
                }
            }
        };

        var json = JsonSerializer.Serialize(payloadObj, JsonOptions);
        var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");

        using var response = await _http.PostAsync(_webhookUrl, content, cancellationToken);
        response.EnsureSuccessStatusCode();
    }
}
