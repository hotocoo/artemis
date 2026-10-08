using System.Net.Http;
using System.Text.Json;

namespace ACT.Workflow;

public class JiraTicketProvider : ITicketProvider
{
    private static readonly JsonSerializerOptions JsonOptions = new();

    private readonly HttpClient _http;
    private readonly Uri _baseUrl;
    private readonly string _projectKey;

    public string ProviderName => "jira";

    public JiraTicketProvider(HttpClient http, Uri baseUrl, string projectKey)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _baseUrl = baseUrl ?? throw new ArgumentNullException(nameof(baseUrl));
        _projectKey = projectKey ?? throw new ArgumentNullException(nameof(projectKey));
    }

    public async Task<string> CreateTicketAsync(TicketPayload payload, CancellationToken cancellationToken)
    {
        var body = new
        {
            fields = new
            {
                project = new { key = _projectKey },
                summary = payload.Title,
                description = payload.Description,
                issuetype = new { name = "Task" },
                priority = new { name = payload.Priority ?? "Medium" },
                labels = new[] { "security", payload.Severity.ToLowerInvariant() }
            }
        };

        var json = JsonSerializer.Serialize(body, JsonOptions);
        var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");

        var url = new Uri(_baseUrl, "/rest/api/3/issue");
        using var response = await _http.PostAsync(url, content, cancellationToken);
        response.EnsureSuccessStatusCode();

        var responseJson = await response.Content.ReadAsStringAsync(cancellationToken);
        var document = JsonDocument.Parse(responseJson);
        return document.RootElement.GetProperty("key").GetString() ?? string.Empty;
    }
}
