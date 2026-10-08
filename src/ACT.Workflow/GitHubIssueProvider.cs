using System.Net.Http;
using System.Text.Json;

namespace ACT.Workflow;

public class GitHubIssueProvider : ITicketProvider
{
    private static readonly JsonSerializerOptions JsonOptions = new();

    private readonly HttpClient _http;
    private readonly Uri _baseUrl;
    private readonly string _repo;

    public string ProviderName => "github";

    public GitHubIssueProvider(HttpClient http, Uri baseUrl, string repo)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _baseUrl = baseUrl ?? throw new ArgumentNullException(nameof(baseUrl));
        _repo = repo ?? throw new ArgumentNullException(nameof(repo));
    }

    public async Task<string> CreateTicketAsync(TicketPayload payload, CancellationToken cancellationToken)
    {
        var body = new
        {
            title = payload.Title,
            body = payload.Description,
            labels = new[] { "security", payload.Severity.ToLowerInvariant() }
        };

        var json = JsonSerializer.Serialize(body, JsonOptions);
        var content = new StringContent(json, System.Text.Encoding.UTF8, "application/json");

        var url = new Uri(_baseUrl, $"/repos/{_repo}/issues");
        using var response = await _http.PostAsync(url, content, cancellationToken);
        response.EnsureSuccessStatusCode();

        var responseJson = await response.Content.ReadAsStringAsync(cancellationToken);
        var document = JsonDocument.Parse(responseJson);
        return document.RootElement.GetProperty("html_url").GetString() ?? string.Empty;
    }
}
