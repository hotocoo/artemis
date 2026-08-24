using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using ACT.Contracts;

namespace ACT.Llm;

/// <summary>
/// Client for any OpenAI-compatible chat completions endpoint, local or operator-configured
/// remote. The API key is read only from the environment variable named in configuration; every
/// remote failure degrades to a fallback completion instead of surfacing errors to callers.
/// Construction fails closed on configuration problems.
/// </summary>
public sealed class OpenAiCompatibleProvider : ILanguageModelProvider, IDisposable
{
    /// <summary>Stable provider name reported in completions.</summary>
    public const string ProviderName = "openai-compatible";

    private const long MaxResponseBytes = 4 * 1024 * 1024;
    private const double Temperature = 0.2;
    private const string ChatCompletionsSuffix = "/chat/completions";

    private readonly LlmOptions _options;
    private readonly HttpClient _client;
    private bool _disposed;

    public OpenAiCompatibleProvider(LlmOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        ValidateConfiguration(options);
        _options = options;
        _client = new HttpClient { Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds) };
        _client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    }

    /// <inheritdoc />
    public string Name => ProviderName;

    /// <summary>True only while the configured API-key environment variable holds a usable value.</summary>
    public bool IsAvailable => !_disposed && TryReadApiKey(out _);

    /// <summary>
    /// Posts one bounded chat completion request. Remote failures of any kind return a degraded
    /// fallback completion; only operator-requested cancellation propagates.
    /// </summary>
    public async Task<LlmCompletion> CompleteAsync(LlmRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!TryReadApiKey(out var apiKey))
        {
            return new LlmCompletion(string.Empty, UsedFallback: true, ProviderName, TokensEstimated: 0);
        }

        try
        {
            using var httpRequest = new HttpRequestMessage(HttpMethod.Post, BuildChatCompletionsUri())
            {
                Content = new ByteArrayContent(BuildRequestBody(request)),
            };
            httpRequest.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);

            using var response = await _client.SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                return Degraded();
            }

            using var document = JsonDocument.Parse(await ReadCappedAsync(response.Content, cancellationToken));
            var text = document.RootElement.GetProperty("choices")[0]
                .GetProperty("message").GetProperty("content").GetString() ?? string.Empty;
            return new LlmCompletion(text, UsedFallback: false, ProviderName, EstimateTokens(document.RootElement, text));
        }
        catch (Exception) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is not OperationCanceledException and not OutOfMemoryException)
        {
            return Degraded();
        }
    }

    /// <summary>Releases the underlying HTTP client.</summary>
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _client.Dispose();
        GC.SuppressFinalize(this);
    }

    private static void ValidateConfiguration(LlmOptions options)
    {
        var problems = new List<string>();
        if (options.ProviderKind == LlmProviderKind.Disabled)
        {
            problems.Add("LlmProviderKind.Disabled cannot drive this provider; use DisabledLanguageModelProvider.");
        }

        if (!Uri.TryCreate(options.Endpoint, UriKind.Absolute, out var endpoint) ||
            endpoint.Scheme is not (Uri.UriSchemeHttp or Uri.UriSchemeHttps))
        {
            problems.Add("Llm.Endpoint must be an absolute http(s) URI when a provider kind is enabled.");
        }

        if (string.IsNullOrWhiteSpace(options.Model)) problems.Add("Llm.Model must not be blank when enabled.");
        if (options.TimeoutSeconds <= 0) problems.Add("Llm.TimeoutSeconds must be positive.");
        if (problems.Count == 0) return;

        throw ActException.FailClosed(ErrorCategory.Configuration,
            "The language-model provider configuration is invalid.",
            "OpenAI-compatible provider configuration rejected: " + string.Join(" | ", problems));
    }

    private bool TryReadApiKey(out string apiKey)
    {
        apiKey = string.Empty;
        var variableName = _options.ApiKeyEnvironmentVariable;
        if (string.IsNullOrWhiteSpace(variableName)) return false;

        var value = Environment.GetEnvironmentVariable(variableName);
        if (string.IsNullOrWhiteSpace(value)) return false;

        apiKey = value;
        return true;
    }

    private Uri BuildChatCompletionsUri() =>
        new(_options.Endpoint!.TrimEnd('/') + ChatCompletionsSuffix, UriKind.Absolute);

    private byte[] BuildRequestBody(LlmRequest request)
    {
        var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("model", _options.Model);
            writer.WritePropertyName("messages");
            writer.WriteStartArray();
            WriteMessage(writer, "system", request.SystemPrompt);
            WriteMessage(writer, "user", ComposeUserContent(request));
            writer.WriteEndArray();
            writer.WriteNumber("max_tokens", request.MaxOutputTokens > 0 ? request.MaxOutputTokens : _options.MaxOutputTokens);
            writer.WriteNumber("temperature", Temperature);
            writer.WriteEndObject();
        }

        return stream.ToArray();

        static void WriteMessage(Utf8JsonWriter writer, string role, string content)
        {
            writer.WriteStartObject();
            writer.WriteString("role", role);
            writer.WriteString("content", content);
            writer.WriteEndObject();
        }
    }

    private static string ComposeUserContent(LlmRequest request)
    {
        var builder = new StringBuilder(request.Instruction ?? string.Empty);
        foreach (var block in request.UntrustedBlocks)
        {
            builder.Append("\n\n").Append(UntrustedContent.Wrap(block.Label, block.Content));
        }

        return builder.ToString();
    }

    private static async Task<byte[]> ReadCappedAsync(HttpContent content, CancellationToken cancellationToken)
    {
        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[8192];
        long total = 0;
        int read;
        while ((read = await stream.ReadAsync(chunk.AsMemory(0, chunk.Length), cancellationToken)) > 0)
        {
            total += read;
            if (total > MaxResponseBytes)
            {
                throw new IOException("Language-model response exceeded the response size cap.");
            }

            await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken);
        }

        return buffer.ToArray();
    }

    private static int EstimateTokens(JsonElement root, string text)
    {
        if (root.TryGetProperty("usage", out var usage) &&
            usage.TryGetProperty("total_tokens", out var totalTokens) &&
            totalTokens.TryGetInt32(out var parsed) && parsed > 0)
        {
            return parsed;
        }

        return Math.Max(1, text.Length / 4);
    }

    private LlmCompletion Degraded() =>
        new(string.Empty, UsedFallback: true, ProviderName + " degraded", TokensEstimated: 0);
}
