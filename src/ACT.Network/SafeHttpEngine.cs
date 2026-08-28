
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using ACT.Contracts;
using ACT.Scope;
using Microsoft.Extensions.Logging;

namespace ACT.Network;

/// <summary>
/// The only HTTP path checks may use. Enforces, in order: rate limiting, scope authorization of
/// the initial URL, per-hop redirect re-authorization with TLS-downgrade blocking, DNS pinning,
/// connection caps, timeouts, hard response/body size limits including after decompression.
/// A hostile target cannot make this engine leave scope or exhaust memory by streaming forever.
/// </summary>
public sealed class SafeHttpEngine : ISafeHttpEngine
{
    private const string ProductUserAgent = "artemis-scanner/1.0";
    private const int MaxRequestBodyBytes = 64 * 1024;

    private readonly IScopeValidator _scopeValidator;
    private readonly IDnsGate _dnsGate;
    private readonly ResourceBudget _budget;
    private readonly IRateLimiter _limiter;
    private readonly ILogger _logger;
    private readonly HttpClient _client;

    public SafeHttpEngine(IScopeValidator scopeValidator, IDnsGate dnsGate, ResourceBudget budget,
        IRateLimiter limiter, ILogger logger)
    {
        _scopeValidator = scopeValidator;
        _dnsGate = dnsGate;
        _budget = budget;
        _limiter = limiter;
        _logger = logger;

        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            AutomaticDecompression = DecompressionMethods.None,
            MaxConnectionsPerServer = budget.MaxConnectionsPerHost,
            ConnectTimeout = budget.PerOperationTimeout,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5)
        };
        handler.ConnectCallback += PinToVerifiedAddressAsync;

        _client = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan // per-request timeout enforced via linked CTS
        };
    }

    /// <summary>Connects only to addresses the DNS gate verified for this assessment.</summary>
    private async ValueTask<Stream> PinToVerifiedAddressAsync(SocketsHttpConnectionContext context, CancellationToken cancellationToken)
    {
        var verified = await _dnsGate.ResolveVerifiedAsync(context.DnsEndPoint.Host, context.DnsEndPoint.Port, cancellationToken);

        Exception? lastError = null;
        foreach (var address in verified)
        {
            try
            {
                var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
                {
                    NoDelay = true
                };
                await socket.ConnectAsync(address, context.DnsEndPoint.Port, cancellationToken);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (SocketException ex)
            {
                lastError = ex;
            }
        }
        throw ActException.FailClosed(ErrorCategory.Network,
            "No verified address accepted the connection.",
            $"Connect failed to all pinned addresses of '{context.DnsEndPoint.Host}:{context.DnsEndPoint.Port}'.",
            lastError);
    }

    public async Task<SafeHttpResponse> SendAsync(SafeHttpRequest request, CancellationToken cancellationToken)
    {
        if (request.Body is { } body && body.Length > MaxRequestBodyBytes)
        {
            throw ActException.FailClosed(ErrorCategory.SecurityCheck,
                "A request body exceeded the engine's hard limit.",
                $"Request body of {body.Length} bytes exceeded {MaxRequestBodyBytes}.");
        }

        await _limiter.WaitForTokenAsync(cancellationToken);

        var verdict = _scopeValidator.Evaluate(TargetCandidate.FromUri(request.Url));
        if (!verdict.Allowed)
        {
            throw ActException.FailClosed(ErrorCategory.Scope, verdict.SafeMessage, verdict.DiagnosticDetail);
        }

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();
        var trail = new List<RedirectHop>();
        var currentUrl = request.Url;
        var currentMethod = request.Method;
        HttpResponseMessage? response = null;

        var timeout = request.TimeoutOverride ?? _budget.PerOperationTimeout;
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        linked.CancelAfter(timeout);

        try
        {
            for (var hop = 0; ; hop++)
            {
                using var message = new HttpRequestMessage(currentMethod, currentUrl);
                foreach (var header in request.Headers)
                {
                    message.Headers.TryAddWithoutValidation(header.Key, header.Value);
                }
                if (request.Headers.Keys.All(k => !k.Equals("User-Agent", StringComparison.OrdinalIgnoreCase)))
                {
                    message.Headers.TryAddWithoutValidation("User-Agent", ProductUserAgent);
                }
                if (request.Body is { } payload &&
                    (currentMethod == HttpMethod.Post || currentMethod == HttpMethod.Put))
                {
                    message.Content = new ByteArrayContent(payload.ToArray());
                }

                response = await _client.SendAsync(message, HttpCompletionOption.ResponseHeadersRead, linked.Token)
                    .ConfigureAwait(false);

                var status = (int)response.StatusCode;
                if (status is 301 or 302 or 303 or 307 or 308)
                {
                    var location = response.Headers.Location;
                    if (location is null)
                    {
                        break; // Malformed redirect: treat as final response.
                    }
                    var next = location.IsAbsoluteUri ? location : new Uri(currentUrl, location);
                    var redirectVerdict = _scopeValidator.EvaluateRedirect(currentUrl, next);
                    if (!redirectVerdict.Allowed)
                    {
                        response.Dispose();
                        throw ActException.FailClosed(ErrorCategory.Scope,
                            redirectVerdict.SafeMessage, redirectVerdict.DiagnosticDetail);
                    }
                    trail.Add(new RedirectHop(currentUrl, next, status));
                    if (trail.Count > _budget.MaxRedirects)
                    {
                        response.Dispose();
                        throw ActException.FailClosed(ErrorCategory.Network,
                            "A redirect chain exceeded the configured maximum length.",
                            $"More than {_budget.MaxRedirects} redirects from '{request.Url}'.");
                    }
                    var nextMethod = status is 307 or 308 ? currentMethod : HttpMethod.Get;
                    response.Dispose();
                    currentUrl = next;
                    currentMethod = nextMethod;
                    await _limiter.WaitForTokenAsync(linked.Token);
                    continue;
                }
                break;
            }

            if (response is null)
            {
                throw ActException.FailClosed(ErrorCategory.Network,
                    "No HTTP response was obtained.",
                    $"Request '{currentMethod} {currentUrl}' completed without a response object.");
            }

            var bodyBytes = await ReadBoundedBodyAsync(response, linked.Token);
            stopwatch.Stop();

            var headers = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            foreach (var header in response.Headers.Concat(response.Content.Headers))
            {
                headers[header.Key] = header.Value.ToArray();
            }

            return new SafeHttpResponse(
                StatusCode: (int)response.StatusCode,
                Headers: headers,
                BodyBytes: bodyBytes.Bytes,
                FinalUri: currentUrl,
                RedirectTrail: trail,
                Elapsed: stopwatch.Elapsed,
                Correlation: request.Correlation,
                TruncatedDueToLimits: bodyBytes.Truncated,
                ContentType: response.Content.Headers.ContentType?.ToString());
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw ActException.FailClosed(ErrorCategory.Network,
                "The target did not respond within the configured timeout.",
                $"Request '{currentMethod} {currentUrl}' timed out after {timeout.TotalSeconds}s.");
        }
        finally
        {
            response?.Dispose();
        }
    }

    /// <summary>
    /// Reads at most MaxResponseBytes of transfer encoding, then decompresses with an equally hard
    /// cap on the OUTPUT side. This is the decompression-bomb defense.
    /// </summary>
    private async Task<(byte[] Bytes, bool Truncated)> ReadBoundedBodyAsync(HttpResponseMessage response, CancellationToken cancellationToken)
    {
        var contentLength = response.Content.Headers.ContentLength;
        if (contentLength.HasValue && contentLength.Value > _budget.MaxResponseBytes)
        {
            return ([], true);
        }

        await using var raw = await response.Content.ReadAsStreamAsync(cancellationToken);

        var encodingHeader = (response.Content.Headers.ContentEncoding?.ToString() ?? string.Empty).ToLowerInvariant();
        Stream decoded = encodingHeader.Contains("gzip") ? new GZipStream(raw, CompressionMode.Decompress)
            : encodingHeader.Contains("deflate") ? new DeflateStream(raw, CompressionMode.Decompress)
            : encodingHeader.Contains("br") ? new BrotliStream(raw, CompressionMode.Decompress)
            : raw;

        try
        {
            using var buffer = new MemoryStream();
            var chunk = new byte[64 * 1024];
            long totalDecompressed = 0;
            while (true)
            {
                var read = await decoded.ReadAsync(chunk.AsMemory(0, chunk.Length), cancellationToken);
                if (read <= 0) break;
                totalDecompressed += read;
                if (totalDecompressed > _budget.MaxBodyBytes || buffer.Length + read > _budget.MaxResponseBytes)
                {
                    return (buffer.ToArray(), true);
                }
                buffer.Write(chunk, 0, read);
            }
            return (buffer.ToArray(), false);
        }
        finally
        {
            if (!ReferenceEquals(decoded, raw)) await decoded.DisposeAsync();
        }
    }

    public ValueTask DisposeAsync()
    {
        _client.Dispose();
        return ValueTask.CompletedTask;
    }
}
