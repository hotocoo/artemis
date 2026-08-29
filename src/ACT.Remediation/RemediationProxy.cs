using System.Net;
using System.Net.Security;
using System.Text;

namespace ACT.Remediation;

/// <summary>
/// A local reverse proxy that corrects a vulnerable target's responses in place: every request is
/// forwarded to the upstream origin and the response is rewritten with the planned remediation
/// actions (header injection/removal, Set-Cookie hardening, HTTP->HTTPS redirect). Pointing a
/// check at the proxy's endpoint is how Artemis "fixes on the spot" and then verifies the fix.
/// </summary>
public sealed class RemediationProxy : IAsyncDisposable
{
    private readonly HttpListener _listener;
    private readonly Uri _upstream;
    private readonly IReadOnlyList<RemediationAction> _actions;
    private readonly HttpClient _httpClient;
    private readonly CancellationTokenSource _cts = new();
    private Task? _loop;

    /// <summary>The local endpoint that serves the corrected responses.</summary>
    public string EndpointUrl { get; }

    /// <summary>The upstream origin being remediated.</summary>
    public Uri Upstream { get; }

    /// <summary>Creates a proxy for the given upstream with the given remediation actions.</summary>
    public RemediationProxy(Uri upstream, IReadOnlyList<RemediationAction> actions)
    {
        Upstream = upstream;
        _upstream = upstream;
        _actions = actions;

        var port = GetFreePort();
        EndpointUrl = "http://127.0.0.1:" + port;
        _listener = new HttpListener();
        _listener.Prefixes.Add(EndpointUrl + "/");

        // The upstream is an operator-specified local target (a loopback lab). Trust its
        // self-signed certificate for remediation traffic only when it is a loopback origin.
        var upstreamIsLocal = IsLocalHost(upstream);
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            ConnectTimeout = TimeSpan.FromSeconds(30)
        };
        handler.SslOptions.RemoteCertificateValidationCallback =
            (sender, cert, chain, errors) => errors == SslPolicyErrors.None || upstreamIsLocal;
        _httpClient = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
    }

    /// <summary>Starts listening. Must be called once before use.</summary>
    public void Start()
    {
        _listener.Start();
        _loop = Task.Run(AsyncLoop);
    }

    private async Task AsyncLoop()
    {
        while (!_cts.IsCancellationRequested && _listener.IsListening)
        {
            HttpListenerContext ctx;
            try
            {
                ctx = await _listener.GetContextAsync().ConfigureAwait(false);
            }
            catch
            {
                break;
            }

            _ = Task.Run(() => HandleAsync(ctx));
        }
    }

    private async Task HandleAsync(HttpListenerContext ctx)
    {
        try
        {
            var request = ctx.Request;
            var response = ctx.Response;

            // HTTP->HTTPS redirect remediation: bounce plain-HTTP callers to the secure origin.
            if (_actions.Any(a => a.Kind == RemediationActionKind.ForceHttpsRedirect))
            {
                var httpsUpstream = new UriBuilder(_upstream) { Scheme = Uri.UriSchemeHttps }.Uri;
                var target = httpsUpstream + request.Url!.PathAndQuery;
                response.StatusCode = 301;
                response.Headers.Add("Location", target.ToString());
                response.Close();
                return;
            }

            // Build the upstream URL preserving path, query, and scheme.
            if (request.Url is not { } reqUrl)
            {
                response.StatusCode = 400;
                response.Close();
                return;
            }
            var upstreamUrl = new Uri(_upstream, reqUrl.PathAndQuery);

            using var upstreamRequest = new HttpRequestMessage(TranslateMethod(request.HttpMethod), upstreamUrl);
            var requestHeaders = request.Headers ?? throw new InvalidOperationException("No request headers.");
            foreach (var key in requestHeaders.AllKeys)
            {
                if (key is null || key.Equals("Host", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }
                if (requestHeaders[key] is { } headerVal)
                {
                    upstreamRequest.Headers.TryAddWithoutValidation(key, headerVal);
                }
            }

            if (request.HasEntityBody)
            {
                using var ms = new MemoryStream();
                await request.InputStream.CopyToAsync(ms).ConfigureAwait(false);
                var body = ms.ToArray();
                if (body.Length > 0)
                {
                    upstreamRequest.Content = new ByteArrayContent(body);
                }
            }

            using var upstreamResponse = await _httpClient
                .SendAsync(upstreamRequest, HttpCompletionOption.ResponseHeadersRead, _cts.Token)
                .ConfigureAwait(false);

            response.StatusCode = upstreamResponse.StatusCode == 0 ? 200 : (int)upstreamResponse.StatusCode;

            // Copy upstream response headers, applying remediation transforms.
            var setCookieValues = new List<string>();
            foreach (var header in upstreamResponse.Headers)
            {
                if (ShouldSkipRequestHeader(header.Key))
                {
                    continue;
                }
                AddTransformedHeader(response, header.Key, header.Value.ToString() ?? "");
            }
            if (upstreamResponse.Content is not null)
            {
                foreach (var header in upstreamResponse.Content.Headers)
                {
                    if (header.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
                    {
                        setCookieValues.AddRange(header.Value);
                        continue;
                    }
                    AddTransformedHeader(response, header.Key, header.Value.ToString() ?? "");
                }
            }

            // Inject planned headers that the upstream did NOT send (the common remediation case:
            // a missing HSTS/CSP/security header is added, not just rewritten).
            foreach (var inject in _actions.Where(a => a.Kind == RemediationActionKind.InjectHeader))
            {
                if (inject.HeaderName is not { } name || inject.HeaderValue is not { } value)
                {
                    continue;
                }
                var alreadyPresent = response.Headers.AllKeys
                    .Any(k => string.Equals(k, name, StringComparison.OrdinalIgnoreCase));
                if (!alreadyPresent)
                {
                    response.Headers.Add(name, value);
                }
            }

            // Harden Set-Cookie headers if planned.
            if (_actions.Any(a => a.Kind == RemediationActionKind.HardenSetCookie))
            {
                var attrs = _actions.First(a => a.Kind == RemediationActionKind.HardenSetCookie).HeaderValue ?? "";
                foreach (var cookie in setCookieValues)
                {
                    response.Headers.Add("Set-Cookie", HardenCookie(cookie, attrs));
                }
            }
            else if (setCookieValues.Count > 0)
            {
                foreach (var cookie in setCookieValues)
                {
                    response.Headers.Add("Set-Cookie", cookie);
                }
            }

            // Stream the body back.
            if (upstreamResponse.Content is not null)
            {
                var bodyBytes = await upstreamResponse.Content.ReadAsByteArrayAsync(_cts.Token).ConfigureAwait(false);
                response.ContentLength64 = bodyBytes.Length;
                await response.OutputStream.WriteAsync(bodyBytes).ConfigureAwait(false);
            }

            response.Close();
        }
        catch
        {
            try
            {
                ctx.Response.StatusCode = 502;
                ctx.Response.Close();
            }
            catch
            {
                // best effort
            }
        }
    }

    /// <summary>Applies header injection/removal transforms for a single response header.</summary>
    private void AddTransformedHeader(HttpListenerResponse response, string name, string value)
    {
        var remove = _actions.FirstOrDefault(a =>
            a.Kind == RemediationActionKind.RemoveHeader &&
            a.HeaderName is not null &&
            string.Equals(a.HeaderName, name, StringComparison.OrdinalIgnoreCase));
        if (remove is not null)
        {
            return; // drop this header entirely
        }

        var inject = _actions.FirstOrDefault(a =>
            a.Kind == RemediationActionKind.InjectHeader &&
            a.HeaderName is not null &&
            string.Equals(a.HeaderName, name, StringComparison.OrdinalIgnoreCase));
        if (inject is not null && inject.HeaderValue is not null)
        {
            response.Headers.Add(name, inject.HeaderValue); // replace with the fixed value
            return;
        }

        response.Headers.Add(name, value);
    }

    /// <summary>Ensures a Set-Cookie carries all planned attributes without duplicating existing ones.</summary>
    private static string HardenCookie(string cookie, string attributes)
    {
        var parts = cookie.Split(';', 2, StringSplitOptions.TrimEntries);
        var nameValue = parts[0];
        var existing = parts.Length > 1 ? parts[1] : "";
        var result = new StringBuilder(nameValue);
        if (existing.Length > 0)
        {
            result.Append(';').Append(existing);
        }

        foreach (var attr in attributes.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var attrName = attr.Split(['='], 2)[0].Trim();
            var alreadyPresent = existing.Split(';', StringSplitOptions.RemoveEmptyEntries)
                .Any(p => p.Trim().StartsWith(attrName, StringComparison.OrdinalIgnoreCase));
            if (!alreadyPresent)
            {
                result.Append("; ").Append(attr);
            }
        }

        return result.ToString();
    }

    private static bool ShouldSkipRequestHeader(string name) =>
        name.Equals("Host", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Connection", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Content-Length", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase);

    private static HttpMethod TranslateMethod(string method) => method.ToUpperInvariant() switch
    {
        "GET" => HttpMethod.Get,
        "POST" => HttpMethod.Post,
        "PUT" => HttpMethod.Put,
        "DELETE" => HttpMethod.Delete,
        "HEAD" => HttpMethod.Head,
        "OPTIONS" => HttpMethod.Options,
        "PATCH" => HttpMethod.Patch,
        _ => HttpMethod.Get
    };

    private static bool IsLocalHost(Uri uri) =>
        uri.IsLoopback || uri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase);

    private static int GetFreePort()
    {
        var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            _cts.Cancel();
            _listener.Stop();
            _listener.Close();
            if (_loop is not null)
            {
                await _loop.ConfigureAwait(false);
            }
        }
        catch
        {
            // best effort shutdown
        }
        finally
        {
            _httpClient.Dispose();
            _cts.Dispose();
        }
    }
}
