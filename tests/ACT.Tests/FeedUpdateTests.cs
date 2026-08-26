
using System.Net;
using System.Net.Sockets;
using System.Text;
using ACT.Cli;
using ACT.Contracts;
using ACT.Persistence;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ACT.Tests;

/// <summary>
/// 'artemis feed update' against a LOCAL loopback OSV endpoint: the live-query branch must
/// record honest freshness on success and specific staleness on failure - without any external
/// network. An opt-in test proves the same code path against the real api.osv.dev when the
/// operator sets ARTEMIS_OSV_LIVE=1.
/// </summary>
public sealed class FeedUpdateTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "act-feed-tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task LiveOsvQueryRecordsCurrentFreshness()
    {
        using var server = OsvStubServer.Start(OsvStubServer.SuccessBody);
        var db = CreateDatabase();
        var services = BuildServices(db, server.Endpoint);

        var exit = await FeedCommands.Run(services, ["update"]);

        Assert.Equal(ExitCodes.Ok, exit);
        var version = await db.LatestFeedVersionAsync("osv-test");
        Assert.NotNull(version);
        Assert.True(version!.IsCurrent, "a successful live query must mark the feed current");
        Assert.Contains("live query succeeded", version.Note);
        Assert.False(string.IsNullOrWhiteSpace(version.MetadataHash));
    }

    [Fact]
    public async Task FailingOsvEndpointDegradesToSpecificStaleMarker()
    {
        using var server = OsvStubServer.Start(null, statusCode: 500);
        await using var db = CreateDatabase();
        var services = BuildServices(db, server.Endpoint);

        // Transport-level failure degrades honestly instead of throwing: absence stays visible.
        var exit = await FeedCommands.Run(services, ["update"]);
        Assert.Equal(ExitCodes.Ok, exit);
        var version = await db.LatestFeedVersionAsync("osv-test");
        Assert.NotNull(version);
        Assert.False(version!.IsCurrent);
        Assert.Contains("HTTP 500", version.Note);
    }

    [Fact]
    public async Task UnparseableOsvResponseMarksStaleNotCurrent()
    {
        using var server = OsvStubServer.Start("{ not json at all");
        await using var db = CreateDatabase();
        var services = BuildServices(db, server.Endpoint);

        await FeedCommands.Run(services, ["update"]);
        var version = await db.LatestFeedVersionAsync("osv-test");
        Assert.NotNull(version);
        Assert.False(version!.IsCurrent);
        Assert.Contains("unparseable", version.Note);
    }

    [Fact]
    public async Task NonHttpEndpointFailsClosedLoudly()
    {
        await using var db = CreateDatabase();
        var services = BuildServices(db, new Uri("ftp://example.invalid/v1/query"));

        await Assert.ThrowsAsync<ActException>(() => FeedCommands.Run(services, ["update"]));
    }

    [Fact]
    public async Task RealOsvEndpointIsLiveProvenWhenOptedIn()
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("ARTEMIS_OSV_LIVE"), "1", StringComparison.Ordinal))
        {
            return; // Offline by design; operators may prove the live path explicitly.
        }

        await using var db = CreateDatabase();
        var services = BuildServices(db, new Uri("https://api.osv.dev/v1/query"));
        var exit = await FeedCommands.Run(services, ["update"]);
        Assert.Equal(ExitCodes.Ok, exit);
        var version = await db.LatestFeedVersionAsync("osv-test");
        Assert.NotNull(version);
        Assert.True(version!.IsCurrent,
            "the real api.osv.dev single-query endpoint must answer the production client; note: " + version.Note);
    }

    private ActDatabase CreateDatabase()
    {
        Directory.CreateDirectory(_directory);
        var databasePath = Path.Combine(_directory, Guid.NewGuid().ToString("N") + ".db");
        var database = new ActDatabase(databasePath, new StorageOptions
        {
            DatabasePath = databasePath,
            WalEnabled = false,
            RetentionDays = 90
        });
        database.InitializeAsync().GetAwaiter().GetResult();
        return database;
    }

    private IServiceProvider BuildServices(ActDatabase db, Uri osvEndpoint)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Act:Feeds:Sources:0:Name"] = "osv-test",
            ["Act:Feeds:Sources:0:Kind"] = "Osv",
            ["Act:Feeds:Sources:0:EndpointOrPath"] = osvEndpoint.ToString(),
            ["Act:Feeds:Sources:0:Enabled"] = "true"
        }).Build();

        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(configuration);
        services.AddSingleton(db);
        // Quiet: command output must stay off the process-wide Console.Out - parallel unit
        // tests capture that stream and parse it, so any stray line breaks their JSON reads.
        services.AddSingleton(new GlobalOptions { Quiet = true });
        return services.BuildServiceProvider();
    }

    public void Dispose()
    {
        try { Directory.Delete(_directory, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}

/// <summary>A minimal raw-socket HTTP/1.1 responder standing in for an OSV query endpoint.</summary>
public sealed class OsvStubServer : IDisposable
{
    /// <summary>One real-shaped OSV vulnerability for Newtonsoft.Json below the fix version.</summary>
    public const string SuccessBody = """
        {"vulns":[{"id":"GHSA-TEST-0001","summary":"unit-stub advisory","details":"stub",
        "affected":[{"package":{"ecosystem":"NuGet","name":"Newtonsoft.Json"},
        "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"13.0.2"}]}]}],
        "database_specific":{"severity":"HIGH"}}]}
        """;

    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cancellation = new();
    private readonly Task _loop;

    public Uri Endpoint { get; }

    private OsvStubServer(TcpListener listener, int port, string? body, int statusCode)
    {
        _listener = listener;
        Endpoint = new Uri("http://127.0.0.1:" + port + "/v1/query");
        _loop = LoopAsync(body, statusCode, _cancellation.Token);
    }

    public static OsvStubServer Start(string? body, int statusCode = 200)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return new OsvStubServer(listener, ((IPEndPoint)listener.LocalEndpoint).Port, body, statusCode);
    }

    private async Task LoopAsync(string? body, int statusCode, CancellationToken cancellation)
    {
        var payload = Encoding.UTF8.GetBytes(body ?? "{}");
        try
        {
            while (!cancellation.IsCancellationRequested)
            {
                using var client = await _listener.AcceptTcpClientAsync(cancellation);
                await using var stream = client.GetStream();
                var requestBody = await ReadRequestBodyAsync(stream, cancellation);

                // Mirror the real endpoint's strictness: the query body MUST be camelCase
                // ("package"/"version"). PascalCase members are rejected with HTTP 400, exactly
                // like api.osv.dev rejects them - so a serialization regression can never pass
                // these tests vacuously.
                if (!HasCamelCaseQueryShape(requestBody))
                {
                    statusCode = 400;
                    payload = Encoding.UTF8.GetBytes("{}");
                }

                var head = Encoding.ASCII.GetBytes(
                    "HTTP/1.1 " + statusCode + " reason\r\nContent-Type: application/json\r\nContent-Length: "
                    + payload.Length + "\r\nConnection: close\r\n\r\n");
                await stream.WriteAsync(head, cancellation);
                await stream.WriteAsync(payload, cancellation);
                await stream.FlushAsync(cancellation);
                client.Close();
            }
        }
        catch (OperationCanceledException) { }
        catch (SocketException) { }
        catch (ObjectDisposedException) { }
        catch (IOException) { }
    }

    private static bool HasCamelCaseQueryShape(string requestBody)
    {
        try
        {
            using var document = System.Text.Json.JsonDocument.Parse(requestBody);
            var root = document.RootElement;
            return root.TryGetProperty("package", out var package)
                && package.TryGetProperty("name", out _)
                && package.TryGetProperty("ecosystem", out _)
                && root.TryGetProperty("version", out _)
                && !root.TryGetProperty("Package", out _);
        }
        catch (System.Text.Json.JsonException)
        {
            return false;
        }
    }

    /// <summary>The provider posts one small single-shot request; one read carries head + body.</summary>
    private static async Task<string> ReadRequestBodyAsync(NetworkStream stream, CancellationToken cancellation)
    {
        var buffer = new byte[8192];
        var read = await stream.ReadAsync(buffer, cancellation);
        if (read == 0) return string.Empty;
        var text = Encoding.ASCII.GetString(buffer, 0, read);
        var marker = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        return marker >= 0 ? text[(marker + 4)..] : string.Empty;
    }

    public void Dispose()
    {
        _cancellation.Cancel();
        try { _listener.Stop(); } catch (ObjectDisposedException) { }
        try { _loop.Wait(TimeSpan.FromSeconds(2)); } catch { }
        _cancellation.Dispose();
    }
}
