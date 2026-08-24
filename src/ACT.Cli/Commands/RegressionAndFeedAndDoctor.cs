
using System.Net;
using System.Text.Json;
using ACT.Contracts;
using ACT.Core;
using ACT.Network;
using ACT.Persistence;
using ACT.Policy;
using ACT.Risk;
using ACT.Reporting;
using ACT.Scope;
using Microsoft.Extensions.DependencyInjection;

namespace ACT.Cli;

/// <summary>artemis regression run --finding ID --base-url URL [--fixtures FILE]</summary>
public static class RegressionCommands
{
    public static async Task<int> Run(IServiceProvider services, string[] args)
    {
        if (args.Length == 0 || args[0] != "run")
        {
            Console.Error.WriteLine("usage: artemis regression run --finding FINDING_ID --base-url URL [--fixtures FILE]");
            return ExitCodes.UsageError;
        }

        string? findingIdText = null;
        string? baseUrlText = null;
        string? fixturesFile = null;
        for (var i = 1; i < args.Length - 1; i++)
        {
            if (args[i] == "--finding") findingIdText = args[i + 1];
            if (args[i] == "--base-url") baseUrlText = args[i + 1];
            if (args[i] == "--fixtures") fixturesFile = args[i + 1];
        }
        if (!Guid.TryParse(findingIdText, out var findingId) || baseUrlText is null)
        {
            Console.Error.WriteLine("error: --finding FINDING_ID and --base-url URL are required.");
            return ExitCodes.UsageError;
        }

        var db = services.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();
        var all = await db.ListFindingsAsync(null, null, null, 100000);
        var finding = all.FirstOrDefault(f => f.FindingId == findingId)
            ?? throw ActException.FailClosed(ErrorCategory.Configuration,
                "The requested regression target finding does not exist.",
                $"Finding '{findingId}' was not found in the local store.");

        var fixtures = fixturesFile is null ? AuthorizationFixtureSet.None : FixturesFile.Load(fixturesFile);
        fixtures.Validate();

        var scope = ValidRegressionScope(baseUrlText);
        var compiled = new CompiledScope(scope);
        var validator = new ScopeValidator(compiled, new PinningDnsResolver());
        var limiter = new TokenBucketRateLimiter(scope.RequestsPerSecond);
        var budget = ResourceBudget.FromScope(scope, EngineDefaults.Conservative);

        await using var http = new SafeHttpEngine(validator, validator, budget, limiter, NullLogger.Instance);

        var generated = RegressionGenerator.TryGenerate(finding, fixtures, new Uri(baseUrlText));
        if (generated is null)
        {
            Console.Error.WriteLine("error: this finding class has no executable regression template and no fixtures were supplied.");
            return ExitCodes.UsageError;
        }

        var runner = new RegressionRunner(http);
        var result = await runner.RunAsync(generated, CancellationToken.None);

        return await OutputWriter.WriteAsync(services,
            $"{(result.Passed ? "PASS" : "FAIL")} - {result.DetailSafe}",
            JsonSerializer.Serialize(new
            {
                regressionTestId = result.RegressionTestId,
                findingId = result.FindingId,
                passed = result.Passed,
                detail = result.DetailSafe,
                ranUtc = result.RanUtc
            }, JsonOpts.Indented));
    }

    private static ScopeDefinition ValidRegressionScope(string baseUrlText)
    {
        var uri = new Uri(baseUrlText);
        var port = uri.IsDefaultPort ? (uri.Scheme == "https" ? 443 : 80) : uri.Port;
        return new ScopeDefinition(
            Guid.NewGuid(), Guid.NewGuid(), "regression-runner", "artemis",
            TargetTypeKind.Url, [baseUrlText.TrimEnd('/') + "/"], [],
            [ProtocolKind.Http, ProtocolKind.Https], [PortRange.Single(port)],
            10, 1, TimeSpan.FromMinutes(2), 50,
            [CheckCategory.Authorization], [], true,
            TimeSpan.FromDays(1), RedactionPolicy.Standard,
            "Regression replay against a previously authorized target.");
    }
}

/// <summary>artemis feed update — refreshes configured advisory feeds and records freshness.</summary>
public static class FeedCommands
{
    public static async Task<int> Run(IServiceProvider services, string[] args)
    {
        if (args.Length == 0 || args[0] != "update")
        {
            Console.Error.WriteLine("usage: artemis feed update [--json]");
            return ExitCodes.UsageError;
        }

        var configuration = services.GetRequiredService<IConfiguration>();
        var feedsSection = configuration.GetSection("Act:Feeds:Sources").GetChildren().ToList();

        var results = new List<object>();
        foreach (var source in feedsSection)
        {
            var name = source.GetValue<string>("Name") ?? "";
            var enabled = source.GetValue<bool>("Enabled");
            var kind = source.GetValue<string>("Kind") ?? "";
            var endpointOrPath = source.GetValue<string>("EndpointOrPath") ?? "";

            if (!enabled)
            {
                results.Add(new { feed = name, updated = false, note = "disabled in configuration" });
                continue;
            }

            try
            {
                if (kind.Equals("OfflineFile", StringComparison.OrdinalIgnoreCase))
                {
                    var bytes = File.ReadAllBytes(endpointOrPath);
                    var hash = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();
                    var expected = source.GetValue<string?>("Sha256");
                    if (!string.IsNullOrWhiteSpace(expected) &&
                        !string.Equals(expected, hash, StringComparison.OrdinalIgnoreCase))
                    {
                        throw ActException.FailClosed(ErrorCategory.ExternalFeed,
                            $"Advisory snapshot '{name}' failed its integrity check.",
                            $"SHA-256 mismatch: expected {expected}, got {hash}.");
                    }
                    results.Add(new { feed = name, updated = true, sha256 = hash, retrievedUtc = DateTimeOffset.UtcNow });
                }
                else
                {
                    // Remote feeds are optional integrations; their absence must be visible, not silent.
                    results.Add(new { feed = name, updated = false, note = "remote provider update requires network; marked stale until refreshed" });
                }
            }
            catch (ActException ex) when (ex.Category == ErrorCategory.ExternalFeed)
            {
                throw; // integrity failures fail closed loudly.
            }
        }

        var db = services.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();
        foreach (var entry in results)
        {
            var json = JsonSerializer.Serialize(entry);
            var doc = JsonDocument.Parse(json);
            var name = doc.RootElement.GetProperty("feed").GetString() ?? "";
            var updated = doc.RootElement.TryGetProperty("updated", out var upd) && upd.GetBoolean();
            await db.UpsertFeedAsync(new FeedRecord(name, AdvisoryFeedKind.OfflineFile, "", updated), CancellationToken.None);
            await db.RecordFeedVersionAsync(name, DateTimeOffset.UtcNow,
                doc.RootElement.TryGetProperty("sha256", out var h) ? h.GetString() : null,
                updated, doc.RootElement.TryGetProperty("note", out var n) ? n.GetString() : null, CancellationToken.None);
        }

        return await OutputWriter.WriteAsync(services,
            string.Join(Environment.NewLine, results.Select(r => JsonSerializer.Serialize(r))),
            JsonSerializer.Serialize(results, JsonOpts.Indented));
    }
}

/// <summary>artemis doctor — environment health without touching any target.</summary>
public static class DoctorCommand
{
    public static async Task<int> Run(IServiceProvider services, string[] args)
    {
        var findingsList = new List<(string Check, bool Ok, string Detail)>();

        findingsList.Add(("Configuration", true, "Effective configuration validated at startup (fail-closed)."));

        var databasePath = ResolveDatabasePath(services);
        var directoryWritable = ProbeWrite(Path.GetDirectoryName(Path.GetFullPath(databasePath)) ?? ".");
        findingsList.Add(("Filesystem", directoryWritable,
            $"Data directory for '{databasePath}' {(directoryWritable ? "writable" : "NOT writable")}."));

        try
        {
            var db = services.GetRequiredService<ActDatabase>();
            await db.InitializeAsync();
            findingsList.Add(("Database", true, "Opened and migrated successfully."));
            var chainOk = await db.VerifyChainAsync();
            findingsList.Add(("Audit chain", chainOk, chainOk ? "Hash chain verifies." : "HASH CHAIN BROKEN."));
            var feedVersion = await db.LatestFeedVersionAsync("osv");
            findingsList.Add(("Feeds", feedVersion is not null && feedVersion.IsCurrent,
                feedVersion is null ? "No advisory data yet; dependency severities will be inconclusive." : "Last retrieval " + feedVersion.RetrievedUtc.ToString("u")));
        }
        catch (ActException ex)
        {
            findingsList.Add(("Database", false, ex.SafeMessage));
        }

        var loopbackOpen = await ProbeLoopbackAsync();
        findingsList.Add(("Network stack", loopbackOpen, loopbackOpen ? "Loopback TCP connect works." : "Loopback connect failed - assessment checks cannot run."));

        findingsList.Add(("Checks", true, $"{CheckRegistry.Catalog().Count} built-in web-surface checks registered."));

        var healthy = findingsList.All(f => f.Ok);
        return await OutputWriter.WriteAsync(services,
            string.Join(Environment.NewLine,
                findingsList.Select(f => $"{(f.Ok ? "[ OK ]" : "[FAIL]")} {f.Check}: {f.Detail}") +
                [Environment.NewLine + (healthy ? "doctor verdict: HEALTHY" : "doctor verdict: DEGRADED")]),
            JsonSerializer.Serialize(new { healthy, checks = findingsList.Select(f => new { check = f.Check, ok = f.Ok, detail = f.Detail }) },
                JsonOpts.Indented));
    }

    private static string ResolveDatabasePath(IServiceProvider services)
    {
        var configuration = services.GetRequiredService<IConfiguration>();
        var raw = configuration["Act:Storage:DatabasePath"] ?? "artemis.db";
        return Path.IsPathRooted(raw) ? raw : Path.Combine(AppContext.BaseDirectory, raw);
    }

    private static bool ProbeWrite(string directory)
    {
        try
        {
            Directory.CreateDirectory(directory);
            var probe = Path.Combine(directory, ".artemis-doctor-probe");
            File.WriteAllText(probe, "probe");
            File.Delete(probe);
            return true;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    private static async Task<bool> ProbeLoopbackAsync()
    {
        try
        {
            var listener = new TcpListenerAdapter(IPAddress.Loopback, 0);
            listener.Start();
            var port = listener.Port;
            using var client = new TcpClient();
            await client.ConnectAsync(IPAddress.Loopback, port);
            listener.Stop();
            return client.Connected;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    private sealed class TcpListenerAdapter(IPAddress address, int port)
    {
        private readonly System.Net.Sockets.TcpListener _inner = new(address, port);
        public int Port => ((IPEndPoint)_inner.LocalEndpoint).Port;
        public void Start() => _inner.Start();
        public void Stop() => _inner.Stop();
    }
}
