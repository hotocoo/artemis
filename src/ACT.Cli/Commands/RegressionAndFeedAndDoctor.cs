
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using ACT.Contracts;
using ACT.Core;
using ACT.DependencyAnalysis;
using ACT.Network;
using ACT.Persistence;
using ACT.Policy;
using ACT.Reporting;
using ACT.Risk;
using ACT.Scope;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace ACT.Cli;

/// <summary>artemis regression list|show|run - stored re-verification tests for known findings.</summary>
public static class RegressionCommands
{
    public static async Task<int> Run(IServiceProvider services, string[] args)
    {
        if (args.Length == 0)
        {
            Usage();
            return ExitCodes.UsageError;
        }

        return args[0] switch
        {
            "list" => await ListAsync(services, args[1..]),
            "show" => await ShowAsync(services, args[1..]),
            "run" => await RunOneAsync(services, args[1..]),
            _ => await RunOneAsync(services, args) // legacy one-shot form keeps working
        };
    }

    private static void Usage()
    {
        Console.Error.WriteLine("usage: artemis regression list [--assessment ASSESSMENT_ID]");
        Console.Error.WriteLine("       artemis regression show REGRESSION_TEST_ID");
        Console.Error.WriteLine("       artemis regression run --finding FINDING_ID --base-url URL [--fixtures FILE] [--cadence-days N]");
    }

    /// <summary>
    /// Lists stored regression tests with their cadence state. A test is DUE when its scheduled
    /// verification time has elapsed; disabled tests are listed but never due.
    /// </summary>
    private static async Task<int> ListAsync(IServiceProvider services, string[] args)
    {
        Guid? assessmentFilter = null;
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == "--assessment" && Guid.TryParse(args[i + 1], out var parsed)) assessmentFilter = parsed;
        }

        var db = services.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();
        var tests = await db.ListRegressionTestsAsync(500);
        if (assessmentFilter is { } filter)
        {
            tests = [.. tests.Where(t => t.OriginAssessmentId == filter)];
        }

        var assessments = await db.ListAssessmentsAsync(500);
        var names = assessments.ToDictionary(a => a.AssessmentId, a => a.Name);
        var now = DateTimeOffset.UtcNow;

        var human = tests.Count == 0
            ? "no regression tests stored yet - they are captured from fixture-backed authorization findings"
            : string.Join(Environment.NewLine, tests.Select(t =>
            {
                var due = t.Enabled && t.NextRunUtc <= now ? " DUE" : "";
                var lastRun = t.LastRunUtc?.ToString("u") ?? "never";
                return t.RegressionTestId.ToString()[..8] + "  " + (t.Enabled ? "enabled " : "DISABLED") + "  "
                    + t.SuggestedSeverity.ToString().PadRight(14)
                    + RegressionOperations.FormatCadence(t.Cadence).PadRight(20)
                    + "last " + lastRun + "  next " + t.NextRunUtc.ToString("u") + due + "  "
                    + "[assessment " + names.GetValueOrDefault(t.OriginAssessmentId, t.OriginAssessmentId.ToString()[..8]) + "]  "
                    + t.Name;
            }));

        return await OutputWriter.WriteAsync(services, human, JsonSerializer.Serialize(new
        {
            now,
            tests = tests.Select(t => new
            {
                regressionTestId = t.RegressionTestId,
                findingId = t.FindingId,
                assessmentId = t.OriginAssessmentId,
                name = t.Name,
                severity = t.SuggestedSeverity.ToString(),
                enabled = t.Enabled,
                due = t.Enabled && t.NextRunUtc <= now,
                lastRunUtc = t.LastRunUtc,
                nextRunUtc = t.NextRunUtc,
                executable = t.RecipeJson is not null,
                cadence = RegressionOperations.FormatCadence(t.Cadence)
            })
        }, JsonOpts.Indented));
    }

    /// <summary>Shows one stored test in full, including its replay steps and run history.</summary>
    private static async Task<int> ShowAsync(IServiceProvider services, string[] args)
    {
        if (args.Length == 0 || !Guid.TryParse(args[0], out var testId))
        {
            Console.Error.WriteLine("error: regression show requires REGRESSION_TEST_ID.");
            return ExitCodes.UsageError;
        }

        var db = services.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();
        var test = await db.GetRegressionTestAsync(testId)
            ?? throw ActException.FailClosed(ErrorCategory.Persistence,
                "The requested regression test does not exist.",
                $"No stored regression test '{testId}'.");

        var runs = await db.ListTestRunsAsync(testId, 10);
        GeneratedRegression? recipe = null;
        if (test.RecipeJson is not null)
        {
            try { recipe = RegressionRunner.Deserialize(test.RecipeJson); }
            catch (ActException) { recipe = null; } // shown as non-executable below, never hidden
        }

        var human = new StringBuilder()
            .AppendLine(test.Name)
            .AppendLine(new string('-', Math.Min(72, Math.Max(8, test.Name.Length))))
            .AppendLine("id:        " + test.RegressionTestId)
            .AppendLine("finding:   " + test.FindingId)
            .AppendLine("severity:  " + test.SuggestedSeverity)
            .AppendLine("cadence:   " + RegressionOperations.FormatCadence(test.Cadence))
            .AppendLine("state:     " + (test.Enabled ? "enabled" : "disabled")
                + (test.RecipeJson is null ? ", captured before recipes were stored (manual only)" : ""))
            .AppendLine("created:   " + test.CreatedUtc.ToString("u"))
            .AppendLine("last run:  " + (test.LastRunUtc?.ToString("u") ?? "never"))
            .AppendLine("next run:  " + test.NextRunUtc.ToString("u")
                + (test.Enabled && test.NextRunUtc <= DateTimeOffset.UtcNow ? "  (DUE)" : ""))
            .AppendLine();

        if (recipe is { } executable)
        {
            human.AppendLine("replay steps:");
            foreach (var step in executable.Steps)
            {
                human.AppendLine("  given : " + step.Given);
                human.AppendLine("  when  : " + step.When);
                human.AppendLine("  then  : " + step.Then);
                human.AppendLine();
            }
        }
        else
        {
            human.AppendLine("replay steps: none recorded for this row.");
        }

        human.AppendLine(runs.Count == 0 ? "run history: empty." : "recent runs:");
        foreach (var run in runs)
        {
            human.AppendLine($"  {run.RanAtUtc:u}  {run.Result,-12}  {run.Detail}");
        }

        return await OutputWriter.WriteAsync(services, human.ToString(), JsonSerializer.Serialize(new
        {
            test.RegressionTestId,
            test.FindingId,
            test.OriginAssessmentId,
            test.Name,
            test.Description,
            severity = test.SuggestedSeverity.ToString(),
            test.Enabled,
            executable = recipe is not null,
            steps = recipe?.Steps.Select(s => new { s.Given, s.When, s.Then }),
            expectation = recipe?.HttpExpectation is { } e
                ? new { method = e.Method.ToString(), urlPath = e.Url.PathAndQuery, e.ExpectedStatusMin, e.ExpectedStatusMax }
                : null,
            runs = runs.Select(r => new { r.RanAtUtc, result = r.Result.ToString(), detail = r.Detail })
        }, JsonOpts.Indented));
    }

    /// <summary>
    /// Generates the regression for one finding, stores it durably (upsert per finding), executes
    /// it through the safe engine against an explicitly provided base URL, and records the verdict
    /// on the cadence schedule with an audited event.
    /// </summary>
    private static async Task<int> RunOneAsync(IServiceProvider services, string[] args)
    {
        string? findingIdText = null;
        string? baseUrlText = null;
        string? fixturesFile = null;
        string? actorFlag = null;
        double? cadenceDays = null;
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == "--finding") findingIdText = args[i + 1];
            if (args[i] == "--base-url") baseUrlText = args[i + 1];
            if (args[i] == "--fixtures") fixturesFile = args[i + 1];
            if (args[i] == "--actor") actorFlag = args[i + 1];
            if (args[i] == "--cadence-days" && double.TryParse(args[i + 1], System.Globalization.CultureInfo.InvariantCulture, out var days)) cadenceDays = days;
        }

        if (!Guid.TryParse(findingIdText, out var findingId))
        {
            Usage();
            Console.Error.WriteLine("error: --finding FINDING_ID and --base-url URL are required.");
            return ExitCodes.UsageError;
        }

        if (baseUrlText is null || !Uri.TryCreate(baseUrlText, UriKind.Absolute, out var baseUrl)
            || (baseUrl.Scheme != "http" && baseUrl.Scheme != "https"))
        {
            Usage();
            Console.Error.WriteLine("error: --base-url must be an absolute http(s) URL.");
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

        // The replay runs inside a minimal single-target scope derived from the operator-provided
        // base URL, so every request inherits full scope enforcement instead of raw HttpClient.
        var scope = ValidRegressionScope(baseUrlText);
        var compiled = new CompiledScope(scope);
        var validator = new ScopeValidator(compiled, new PinningDnsResolver());
        var limiter = new TokenBucketRateLimiter(scope.RequestsPerSecond);
        var budget = ResourceBudget.FromScope(scope, EngineDefaults.Conservative);

        await using var http = new SafeHttpEngine(validator, validator, budget, limiter, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);

        var generated = RegressionGenerator.TryGenerate(finding, fixtures, baseUrl);
        if (generated is null || generated.HttpExpectation is null)
        {
            Console.Error.WriteLine("error: no executable HTTP regression exists for this finding without "
                + "authorization fixtures describing at least two principals and one object.");
            return ExitCodes.UsageError;
        }

        var actor = actorFlag ?? "operator-cli";
        var correlation = CorrelationId.New();
        var test = await RegressionOperations.StoreForFindingAsync(
            db, finding.AssessmentId, finding, generated, actor, correlation,
            cadenceDays is { } chosenDays ? TimeSpan.FromDays(chosenDays) : null);

        var runner = new RegressionRunner(http);
        var result = await runner.RunAsync(generated, CancellationToken.None);
        var recorded = await RegressionOperations.RecordRunOutcomeAsync(db, test, result, actor, correlation);

        return await OutputWriter.WriteAsync(services,
            $"{(result.Passed ? "PASS" : "FAIL")} - {result.DetailSafe} (test {test.RegressionTestId.ToString()[..8]}, next run {test.NextRunUtc:u})",
            JsonSerializer.Serialize(new
            {
                regressionTestId = test.RegressionTestId,
                findingId = result.FindingId,
                passed = result.Passed,
                detail = result.DetailSafe,
                recordedResult = recorded.Result.ToString(),
                ranUtc = result.RanUtc
            }, JsonOpts.Indented));
    }

    private static ScopeDefinition ValidRegressionScope(string baseUrlText)
    {
        var uri = new Uri(baseUrlText);
        var port = uri.IsDefaultPort ? (uri.Scheme == "https" ? 443 : 80) : uri.Port;

        // The DNS-pinning gate authorizes the HOST before any socket connects, and resolved
        // addresses are only ever covered by hostname/IP-range matchers - a bare URL prefix
        // entry alone can never satisfy either check. The replay scope therefore allowlists the
        // host itself (CIDR form for address literals, exact-hostname form otherwise) next to
        // the URL prefix that keeps request-level authorization path-scoped. Tcp is permitted
        // because the pinning gate classifies every non-default port as a Tcp candidate; the
        // replayed HTTP requests themselves still speak http/https on top of that socket.
        string hostEntry;
        if (IPAddress.TryParse(uri.Host, out var literal))
        {
            hostEntry = literal + (literal.AddressFamily == AddressFamily.InterNetwork ? "/32" : "/128");
        }
        else
        {
            hostEntry = uri.Host;
        }

        return new ScopeDefinition(
            Guid.NewGuid(), Guid.NewGuid(), "regression-runner", "artemis",
            TargetTypeKind.Url, [baseUrlText.TrimEnd('/') + "/", hostEntry], [],
            [ProtocolKind.Tcp, ProtocolKind.Http, ProtocolKind.Https], [PortRange.Single(port)],
            10, 1, TimeSpan.FromMinutes(2), 50,
            [CheckCategory.Authorization], [], true,
            TimeSpan.FromDays(1), RedactionPolicy.Standard,
            "Regression replay against a previously authorized target.");
    }
}

/// <summary>artemis feed update — refreshes configured advisory feeds and records freshness.</summary>
public static class FeedCommands
{
    /// <summary>
    /// The pinned probe package for OSV liveness: a historical NuGet version whose advisory set
    /// is stable. The round trip proves endpoint reachability and response parseability end to
    /// end through the production advisory client; the result COUNT is reported, never assumed.
    /// </summary>
    private const string OsvProbeEcosystem = "NuGet";
    private const string OsvProbePackage = "Newtonsoft.Json";
    private const string OsvProbeVersion = "9.0.0";

    private sealed record FeedUpdateOutcome(
        string Name,
        AdvisoryFeedKind Kind,
        string EndpointOrPath,
        bool Enabled,
        bool Updated,
        string MetadataHash,
        string Note);

    public static async Task<int> Run(IServiceProvider services, string[] args)
    {
        if (args.Length == 0 || args[0] != "update")
        {
            Console.Error.WriteLine("usage: artemis feed update [--json]");
            return ExitCodes.UsageError;
        }

        var configuration = services.GetRequiredService<IConfiguration>();
        var feedsSection = configuration.GetSection("Act:Feeds:Sources").GetChildren().ToList();

        var results = new List<FeedUpdateOutcome>();
        foreach (var source in feedsSection)
        {
            var name = source.GetValue<string>("Name") ?? "";
            var enabled = source.GetValue<bool>("Enabled");
            var kindText = source.GetValue<string>("Kind") ?? "";
            var endpointOrPath = source.GetValue<string>("EndpointOrPath") ?? "";

            if (!enabled)
            {
                results.Add(new FeedUpdateOutcome(name, AdvisoryFeedKind.OfflineFile, endpointOrPath,
                    Enabled: false, Updated: false, "", "disabled in configuration"));
                continue;
            }

            try
            {
                if (kindText.Equals("OfflineFile", StringComparison.OrdinalIgnoreCase))
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
                    results.Add(new FeedUpdateOutcome(name, AdvisoryFeedKind.OfflineFile, endpointOrPath,
                        Enabled: true, Updated: true, hash, ""));
                }
                else if (kindText.Equals("Osv", StringComparison.OrdinalIgnoreCase))
                {
                    // A LIVE OSV query through the production client. Success advances the feed's
                    // recorded freshness honestly; any transport or parse failure degrades to a
                    // stale marker carrying the specific reason - absence stays visible, silent.
                    if (!Uri.TryCreate(endpointOrPath, UriKind.Absolute, out var osvEndpoint)
                        || osvEndpoint.Scheme is not ("http" or "https"))
                    {
                        throw ActException.FailClosed(ErrorCategory.ExternalFeed,
                            $"The OSV feed '{name}' has an invalid endpoint.",
                            $"EndpointOrPath '{endpointOrPath}' is not an absolute HTTP(S) URI.");
                    }

                    var staleAfterDays = source.GetValue<int?>("StaleAfterDays")
                        ?? configuration.GetValue<int?>("Act:Feeds:StaleAfterDays") ?? 7;
                    using var provider = new OsvAdvisoryProvider(
                        osvEndpoint, staleAfterDays > 0 ? staleAfterDays : 7);
                    var lookup = await provider.QueryAsync(
                        OsvProbeEcosystem, OsvProbePackage, OsvProbeVersion, CancellationToken.None)
                        .ConfigureAwait(false);
                    var canonical = OsvProbeEcosystem + "|" + OsvProbePackage + "|" + OsvProbeVersion + "|"
                        + lookup.Advisories.Count + "|"
                        + string.Join(",", lookup.Advisories.Select(static a => a.MetadataHash));
                    var digest = Convert.ToHexString(
                        System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(canonical)))
                        .ToLowerInvariant();
                    results.Add(new FeedUpdateOutcome(name, AdvisoryFeedKind.Osv, endpointOrPath,
                        Enabled: true, Updated: lookup.Freshness.IsCurrent, digest,
                        lookup.Freshness.IsCurrent
                            ? "live query succeeded (" + lookup.Advisories.Count + " advisories for the probe package)"
                            : lookup.Freshness.Note));
                }
                else
                {
                    // Unknown remote kinds are optional integrations; their absence must stay visible.
                    results.Add(new FeedUpdateOutcome(name, AdvisoryFeedKind.OfflineFile, endpointOrPath,
                        Enabled: true, Updated: false, "",
                        "remote provider kind '" + kindText + "' has no live updater; marked stale until refreshed"));
                }
            }
            catch (ActException ex) when (ex.Category == ErrorCategory.ExternalFeed)
            {
                throw; // integrity/configuration failures fail closed loudly.
            }
        }

        var db = services.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();
        foreach (var entry in results)
        {
            await db.UpsertFeedAsync(new FeedRecord(
                entry.Name, entry.Kind, entry.EndpointOrPath, entry.Enabled, DateTimeOffset.UtcNow));
            await db.RecordFeedVersionAsync(entry.Name, DateTimeOffset.UtcNow, entry.MetadataHash, entry.Updated, entry.Note);
        }

        var text = string.Join(Environment.NewLine, results.Select(r =>
            r.Name + ": " + (r.Updated ? "updated" : "NOT current") + (r.Note.Length > 0 ? " - " + r.Note : "")));
        return await OutputWriter.WriteAsync(services, text, JsonSerializer.Serialize(results.Select(r => new
        {
            feed = r.Name,
            kind = r.Kind.ToString(),
            updated = r.Updated,
            sha256 = r.MetadataHash,
            note = r.Note
        }), JsonOpts.Indented));
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
                findingsList.Select(f => $"{(f.Ok ? "[ OK ]" : "[FAIL]")} {f.Check}: {f.Detail}")
                    .Append(healthy ? "doctor verdict: HEALTHY" : "doctor verdict: DEGRADED")),
            JsonSerializer.Serialize(new { healthy, checks = findingsList.Select(f => new { check = f.Check, ok = f.Ok, detail = f.Detail }) },
                JsonOpts.Indented));
    }

    private static string ResolveDatabasePath(IServiceProvider services)
    {
        // One database-location rule shared with composition, config, and the console host.
        return Composition.ArtemisComposition.ResolveDatabasePath(services.GetRequiredService<IConfiguration>());
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
