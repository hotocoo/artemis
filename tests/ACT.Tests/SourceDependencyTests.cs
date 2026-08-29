
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using ACT.Contracts;
using ACT.DependencyAnalysis;
using ACT.SourceAnalysis;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace ACT.Tests;

// Test doubles live only inside the test assembly.
internal sealed class SrcDepTempDir : IDisposable
{
    public SrcDepTempDir()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "artemis-srcdep-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public string Write(string relative, string contentText)
    {
        var full = System.IO.Path.Combine(Path, relative.Replace('/', System.IO.Path.DirectorySeparatorChar));
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(full)!);
        File.WriteAllText(full, contentText);
        return full;
    }

    public void Dispose()
    {
        try { Directory.Delete(Path, recursive: true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}

internal sealed class SrcDepRecordingEvidenceFactory : IEvidenceFactory
{
    public List<EvidenceItem> Items { get; } = [];

    public EvidenceItem Create(Guid findingId, EvidenceKind kind, string key, string value,
        CheckId collectedBy, CorrelationId correlation, IReadOnlyDictionary<string, string>? attributes = null)
    {
        var item = new EvidenceItem(
            Guid.NewGuid(), findingId, kind, key, value,
            DateTimeOffset.UtcNow, collectedBy, correlation,
            attributes ?? new Dictionary<string, string>());
        Items.Add(item);
        return item;
    }
}

internal sealed class SrcDepNoopRateLimiter : IRateLimiter
{
    public ValueTask WaitForTokenAsync(CancellationToken cancellationToken) => ValueTask.CompletedTask;
}

internal sealed class SrcDepAllowAllScopeValidator : IScopeValidator
{
    public ScopeDecision Evaluate(TargetCandidate candidate) => ScopeDecision.Allow("unit-test", "test allow.");
    public ScopeDecision EvaluateRedirect(Uri originalUri, Uri redirectTarget) => ScopeDecision.Allow("unit-test", "test allow.");

    public Task<ScopeDecision> EvaluateResolvedAsync(string host, int port, CancellationToken cancellationToken) =>
        Task.FromResult(ScopeDecision.Allow("unit-test", "test allow."));
}

internal sealed class SrcDepThrowingHttpEngine : ISafeHttpEngine
{
    public Task<SafeHttpResponse> SendAsync(SafeHttpRequest request, CancellationToken cancellationToken) =>
        throw new NotSupportedException("Local-only checks never send HTTP requests.");

    public ValueTask DisposeAsync() => ValueTask.CompletedTask;
}

internal sealed class SrcDepInMemoryLedger : IAssessmentLedger
{
    public Task<AssetRecord> RecordAssetAsync(AssetRecord asset, CancellationToken cancellationToken) => Task.FromResult(asset);
    public Task<ServiceObservation> RecordServiceAsync(ServiceObservation service, CancellationToken cancellationToken) => Task.FromResult(service);
    public IReadOnlyList<ServiceObservation> ObservedServices() => [];
}

internal sealed class SrcDepSlowAdvisoryProvider : ISecurityAdvisoryProvider
{
    private readonly TimeSpan _delay;

    public SrcDepSlowAdvisoryProvider(TimeSpan delay) => _delay = delay;

    public string Name => "slow-unit-test";

    public async Task<AdvisoryLookupResult> QueryAsync(string ecosystem, string packageName, string version, CancellationToken cancellationToken)
    {
        await Task.Delay(_delay, cancellationToken);
        return new AdvisoryLookupResult(ecosystem, packageName, version, [], new FeedFreshness(true, DateTimeOffset.UtcNow, "ok"));
    }

    public Task<FeedFreshness> GetFreshnessAsync(CancellationToken cancellationToken) =>
        Task.FromResult(new FeedFreshness(true, DateTimeOffset.UtcNow, "fresh"));
}

internal static class SrcDepHarness
{
    public static ResourceBudget Budget() => new(
        MaxConcurrency: 2,
        MaxRequests: 100,
        MaxResponseBytes: 1 << 20,
        MaxBodyBytes: 1 << 20,
        MaxFileBytes: 10 << 20,
        MemoryBudgetBytes: 64L << 20,
        PerOperationTimeout: TimeSpan.FromMilliseconds(250),
        TotalRuntime: TimeSpan.FromMinutes(2),
        MaxConnectionsPerHost: 2,
        MaxRedirects: 2);

    public static SecurityCheckContext CreateContext(string repoRoot, IEvidenceFactory evidence, AssetKind kind = AssetKind.Repository)
    {
        var scope = new ScopeDefinition(
            Guid.NewGuid(), Guid.NewGuid(), "unit-test-operator", "unit-test-org",
            TargetTypeKind.LocalSourceRepository,
            AllowlistedTargets: [repoRoot],
            ExcludedTargets: [],
            PermittedProtocols: [ProtocolKind.Tcp],
            PermittedPorts: [PortRange.Single(1)],
            RequestsPerSecond: 1, ConcurrencyLimit: 1,
            MaxRuntime: TimeSpan.FromMinutes(5), MaxRequests: 10,
            AllowedCategories: [CheckCategory.Source, CheckCategory.Dependency],
            ProhibitedCategories: [],
            EmergencyStopEnabled: true,
            EvidenceRetentionPeriod: TimeSpan.FromDays(30),
            DataRedactionPolicy: RedactionPolicy.Standard,
            AuthorizationStatement: "Authorized for automated defensive testing.");

        var assessment = new AssessmentContext(
            scope.AssessmentId, scope,
            new SrcDepAllowAllScopeValidator(),
            new SrcDepThrowingHttpEngine(),
            new SrcDepNoopRateLimiter(),
            evidence,
            NullLogger.Instance,
            AuthorizationFixtureSet.None,
            Budget(),
            new SrcDepInMemoryLedger(),
            LanguageModel: null)
        { CancellationToken = CancellationToken.None };

        var asset = new AssetRecord(
            Guid.NewGuid(), assessment.AssessmentId, kind, "repo-under-test",
            repoRoot, [], DateTimeOffset.UtcNow, WithinScope: true);

        return new SecurityCheckContext(assessment, asset, Service: null, BaseUrl: null);
    }

    public static async Task<List<RepositoryWalkEntry>> CollectAsync(RepositoryWalker walker)
    {
        var entries = new List<RepositoryWalkEntry>();
        await foreach (var entry in walker.WalkAsync())
        {
            entries.Add(entry);
        }

        return entries;
    }

    public static async Task<List<RuleScanResult>> ScanTreeAsync(string rootPath)
    {
        var engine = new SourceRuleEngine();
        var results = new List<RuleScanResult>();
        var walker = new RepositoryWalker(rootPath);
        await foreach (var entry in walker.WalkAsync())
        {
            if (entry is DiscoveredFile file)
            {
                results.Add(await engine.EvaluateAsync(file.File, file.File.EnumerateLinesAsync(), CancellationToken.None));
            }
        }

        return results;
    }

    public static List<SourceRuleMatch> MatchesFor(IReadOnlyList<RuleScanResult> scans, string ruleId) =>
        scans.SelectMany(static r => r.Matches).Where(m => m.Rule.RuleId == ruleId).ToList();
}



// ============================================================================
// Walker tests.
// ============================================================================

public class SrcDepRepositoryWalkerTests
{
    [Fact]
    public async Task Walk_SkipsWellKnownDirectories()
    {
        using var root = new SrcDepTempDir();
        root.Write("src/app.cs", "class A { }");
        root.Write("node_modules/lib.js", "module.exports = 1;");
        root.Write("bin/x.bin", "BINARY");
        root.Write("obj/a.cache", "x");
        root.Write(".git/config", "[core]");
        root.Write("dist/out.js", "var x;");
        root.Write("target/debug/t.rs", "fn main() {}");

        var walker = new RepositoryWalker(root.Path);
        var entries = await SrcDepHarness.CollectAsync(walker);

        var discovered = entries.OfType<DiscoveredFile>().Select(static e => e.File.RelativePath).ToList();
        Assert.Equal(["src/app.cs"], discovered);
        Assert.True(walker.Counters.Snapshot().IgnoredDirectories >= 6);
    }

    [Fact]
    public async Task SymlinkEscapes_AreObservedAndNeverFollowed()
    {
        using var root = new SrcDepTempDir();
        using var outside = new SrcDepTempDir();
        var outsideFile = outside.Write("outside-secret.txt", "must-not-be-read-through-link");
        root.Write("inside.cs", "class B { }");

        new FileInfo(System.IO.Path.Combine(root.Path, "link.txt")).CreateAsSymbolicLink(outsideFile);
        new DirectoryInfo(System.IO.Path.Combine(root.Path, "escdir")).CreateAsSymbolicLink(outside.Path);

        var walker = new RepositoryWalker(root.Path);
        var entries = await SrcDepHarness.CollectAsync(walker);

        var escapes = entries.OfType<SymlinkEscapeObservation>().ToList();
        var discoveredNames = entries.OfType<DiscoveredFile>().Select(static e => e.File.RelativePath).ToList();

        Assert.Equal(2, escapes.Count);
        Assert.Equal(["inside.cs"], discoveredNames);
    }

    [Fact]
    public async Task OversizeFiles_AreSkippedWithCounter()
    {
        using var root = new SrcDepTempDir();
        root.Write("small.txt", "tiny");
        root.Write("big.txt", new string('x', 128));

        var walker = new RepositoryWalker(root.Path, new RepositoryAnalysisLimits { MaxFileBytes = 16 });
        var entries = await SrcDepHarness.CollectAsync(walker);

        var skipped = entries.OfType<OversizedFileSkipped>().ToList();
        var stats = walker.Counters.Snapshot();
        Assert.Single(skipped);
        Assert.Equal("big.txt", skipped[0].RelativePath);
        Assert.Equal(128, skipped[0].SizeBytes);
        Assert.Equal(1, stats.OversizedFilesSkipped);
        Assert.Equal(1, stats.FilesDiscovered);
    }

    [Fact]
    public async Task DepthCap_StopsDescent()
    {
        using var root = new SrcDepTempDir();
        root.Write("a/top.cs", "// t");
        root.Write("a/b/deep.cs", "// d");

        var walker = new RepositoryWalker(root.Path, new RepositoryAnalysisLimits { MaxDepth = 1 });
        var entries = await SrcDepHarness.CollectAsync(walker);

        var names = entries.OfType<DiscoveredFile>().Select(static e => e.File.RelativePath).ToList();
        Assert.Equal(["a/top.cs"], names);
        Assert.Equal(1, walker.Counters.Snapshot().DepthLimitedDirectories);
    }

    [Fact]
    public async Task InvalidUtf8_DecodesWithReplacementCharacters()
    {
        using var root = new SrcDepTempDir();
        var payload = new byte[] { 0x61, 0xFF, 0x62, 0x0A, 0x63 };
        await File.WriteAllBytesAsync(System.IO.Path.Combine(root.Path, "raw.py"), payload);

        var walker = new RepositoryWalker(root.Path);
        var entries = await SrcDepHarness.CollectAsync(walker);
        var file = entries.OfType<DiscoveredFile>().Single();
        var lines = new List<FileLine>();
        await foreach (var line in file.File.EnumerateLinesAsync())
        {
            lines.Add(line);
        }

        Assert.Equal(2, lines.Count);
        Assert.Contains('\uFFFD', lines[0].Text);
        Assert.Equal("c", lines[1].Text);
    }

    [Theory]
    [InlineData("main.cs", SourceLanguage.Cs)]
    [InlineData("index.ts", SourceLanguage.Ts)]
    [InlineData("app.js", SourceLanguage.Js)]
    [InlineData("tool.py", SourceLanguage.Py)]
    [InlineData("lib.rs", SourceLanguage.Rust)]
    [InlineData("query.sql", SourceLanguage.Sql)]
    [InlineData("cfg.yaml", SourceLanguage.Yaml)]
    [InlineData("data.json", SourceLanguage.Json)]
    [InlineData("Dockerfile", SourceLanguage.Dockerfile)]
    [InlineData("run.sh", SourceLanguage.Shell)]
    [InlineData("blob.xyz", SourceLanguage.Unknown)]
    public void LanguageDetection_MapsExtensionsExactly(string fileName, SourceLanguage expected)
    {
        Assert.Equal(expected, SourceLanguageDetector.Detect(fileName));
    }

    [Fact]
    public async Task PerRunFileCap_EmitsTerminalNotice()
    {
        using var root = new SrcDepTempDir();
        for (var i = 0; i < 4; i++)
        {
            root.Write("f" + i + ".cs", "// " + i);
        }

        var walker = new RepositoryWalker(root.Path, new RepositoryAnalysisLimits { MaxFilesPerRun = 2 });
        var entries = await SrcDepHarness.CollectAsync(walker);

        Assert.Equal(2, entries.OfType<DiscoveredFile>().Count());
        Assert.IsType<ScanLimitReached>(entries[^1]);
        Assert.True(walker.Counters.Snapshot().FileLimitReached);
    }
}

// ============================================================================
// Rule engine tests.
// ============================================================================

public class SrcDepRuleEngineTests
{
    [Fact]
    public async Task SecretRule_DetectsAwsKeyAndGithubTokens()
    {
        using var root = new SrcDepTempDir();
        root.Write("appsettings.json", "{\n  \"AwsKey\": \"AKIAIOSFODNN7EXAMPLE\"\n}");
        root.Write("token.txt", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ01");

        var scans = await SrcDepHarness.ScanTreeAsync(root.Path);
        var secretMatches = SrcDepHarness.MatchesFor(scans, "SRC-SECRET-001").ToList();

        Assert.Equal(2, secretMatches.Count);
        Assert.Contains(secretMatches, static m => m.MatchedText == "AKIAIOSFODNN7EXAMPLE");
        Assert.All(secretMatches, static m => Assert.Equal(ConfidenceLevel.High, m.Rule.Confidence));
    }

    [Fact]
    public async Task GenericCredentialAssignment_RequiresVarietyAndRejectsPlaceholders()
    {
        using var root = new SrcDepTempDir();
        root.Write("good.cs", "password = \"S3cr3t_V4lue!xyz\";");
        root.Write("short.cs", "password = \"hello\";");
        root.Write("placeholder.cs", "password = \"changeme_value_123456\";");
        root.Write("good.yaml", "secret: \"V3ryL0ngSecretValue!\"");

        var scans = await SrcDepHarness.ScanTreeAsync(root.Path);
        var secretMatches = SrcDepHarness.MatchesFor(scans, "SRC-SECRET-002").ToList();

        Assert.Equal(2, secretMatches.Count);
        Assert.Contains(secretMatches, static m => m.LineText.Contains("S3cr3t_V4lue!xyz", StringComparison.Ordinal));
        Assert.Contains(secretMatches, static m => m.LineText.Contains("V3ryL0ngSecretValue!", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ReDoSGuard_TripsTimeoutOnPathologicalInput()
    {
        var evilPattern = new Regex("(a*)*b", RegexOptions.Compiled | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
        var evilRule = new SourceRule(
            "SRC-TEST-EVIL", "Evil pattern fixture", "why",
            new RemediationGuidance("fix", [], []),
            "Test", Severity.Low, ConfidenceLevel.Medium,
            ExploitabilityIndicator: false,
            Languages: [],
            Pattern: evilPattern,
            MaxMatchesPerFile: 5,
            RedactMatches: false);
        var engine = new SourceRuleEngine([evilRule]);

        using var root = new SrcDepTempDir();
        root.Write("bomb.cs", new string('a', 48) + "!");

        var walker = new RepositoryWalker(root.Path);
        DiscoveredFile? target = null;
        await foreach (var entry in walker.WalkAsync())
        {
            if (entry is DiscoveredFile file)
            {
                target = file;
            }
        }

        Assert.NotNull(target);

        var stopwatch = Stopwatch.StartNew();
        var result = await engine.EvaluateAsync(target.File, target.File.EnumerateLinesAsync(), CancellationToken.None);
        stopwatch.Stop();

        Assert.Contains("SRC-TEST-EVIL", result.TimedOutRuleIds);
        Assert.Empty(result.Matches);
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task InjectionRules_FlagDangerousSinksOnly()
    {
        using var root = new SrcDepTempDir();
        root.Write("query.cs", "var r = cmd.ExecuteReader($\"SELECT * FROM Users WHERE id={id}\");");
        root.Write("safe.cs", "var ok = cmd.ExecuteReader(\"SELECT 1\");");
        root.Write("cmd.py", "os.system(user_cmd)");
        root.Write("task.js", "const out = exec(`rm -rf ${dir}@BT);");

        var scans = await SrcDepHarness.ScanTreeAsync(root.Path);

        var sqlMatches = SrcDepHarness.MatchesFor(scans, "SRC-INJECT-SQL-003").ToList();
        var cmdMatches = SrcDepHarness.MatchesFor(scans, "SRC-INJECT-CMD-004").ToList();

        Assert.Single(sqlMatches);
        Assert.Contains(sqlMatches, static m => m.LineText.Contains("ExecuteReader(", StringComparison.Ordinal));
        Assert.DoesNotContain(sqlMatches, static m => m.LineText.Contains("SELECT 1", StringComparison.Ordinal));
        Assert.Equal(2, cmdMatches.Count);
    }

    [Fact]
    public async Task TlsCorsDeserializationRules_MatchExactApis()
    {
        using var root = new SrcDepTempDir();
        root.Write("tls.py", "requests.get(url, verify=False)");
        root.Write("agent.js", "https.createServer({ rejectUnauthorized: false });");
        root.Write("cors.cs", "builder.AllowAnyOrigin();");
        root.Write("load.py", "data = yaml.load(stream)\nsafe = yaml.load(stream, Loader=yaml.SafeLoader)");

        var scans = await SrcDepHarness.ScanTreeAsync(root.Path);

        Assert.Equal(2, SrcDepHarness.MatchesFor(scans, "SRC-TLS-008").Count);
        Assert.Single(SrcDepHarness.MatchesFor(scans, "SRC-CORS-009"));

        var desers = SrcDepHarness.MatchesFor(scans, "SRC-DESERS-011").ToList();
        Assert.Single(desers);
        Assert.Equal(1, desers[0].LineNumber);
    }
}



// ============================================================================
// Manifest parser tests.
// ============================================================================

public class SrcDepManifestParserTests
{
    private readonly ManifestParser _parser = new();

    [Fact]
    public async Task Csproj_ParsesReferencesAndRecordsMissingVersions()
    {
        using var root = new SrcDepTempDir();
        const string content = """
            <Project Sdk="Microsoft.NET.Sdk">
              <ItemGroup>
                <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
                <PackageReference Include="NoVersion.Pkg" />
              </ItemGroup>
            </Project>
            """;
        var path = root.Write("App.csproj", content);

        var manifest = await _parser.ParseFileAsync(path, CancellationToken.None);

        Assert.Equal(DependencyEcosystem.NuGet, manifest.Ecosystem);
        Assert.Equal(2, manifest.Entries.Count);
        Assert.Contains(manifest.Entries, e => e.Name == "Newtonsoft.Json" && e.Version == "13.0.3" && e.IsDirect);
        var issue = Assert.Single(manifest.ParseIssues);
        Assert.Contains("NoVersion.Pkg", issue.DiagnosticDetail);
    }

    [Fact]
    public async Task PackagesLock_SeparatesDirectFromTransitive()
    {
        using var root = new SrcDepTempDir();
        const string content = """
            {"version":1,"targets":{".NETCoreApp,Version=v10.0":{
              "Newtonsoft.Json":{"type":"Direct","requested":"[13.0.3, )","resolved":"13.0.3"},
              "JetBrains.Annotations":{"type":"Transitive","requested":"[2023.3.0]","resolved":"2023.3.0"},
              "MyApp":{"type":"Project"}
            }}}
            """;
        var path = root.Write("packages.lock.json", content);

        var manifest = await _parser.ParseFileAsync(path, CancellationToken.None);

        Assert.Empty(manifest.ParseIssues);
        Assert.Equal(2, manifest.Entries.Count);
        var direct = manifest.Entries.Single(static e => e.Name == "Newtonsoft.Json");
        Assert.True(direct.IsDirect);
        Assert.Equal("13.0.3", direct.Version);
        var transitive = manifest.Entries.Single(static e => e.Name == "JetBrains.Annotations");
        Assert.False(transitive.IsDirect);
        Assert.DoesNotContain(manifest.Entries, static e => e.Name == "MyApp");
    }

    [Fact]
    public async Task PackageLockV3_ReadsDirectAndTransitive()
    {
        using var root = new SrcDepTempDir();
        const string content = """
            {
              "name": "app",
              "lockfileVersion": 3,
              "packages": {
                "": { "name": "app", "dependencies": { "lodash": "^4.17.15" } },
                "node_modules/lodash": { "version": "4.17.15" },
                "node_modules/semver": { "version": "7.6.0" }
              }
            }
            """;
        var path = root.Write("package-lock.json", content);

        var manifest = await _parser.ParseFileAsync(path, CancellationToken.None);

        Assert.Equal(DependencyEcosystem.Npm, manifest.Ecosystem);
        Assert.Empty(manifest.ParseIssues);
        var lodash = manifest.Entries.Single(static e => e.Name == "lodash");
        Assert.Equal("4.17.15", lodash.Version);
        Assert.True(lodash.IsDirect);
        var semverEntry = manifest.Entries.Single(static e => e.Name == "semver");
        Assert.False(semverEntry.IsDirect);
    }

    [Fact]
    public async Task RequirementsTxt_OnlyPinnedEntriesAreInventoried()
    {
        using var root = new SrcDepTempDir();
        const string content = "# comment\nrequests==2.31.0\nflask\n-r base.txt\ndjango[timezone]==4.2.11\nweird @ name==1.0";
        var path = root.Write("requirements.txt", content);

        var manifest = await _parser.ParseFileAsync(path, CancellationToken.None);

        Assert.Equal(DependencyEcosystem.PyPi, manifest.Ecosystem);
        Assert.Equal(2, manifest.Entries.Count);
        Assert.Contains(manifest.Entries, static e => e.Name == "requests" && e.Version == "2.31.0");
        Assert.Contains(manifest.Entries, static e => e.Name == "django" && e.Version == "4.2.11");
        Assert.Equal(3, manifest.ParseIssues.Count);
    }

    [Fact]
    public async Task CargoToml_ParsesSimpleAndTableForms()
    {
        using var root = new SrcDepTempDir();
        const string content = "[package]\nname = \"demo\"\n\n[dependencies]\nserde = \"1.0.203\"\n"
            + "rand = { version = \"0.8.5\", features = [\"std\"] }\npath-dep = { path = \"../other\" }\n\n[dev-dependencies]\ntempfile = \"3.10.1\"";
        var path = root.Write("Cargo.toml", content);

        var manifest = await _parser.ParseFileAsync(path, CancellationToken.None);

        Assert.Equal(DependencyEcosystem.Cargo, manifest.Ecosystem);
        Assert.Equal(4, manifest.Entries.Count);
        Assert.Equal("1.0.203", manifest.Entries.Single(static e => e.Name == "serde").Version);
        Assert.Equal("0.8.5", manifest.Entries.Single(static e => e.Name == "rand").Version);
        Assert.Null(manifest.Entries.Single(static e => e.Name == "path-dep").Version);
        Assert.Equal("3.10.1", manifest.Entries.Single(static e => e.Name == "tempfile").Version);
        Assert.Single(manifest.ParseIssues);
    }

    [Fact]
    public async Task UnreadableManifest_FailsClosedWithParserCategory()
    {
        using var root = new SrcDepTempDir();
        var missing = System.IO.Path.Combine(root.Path, "does-not-exist.csproj");

        var exception = await Assert.ThrowsAsync<ActException>(() => _parser.ParseFileAsync(missing, CancellationToken.None));
        Assert.Equal(ErrorCategory.Parser, exception.Category);
    }
}



// ============================================================================
// Range, advisory provider, caching, and matcher tests.
// ============================================================================

public class SrcDepRangeAndProviderTests
{
    [Theory]
    [InlineData("*", "9.9.9", true)]
    [InlineData("=1.2.3", "1.2.3", true)]
    [InlineData("=1.2.3", "1.2.4", false)]
    [InlineData("=1.2", "1.2.0", true)]
    [InlineData(">=1,<2", "1.5.0", true)]
    [InlineData(">=1,<2", "2.0.0", false)]
    [InlineData("<1.2.3", "1.2.2", true)]
    [InlineData("<1.2.3", "1.2.3", false)]
    [InlineData(">1.0.0", "1.0.0", false)]
    public void RangeSpec_NumericCompareIsExact(string expression, string version, bool expected)
    {
        Assert.Equal(expected, RangeSpec.Parse(expression).Satisfied(version));
    }

    private static (string Path, string Hash) WriteSnapshot(SrcDepTempDir dir, string updatedIso)
    {
        var content = "{\"source\":\"unit\",\"updatedAt\":\"" + updatedIso + "\",\"packages\":[{\"ecosystem\":\"npm\","
            + "\"name\":\"lodash\",\"advisories\":[{\"id\":\"GHSA-35jh-r3h4-6jhm\",\"severity\":\"HIGH\","
            + "\"affectedRange\":\">=4.17.0,<4.17.21\",\"fixedVersion\":\"4.17.21\"}]}]}";
        var path = dir.Write("advisories.json", content);
        var hash = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(content)).AsSpan()).ToLowerInvariant();
        return (path, hash);
    }

    [Fact]
    public async Task OfflineProvider_MatchesLodashAdvisoryAndReportsFreshness()
    {
        using var root = new SrcDepTempDir();
        var (path, hash) = WriteSnapshot(root, DateTimeOffset.UtcNow.AddHours(-1).ToString("O"));
        var provider = new OfflineFileAdvisoryProvider(path, hash);

        var hit = await provider.QueryAsync("npm", "lodash", "4.17.15", CancellationToken.None);
        var miss = await provider.QueryAsync("npm", "lodash", "4.17.21", CancellationToken.None);
        var freshness = await provider.GetFreshnessAsync(CancellationToken.None);

        var advisory = Assert.Single(hit.Advisories);
        Assert.Equal("GHSA-35jh-r3h4-6jhm", advisory.AdvisoryId);
        Assert.Equal(Severity.High, advisory.Severity);
        Assert.Equal("4.17.21", advisory.FixedVersion);
        Assert.Empty(miss.Advisories);
        Assert.True(freshness.IsCurrent);
        Assert.NotNull(freshness.LastUpdatedUtc);
    }

    [Fact]
    public async Task OfflineProvider_FailsClosedOnHashMismatch()
    {
        using var root = new SrcDepTempDir();
        var (path, _) = WriteSnapshot(root, DateTimeOffset.UtcNow.ToString("O"));
        var wrongHash = new string('0', 63) + '1';
        var provider = new OfflineFileAdvisoryProvider(path, wrongHash);

        var exception = await Assert.ThrowsAsync<ActException>(() => provider.QueryAsync("npm", "lodash", "4.17.15", CancellationToken.None));
        Assert.Equal(ErrorCategory.ExternalFeed, exception.Category);
    }

    [Fact]
    public async Task OsvProvider_DegradesGracefullyWhenEndpointUnreachable()
    {
        using var provider = new OsvAdvisoryProvider(new Uri("http://127.0.0.1:9/v1/query"));

        var result = await provider.QueryAsync("npm", "lodash", "4.17.15", CancellationToken.None);
        var freshness = await provider.GetFreshnessAsync(CancellationToken.None);

        Assert.Empty(result.Advisories);
        Assert.False(result.Freshness.IsCurrent);
        Assert.False(freshness.IsCurrent);
        Assert.False(string.IsNullOrEmpty(freshness.Note));
        Assert.Null(freshness.LastUpdatedUtc);
    }

    [Fact]
    public async Task CachingFeedProvider_PersistsRetrievalRecordAndReportsHonestly()
    {
        using var root = new SrcDepTempDir();
        var cacheDir = System.IO.Path.Combine(root.Path, "cache");
        Directory.CreateDirectory(cacheDir);
        using var dead = new OsvAdvisoryProvider(new Uri("http://127.0.0.1:9/v1/query"));
        var sidecarName = FeedSidecarName(dead.Name);

        var beforeCache = new CachingFeedProvider(dead, cacheDir);
        Assert.False((await beforeCache.GetFreshnessAsync(CancellationToken.None)).IsCurrent);
        Assert.False(File.Exists(System.IO.Path.Combine(cacheDir, sidecarName)));

        File.WriteAllText(
            System.IO.Path.Combine(cacheDir, sidecarName),
            "{\"providerName\":\"osv:127.0.0.1\",\"lastSuccessfulRefreshUtc\":\"" + DateTimeOffset.UtcNow.ToString("O") + "\"}");
        var afterCache = new CachingFeedProvider(dead, cacheDir);
        Assert.True((await afterCache.GetFreshnessAsync(CancellationToken.None)).IsCurrent);

        File.WriteAllText(
            System.IO.Path.Combine(cacheDir, sidecarName),
            "{\"providerName\":\"osv:127.0.0.1\",\"lastSuccessfulRefreshUtc\":\"" + DateTimeOffset.UtcNow.AddDays(-30).ToString("O") + "\"}");
        var staleCache = new CachingFeedProvider(dead, cacheDir);
        Assert.False((await staleCache.GetFreshnessAsync(CancellationToken.None)).IsCurrent);
    }

    private static string FeedSidecarName(string innerName)
    {
        var builder = new System.Text.StringBuilder(innerName.Length);
        foreach (var c in innerName)
        {
            builder.Append(char.IsAsciiLetterOrDigit(c) ? c : '-');
        }

        return "feed-" + builder + ".meta.json";
    }

    [Fact]
    public async Task Matcher_EnforcesPerEntryTimeoutFromBudget()
    {
        var matcher = new VulnerabilityMatcher(new SrcDepSlowAdvisoryProvider(TimeSpan.FromSeconds(30)));
        var manifest = new DependencyManifest(
            DependencyEcosystem.NuGet,
            [new DependencyEntry("Some.Package", "1.0.0", true, "App.csproj")],
            []);

        var stopwatch = Stopwatch.StartNew();
        var report = await matcher.MatchAsync(manifest, SrcDepHarness.Budget(), CancellationToken.None);
        stopwatch.Stop();

        Assert.Empty(report.Vulnerabilities);
        Assert.Contains(report.Warnings, static w => w.Contains("time budget", StringComparison.Ordinal));
        Assert.True(stopwatch.Elapsed < TimeSpan.FromSeconds(20));
    }
}

// ============================================================================
// SBOM tests.
// ============================================================================

public class SrcDepSbomTests
{
    [Fact]
    public void CycloneDx_IsDeterministicAndWellFormed()
    {
        var manifest = new DependencyManifest(
            DependencyEcosystem.NuGet,
            [
                new DependencyEntry("Serilog", "4.0.0", true, "A.csproj"),
                new DependencyEntry("Newtonsoft.Json", "13.0.3", true, "A.csproj")
            ],
            []);
        var npmManifest = new DependencyManifest(
            DependencyEcosystem.Npm,
            [new DependencyEntry("lodash", "4.17.15", true, "package-lock.json")],
            []);

        var first = CycloneDxSbomGenerator.ToJson(manifest, "1.2.3");
        var second = CycloneDxSbomGenerator.ToJson(manifest, "1.2.3");
        Assert.True(first.SequenceEqual(second));

        using var npmDocument = JsonDocument.Parse(CycloneDxSbomGenerator.ToJson(npmManifest, "9.9.9"));
        var bom = npmDocument.RootElement;
        Assert.Equal("CycloneDX", bom.GetProperty("bomFormat").GetString());
        Assert.Equal("1.5", bom.GetProperty("specVersion").GetString());
        var serial = bom.GetProperty("serialNumber").GetString();
        Assert.StartsWith("urn:uuid:", serial);

        var purls = bom.GetProperty("components")
            .EnumerateArray().Select(static c => c.GetProperty("purl").GetString()).ToList();
        Assert.Single(purls);
        Assert.Equal("pkg:npm/lodash@4.17.15", purls[0]);

        using var combined = JsonDocument.Parse(first);
        var allPurls = combined.RootElement.GetProperty("components")
            .EnumerateArray().Select(static c => c.GetProperty("purl").GetString()).ToList();
        var sorted = allPurls.OrderBy(static p => p, StringComparer.Ordinal).ToList();
        Assert.Equal(sorted, allPurls);
    }
}



// ============================================================================
// End-to-end check tests.
// ============================================================================

public class SrcDepCheckTests
{
    private static async Task<SecurityCheckResult> RunSourceCheckAsync(string repoRoot, IEvidenceFactory evidence)
    {
        var check = new SourceAnalysisCheck(evidence);
        return await check.ExecuteAsync(SrcDepHarness.CreateContext(repoRoot, evidence), CancellationToken.None);
    }

    [Fact]
    public async Task SourceCheck_FindsSecret_ScrubsSnippet_KeepsFingerprintAcrossLineShifts()
    {
        using var treeA = new SrcDepTempDir();
        treeA.Write("app/appsettings.json", "{\n  \"Logging\": {\n    \"AwsKey\": \"AKIAIOSFODNN7EXAMPLE\"\n  }\n}");
        using var treeB = new SrcDepTempDir();
        treeB.Write("app/appsettings.json", "\n{\n\n  \"Logging\": {\n    \"AwsKey\": \"AKIAIOSFODNN7EXAMPLE\"\n  }\n}");

        var evidenceA = new SrcDepRecordingEvidenceFactory();
        var resultA = await RunSourceCheckAsync(treeA.Path, evidenceA);
        Assert.Equal(CheckExecutionStatus.Completed, resultA.Status);

        var finding = Assert.Single(resultA.Findings);
        Assert.Equal("ACT-SRC-SCAN-001", finding.CheckId.Value);
        Assert.Equal(Severity.High, finding.TechnicalSeverity);
        Assert.Equal(CheckCategory.Source, finding.Category);
        Assert.Contains("appsettings.json", finding.TargetDisplay, StringComparison.Ordinal);

        var locationEvidence = Assert.Single(evidenceA.Items);
        Assert.Equal(EvidenceKind.SourceLocation, locationEvidence.Kind);
        Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", locationEvidence.RedactedValue, StringComparison.Ordinal);
        Assert.Matches(new Regex("[0-9a-f]{12}"), locationEvidence.RedactedValue);
        Assert.Equal("SRC-SECRET-001", locationEvidence.Attributes["ruleId"]);
        Assert.Equal("aws-access-key-id", locationEvidence.Attributes["secretType"]);

        var evidenceB = new SrcDepRecordingEvidenceFactory();
        var resultB = await RunSourceCheckAsync(treeB.Path, evidenceB);
        var findingB = Assert.Single(resultB.Findings);
        Assert.Equal(finding.Fingerprint.Hash, findingB.Fingerprint.Hash);
    }

    [Fact]
    public async Task SourceCheck_SkipsNonRepositoryAssets()
    {
        using var root = new SrcDepTempDir();
        root.Write("a.cs", "class C { }");
        var evidence = new SrcDepRecordingEvidenceFactory();

        var result = await new SourceAnalysisCheck(evidence)
            .ExecuteAsync(SrcDepHarness.CreateContext(root.Path, evidence, AssetKind.Host), CancellationToken.None);

        Assert.Equal(CheckExecutionStatus.Skipped_NotApplicable, result.Status);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public void Walker_FailsClosedWhenRootMissing()
    {
        using var root = new SrcDepTempDir();
        var missingPath = System.IO.Path.Combine(root.Path, "not-there");
        var exception = Assert.Throws<ActException>(() => new RepositoryWalker(missingPath));
        Assert.Equal(ErrorCategory.Configuration, exception.Category);
    }

    [Fact]
    public async Task DependencyCheck_EmitsVulnerableDependencyFinding()
    {
        using var repo = new SrcDepTempDir();
        using var feedDir = new SrcDepTempDir();
        const string lockContent = """
            {
              "name": "app",
              "lockfileVersion": 3,
              "packages": {
                "": { "name": "app", "dependencies": { "lodash": "^4.17.15" } },
                "node_modules/lodash": { "version": "4.17.15" }
              }
            }
            """;
        repo.Write("package-lock.json", lockContent);

        var snapshotContent = "{\"source\":\"unit\",\"updatedAt\":\"" + DateTimeOffset.UtcNow.AddHours(-2).ToString("O")
            + "\",\"packages\":[{\"ecosystem\":\"npm\",\"name\":\"lodash\",\"advisories\":["
            + "{\"id\":\"GHSA-35jh-r3h4-6jhm\",\"severity\":\"HIGH\","
            + "\"affectedRange\":\">=4.17.0,<4.17.21\",\"fixedVersion\":\"4.17.21\"}]}]}";
        var snapshotPath = feedDir.Write("snapshot.json", snapshotContent);
        var provider = new OfflineFileAdvisoryProvider(snapshotPath);
        var evidence = new SrcDepRecordingEvidenceFactory();

        var check = new DependencyAnalysisCheck(provider, evidence);
        var result = await check.ExecuteAsync(SrcDepHarness.CreateContext(repo.Path, evidence), CancellationToken.None);

        Assert.Equal(CheckExecutionStatus.Completed, result.Status);
        var finding = Assert.Single(result.Findings);
        Assert.Equal("ACT-DEP-AUDIT-001", finding.CheckId.Value);
        Assert.Equal(Severity.High, finding.TechnicalSeverity);
        Assert.Equal(ConfidenceLevel.High, finding.Confidence);
        Assert.Contains("lodash@4.17.15", finding.Title, StringComparison.Ordinal);

        var metadata = Assert.Single(evidence.Items, static i => i.Kind == EvidenceKind.DependencyMetadata);
        Assert.Equal("GHSA-35jh-r3h4-6jhm", metadata.Attributes["advisoryId"]);
        Assert.Equal("npm", metadata.Attributes["ecosystem"]);
        Assert.Contains("lodash", metadata.RedactedValue, StringComparison.Ordinal);
        Assert.Equal(1, result.TargetsExamined);
    }
}

public class SrcDepBuildDirAndCppTests
{
    [Fact]
    public async Task Walk_SkipsBuildVariantsAndToolDirs()
    {
        using var root = new SrcDepTempDir();
        root.Write("src/main.cpp", "int main() { return 0; }");
        root.Write("build-release/out.o", "BINARY");
        root.Write("build-win-ship/_deps/lib.cpp", "int x;");
        root.Write("build-audit/log.txt", "log");
        root.Write(".claude/worktrees/agent/src/main.cpp", "int main() {}");
        root.Write("cmake-build-debug/CMakeCache.txt", "cache");

        var walker = new RepositoryWalker(root.Path);
        var entries = await SrcDepHarness.CollectAsync(walker);

        var discovered = entries.OfType<DiscoveredFile>().Select(static e => e.File.RelativePath).ToList();
        Assert.Equal(["src/main.cpp"], discovered);
    }

    [Fact]
    public void Detect_CppExtensions()
    {
        Assert.Equal(SourceLanguage.Cpp, SourceLanguageDetector.Detect("main.cpp"));
        Assert.Equal(SourceLanguage.Cpp, SourceLanguageDetector.Detect("main.cc"));
        Assert.Equal(SourceLanguage.Cpp, SourceLanguageDetector.Detect("main.hpp"));
        Assert.Equal(SourceLanguage.Cpp, SourceLanguageDetector.Detect("main.h"));
        Assert.Equal(SourceLanguage.Cpp, SourceLanguageDetector.Detect("main.c"));
    }

    [Fact]
    public async Task CppUnsafeFunctionRule_DetectsStrcpy()
    {
        using var root = new SrcDepTempDir();
        root.Write("src/vuln.cpp", "void f(char* d, char* s) { strcpy(d, s); }");

        var evidence = new SrcDepRecordingEvidenceFactory();
        var engine = new SourceRuleEngine();
        var check = new SourceAnalysisCheck(evidence, engine);

        var result = await check.ExecuteAsync(SrcDepHarness.CreateContext(root.Path, evidence), CancellationToken.None);
        Assert.Contains(result.Findings, f => f.CheckId.Value == SourceAnalysisCheck.CheckIdValue && f.Title.Contains("Buffer-unsafe"));
    }
}

public class SrcDepCppRulesTests
{
    [Fact]
    public async Task CppCommandInjectionRule_DetectsSystemCall()
    {
        using var root = new SrcDepTempDir();
        root.Write("src/vuln.cpp", "void f(char* cmd) { system(cmd); }");

        var evidence = new SrcDepRecordingEvidenceFactory();
        var engine = new SourceRuleEngine();
        var check = new SourceAnalysisCheck(evidence, engine);

        var result = await check.ExecuteAsync(SrcDepHarness.CreateContext(root.Path, evidence), CancellationToken.None);
        Assert.Contains(result.Findings, f => f.CheckId.Value == SourceAnalysisCheck.CheckIdValue && f.Title.Contains("Shell command"));
    }

    [Fact]
    public async Task CppTlsRule_DetectsDisabledVerification()
    {
        using var root = new SrcDepTempDir();
        root.Write("src/vuln.cpp", "void f(SSL_CTX* ctx) { SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); }");

        var evidence = new SrcDepRecordingEvidenceFactory();
        var engine = new SourceRuleEngine();
        var check = new SourceAnalysisCheck(evidence, engine);

        var result = await check.ExecuteAsync(SrcDepHarness.CreateContext(root.Path, evidence), CancellationToken.None);
        Assert.Contains(result.Findings, f => f.CheckId.Value == SourceAnalysisCheck.CheckIdValue && f.Title.Contains("TLS certificate"));
    }
}
