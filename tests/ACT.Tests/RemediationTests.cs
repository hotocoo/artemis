using System.Net;
using System.Net.Sockets;
using ACT.Contracts;
using ACT.Remediation;
using ACT.Web.Checks;

namespace ACT.Tests;

/// <summary>
/// Unit coverage for the on-the-spot remediation capability: the planner maps finding classes to
/// executable fixes, and the proxy + engine apply and verify them. These tests prove the planning
/// logic is deterministic and complete for every remediable check, without needing a live target.
/// </summary>
public sealed class RemediationPlannerTests
{
    private static Finding MakeFinding(string checkId, string title) => new(
        FindingId: Guid.NewGuid(),
        AssessmentId: Guid.NewGuid(),
        CheckId: new CheckId(checkId),
        TargetDisplay: "http://127.0.0.1:1",
        AssetReference: null,
        Category: CheckCategory.Http,
        Title: title,
        Description: "test",
        TechnicalSeverity: Severity.Medium,
        Confidence: ConfidenceLevel.High,
        ConfidenceScore: 0.9,
        ExploitabilityIndicator: false,
        BusinessImpact: BusinessImpactLevel.Limited,
        WhyItMatters: "test",
        TechnicalExplanation: "test",
        Remediation: new RemediationGuidance("test", [], []),
        FirstSeenUtc: DateTimeOffset.UtcNow,
        LastSeenUtc: DateTimeOffset.UtcNow,
        Status: FindingStatus.New,
        Fingerprint: new FindingFingerprint("abc"),
        RegressionTestId: null,
        CvssVector: null,
        CvssBaseScore: null);

    [Theory]
    [InlineData("ACT-WEB-HSTS-001", 1)]
    [InlineData("ACT-WEB-CSP-001", 1)]
    [InlineData("ACT-WEB-SECHEADERS-002", 3)]
    [InlineData("ACT-WEB-CORS-001", 2)]
    [InlineData("ACT-WEB-CACHECTRL-001", 1)]
    [InlineData("ACT-WEB-COOKIE-001", 1)]
    [InlineData("ACT-WEB-TLSREDIRECT-001", 1)]
    public void PlanFor_remediable_check_yields_expected_action_count(string checkId, int expectedActions)
    {
        var finding = MakeFinding(checkId, "A test finding");
        var plan = RemediationPlanner.PlanFor(finding);
        Assert.NotNull(plan);
        Assert.Equal(expectedActions, plan!.Actions.Count);
        Assert.All(plan.Actions, a => Assert.False(string.IsNullOrWhiteSpace(a.Description)));
    }

    [Theory]
    [InlineData("ACT-NET-DISC-001")]
    [InlineData("ACT-API-OPENAPI-001")]
    public void PlanFor_non_remediable_check_returns_null(string checkId)
    {
        var finding = MakeFinding(checkId, "A non-remediable finding");
        var plan = RemediationPlanner.PlanFor(finding);
        Assert.Null(plan);
    }

    [Fact]
    public void PlanFor_HSTS_injects_compliant_header()
    {
        var finding = MakeFinding("ACT-WEB-HSTS-001", "Missing HSTS");
        var plan = RemediationPlanner.PlanFor(finding);
        var action = plan!.Actions.Single();
        Assert.Equal(RemediationActionKind.InjectHeader, action.Kind);
        Assert.Equal("Strict-Transport-Security", action.HeaderName);
        Assert.Contains("max-age=31536000", action.HeaderValue);
    }

    [Fact]
    public void PlanFor_TLSredirect_uses_force_https_action()
    {
        var finding = MakeFinding("ACT-WEB-TLSREDIRECT-001", "No HTTPS redirect");
        var plan = RemediationPlanner.PlanFor(finding);
        var action = plan!.Actions.Single();
        Assert.Equal(RemediationActionKind.ForceHttpsRedirect, action.Kind);
    }
}

/// <summary>
/// Live-loopback coverage for the remediation engine: a real vulnerable origin is corrected through
/// the remediation proxy and the fix is verified by re-running the originating check. This is the
/// end-to-end proof that Artemis can find AND fix a vulnerability on the spot.
/// </summary>
public sealed class RemediationEngineTests : IDisposable
{
    private readonly HttpListener _listener;
    private readonly int _port;
    private readonly Task _loop;

    public RemediationEngineTests()
    {
        _port = GetFreePort();
        _listener = new HttpListener();
        _listener.Prefixes.Add($"http://127.0.0.1:{_port}/");
        _listener.Start();
        _loop = Task.Run(ServeLoop);
    }

    // Serves a deliberately vulnerable origin: no security headers, no CSP, permissive CORS.
    private async Task ServeLoop()
    {
        while (_listener.IsListening)
        {
            HttpListenerContext ctx;
            try { ctx = await _listener.GetContextAsync(); }
            catch { break; }
            _ = Task.Run(() => Handle(ctx));
        }
    }

    private void Handle(HttpListenerContext ctx)
    {
        try
        {
            var response = ctx.Response;
            response.StatusCode = 200;
            response.ContentType = "text/html; charset=utf-8";
            response.Headers.Add("Access-Control-Allow-Origin", "*");
            var html = "<html><head></head><body><a href='/a'>a</a><a href='/b'>b</a></body></html>";
            var bytes = System.Text.Encoding.UTF8.GetBytes(html);
            response.ContentLength64 = bytes.Length;
            response.OutputStream.Write(bytes);
            response.Close();
        }
        catch { /* best effort */ }
    }

    public void Dispose()
    {
        try { _listener.Stop(); _listener.Close(); }
        catch { /* best effort */ }
    }

    private static int GetFreePort()
    {
        var l = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        l.Start();
        var port = ((IPEndPoint)l.LocalEndpoint).Port;
        l.Stop();
        return port;
    }

    [Fact]
    public async Task RemediateAsync_fixes_missing_CSP_and_verifies()
    {
        var upstream = new Uri($"http://127.0.0.1:{_port}");
        var check = new CspCheck();

        // First confirm the origin is actually vulnerable (the check must report the finding).
        var engine = new RemediationEngine();
        var result = await engine.RemediateAsync(
            MakeCspFinding(), check, upstream, CancellationToken.None);

        Assert.Equal(RemediationOutcome.Remediated, result.Outcome);
        Assert.True(result.FindingsBefore > 0, "origin should be vulnerable before remediation");
        Assert.Equal(0, result.FindingsAfter);
        Assert.NotNull(result.RemediatedEndpoint);
    }

    [Fact]
    public async Task RemediateAsync_fixes_permissive_CORS_and_verifies()
    {
        var upstream = new Uri($"http://127.0.0.1:{_port}");
        var check = new CorsCheck();
        var engine = new RemediationEngine();
        var result = await engine.RemediateAsync(
            MakeCorsFinding(), check, upstream, CancellationToken.None);

        Assert.Equal(RemediationOutcome.Remediated, result.Outcome);
        Assert.Equal(0, result.FindingsAfter);
    }

    private static Finding MakeCspFinding() => new(
        Guid.NewGuid(), Guid.NewGuid(), new CheckId("ACT-WEB-CSP-001"),
        "http://127.0.0.1", null, CheckCategory.Http, "Missing CSP", "d",
        Severity.Medium, ConfidenceLevel.High, 0.9, false,
        BusinessImpactLevel.Limited, "w", "t", new RemediationGuidance("s", [], []),
        DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, FindingStatus.New,
        new FindingFingerprint("csp"), null, null, null);

    private static Finding MakeCorsFinding() => new(
        Guid.NewGuid(), Guid.NewGuid(), new CheckId("ACT-WEB-CORS-001"),
        "http://127.0.0.1", null, CheckCategory.Http, "Wildcard CORS", "d",
        Severity.High, ConfidenceLevel.High, 0.9, false,
        BusinessImpactLevel.Significant, "w", "t", new RemediationGuidance("s", [], []),
        DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, FindingStatus.New,
        new FindingFingerprint("cors"), null, null, null);
}

/// <summary>
/// Unit coverage for the dependency remediation: upgrading a vulnerable package in a manifest
/// to the advisory's fixed version across all supported ecosystems.
/// </summary>

/// <summary>
/// Unit coverage for the dependency remediation: upgrading a vulnerable package in a manifest
/// to the advisory's fixed version across all supported ecosystems.
/// </summary>
public sealed class DependencyRemediatorTests
{
    private static string TempFile(string content)
    {
        var path = Path.Combine(Path.GetTempPath(), "artemis-dep-" + Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public async Task UpdateVersionAsync_updates_requirements_txt()
    {
        var path = TempFile("requests==2.25.0\nflask==2.0.0\n");
        try
        {
            var result = await DependencyRemediator.UpdateVersionAsync(path, "requests", "2.31.0", CancellationToken.None);
            Assert.True(result.Updated);
            Assert.Equal("2.25.0", result.PreviousVersion);
            Assert.Equal("2.31.0", result.NewVersion);
            var content = File.ReadAllText(path);
            Assert.Contains("requests==2.31.0", content);
            Assert.Contains("flask==2.0.0", content);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task UpdateVersionAsync_updates_package_json()
    {
        var path = TempFile("{\n  \"dependencies\": {\n    \"lodash\": \"4.17.15\",\n    \"express\": \"4.18.0\"\n  }\n}\n");
        try
        {
            var result = await DependencyRemediator.UpdateVersionAsync(path, "lodash", "4.17.21", CancellationToken.None);
            Assert.True(result.Updated);
            Assert.Equal("4.17.15", result.PreviousVersion);
            var content = File.ReadAllText(path);
            Assert.Contains("\"4.17.21\"", content);
            Assert.Contains("\"express\": \"4.18.0\"", content);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task UpdateVersionAsync_updates_cargo_toml()
    {
        var path = TempFile("[dependencies]\nserde = \"1.0.0\"\ntokio = \"1.20.0\"\n");
        try
        {
            var result = await DependencyRemediator.UpdateVersionAsync(path, "serde", "1.0.190", CancellationToken.None);
            Assert.True(result.Updated);
            Assert.Equal("1.0.0", result.PreviousVersion);
            var content = File.ReadAllText(path);
            Assert.Contains("serde = \"1.0.190\"", content);
            Assert.Contains("tokio = \"1.20.0\"", content);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task UpdateVersionAsync_updates_csproj()
    {
        var path = TempFile("<Project>\n  <ItemGroup>\n    <PackageReference Include=\"Newtonsoft.Json\" Version=\"13.0.1\" />\n  </ItemGroup>\n</Project>\n");
        try
        {
            var result = await DependencyRemediator.UpdateVersionAsync(path, "Newtonsoft.Json", "13.0.3", CancellationToken.None);
            Assert.True(result.Updated);
            Assert.Equal("13.0.1", result.PreviousVersion);
            var content = File.ReadAllText(path);
            Assert.Contains("Version=\"13.0.3\"", content);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task UpdateVersionAsync_fails_closed_when_package_absent()
    {
        var path = TempFile("requests==2.25.0\n");
        try
        {
            var result = await DependencyRemediator.UpdateVersionAsync(path, "nonexistent", "1.0.0", CancellationToken.None);
            Assert.False(result.Updated);
            var content = File.ReadAllText(path);
            Assert.Equal("requests==2.25.0\n", content);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task UpdateVersionAsync_updates_pom_xml()
    {
        // The dependency's <version> child is rewritten in place; surrounding elements and
        // sibling dependencies stay byte-identical.
        var pom = """
            <?xml version="1.0" encoding="UTF-8"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
                <modelVersion>4.0.0</modelVersion>
                <groupId>com.example</groupId>
                <artifactId>my-app</artifactId>
                <version>1.0.0</version>
                <dependencies>
                    <dependency>
                        <groupId>org.springframework</groupId>
                        <artifactId>spring-core</artifactId>
                        <version>5.3.20</version>
                    </dependency>
                    <dependency>
                        <groupId>com.google.guava</groupId>
                        <artifactId>guava</artifactId>
                        <version>31.1-jre</version>
                    </dependency>
                </dependencies>
            </project>
            """;
        var path = TempFile(pom);
        try
        {
            var result = await DependencyRemediator.UpdateVersionAsync(path, "org.springframework:spring-core", "5.3.25", CancellationToken.None);

            Assert.True(result.Updated);
            Assert.Equal("5.3.20", result.PreviousVersion);
            Assert.Equal("5.3.25", result.NewVersion);

            var content = File.ReadAllText(path);
            Assert.Contains("<version>5.3.25</version>", content);
            Assert.DoesNotContain("<version>5.3.20</version>", content);
            // Sibling dependency untouched.
            Assert.Contains("<version>31.1-jre</version>", content);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task UpdateVersionAsync_pom_xml_disambiguates_same_group_different_artifact()
    {
        // Spring publishes many artifacts under the same org.springframework group; the rewriter
        // must update only the requested artifactId, not every dependency that shares its groupId.
        var pom = """
            <project>
                <dependencies>
                    <dependency>
                        <groupId>org.springframework</groupId>
                        <artifactId>spring-core</artifactId>
                        <version>5.3.20</version>
                    </dependency>
                    <dependency>
                        <groupId>org.springframework</groupId>
                        <artifactId>spring-context</artifactId>
                        <version>5.3.20</version>
                    </dependency>
                </dependencies>
            </project>
            """;
        var path = TempFile(pom);
        try
        {
            var result = await DependencyRemediator.UpdateVersionAsync(path, "org.springframework:spring-core", "5.3.25", CancellationToken.None);

            Assert.True(result.Updated);
            var content = File.ReadAllText(path);
            // Whitespace is normalized to a single space so the test is robust to raw-string
            // indentation in either direction of the rewrite.
            var normalized = System.Text.RegularExpressions.Regex.Replace(content, "\\s+", " ");
            Assert.Contains("<artifactId>spring-core</artifactId> <version>5.3.25</version>", normalized);
            Assert.Contains("<artifactId>spring-context</artifactId> <version>5.3.20</version>", normalized);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task UpdateVersionAsync_pom_xml_fails_closed_when_all_versions_are_managed()
    {
        // The pom declares the pin in <dependencyManagement> and uses it without a literal
        // <version> in <dependencies>. There is no <version>OLD</version> child to rewrite, and
        // silently bumping the managed pin would change the version for every transitive
        // consumer; the remediator fails closed instead.
        var pom = """
            <project>
                <dependencyManagement>
                    <dependencies>
                        <dependency>
                            <groupId>org.springframework</groupId>
                            <artifactId>spring-core</artifactId>
                            <version>5.3.20</version>
                        </dependency>
                    </dependencies>
                </dependencyManagement>
                <dependencies>
                    <dependency>
                        <groupId>org.springframework</groupId>
                        <artifactId>spring-core</artifactId>
                    </dependency>
                </dependencies>
            </project>
            """;
        var path = TempFile(pom);
        try
        {
            var result = await DependencyRemediator.UpdateVersionAsync(path, "org.springframework:spring-core", "5.3.25", CancellationToken.None);

            Assert.False(result.Updated);
            var content = File.ReadAllText(path);
            // The managed version stays pinned for child modules; nothing was fabricated.
            Assert.Contains("<version>5.3.20</version>", content);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task UpdateVersionAsync_pom_xml_prefers_literal_over_managed_match()
    {
        // When one dependency in the file declares its version literally and another (with the
        // same groupId:artifactId) only inherits from <dependencyManagement>, the rewriter must
        // update the literal one and leave the managed pin alone.
        var pom = """
            <project>
                <dependencyManagement>
                    <dependencies>
                        <dependency>
                            <groupId>org.springframework</groupId>
                            <artifactId>spring-core</artifactId>
                            <version>5.3.20</version>
                        </dependency>
                    </dependencies>
                </dependencyManagement>
                <dependencies>
                    <dependency>
                        <groupId>org.springframework</groupId>
                        <artifactId>spring-core</artifactId>
                        <version>5.3.18</version>
                    </dependency>
                </dependencies>
            </project>
            """;
        var path = TempFile(pom);
        try
        {
            var result = await DependencyRemediator.UpdateVersionAsync(path, "org.springframework:spring-core", "5.3.25", CancellationToken.None);

            Assert.True(result.Updated);
            Assert.Equal("5.3.18", result.PreviousVersion);
            var content = File.ReadAllText(path);
            // Literal version upgraded; managed pin untouched.
            Assert.Contains("<version>5.3.25</version>", content);
            Assert.Contains("<version>5.3.20</version>", content);
        }
        finally
        {
            File.Delete(path);
        }
    }
}

/// <summary>
/// Unit coverage for the source remediation: applying rule-specific fixes to source files for
/// the rules with safe, deterministic transformations.
/// </summary>
public sealed class SourceRemediatorTests
{
    private static string TempFile(string content)
    {
        var path = Path.Combine(Path.GetTempPath(), "artemis-src-" + Guid.NewGuid().ToString("N") + ".txt");
        File.WriteAllText(path, content);
        return path;
    }

    [Fact]
    public async Task FixAsync_fixes_weak_crypto()
    {
        var path = TempFile("var hash = MD5.Create();\nvar h2 = SHA1.Create();\n");
        try
        {
            var result = await SourceRemediator.FixAsync(path, "SRC-CRYPTO-002", CancellationToken.None);
            Assert.True(result.Updated);
            Assert.True(result.LocationsFixed >= 2);
            var content = File.ReadAllText(path);
            Assert.Contains("SHA256.Create", content);
            Assert.DoesNotContain("MD5.Create", content);
            Assert.DoesNotContain("SHA1.Create", content);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task FixAsync_fixes_tls_validation()
    {
        var path = TempFile("requests.get(url, verify=False)\n");
        try
        {
            var result = await SourceRemediator.FixAsync(path, "SRC-TLS-008", CancellationToken.None);
            Assert.True(result.Updated);
            var content = File.ReadAllText(path);
            Assert.Contains("verify=True", content);
            Assert.DoesNotContain("verify=False", content);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task FixAsync_fixes_insecure_cookies()
    {
        var path = TempFile("response.SetCookie(name, value, Secure = false, HttpOnly = false);\n");
        try
        {
            var result = await SourceRemediator.FixAsync(path, "SRC-COOKIE-010", CancellationToken.None);
            Assert.True(result.Updated);
            var content = File.ReadAllText(path);
            Assert.Contains("Secure = true", content);
            Assert.Contains("HttpOnly = true", content);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public async Task FixAsync_reports_guidance_only_for_unfixable_rule()
    {
        var path = TempFile("var conn = new SqlConnection(\"password=secret\");\n");
        try
        {
            var result = await SourceRemediator.FixAsync(path, "SRC-SECRET-001", CancellationToken.None);
            Assert.False(result.Updated);
            Assert.Contains("no safe automatic fix", result.Detail);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
