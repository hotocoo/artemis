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
