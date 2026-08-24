using System.Text;
using ACT.Contracts;
using ACT.Web.Checks;
using Microsoft.Extensions.Logging;
using Xunit;

namespace ACT.Tests;

/// <summary>
/// Unit coverage for the ACT.Web header checks. All HTTP traffic runs through StubHttpEngine,
/// a canned-response test double; scoping decisions come from a fake IScopeValidator.
/// </summary>
public class WebCheckTests
{
    private const string HttpUrl = "http://unit-target.test/";
    private const string HttpsUrl = "https://unit-target.test/";
    private static readonly Uri HttpsBase = new(HttpsUrl);

    // ---------- infrastructure ----------

    internal sealed class StubHttpEngine : ISafeHttpEngine
    {
        private readonly Dictionary<string, SafeHttpResponse> _routes = new(StringComparer.Ordinal);

        public List<SafeHttpRequest> Sent { get; } = [];

        public void Register(string method, string url, SafeHttpResponse response)
            => _routes[Key(method, url)] = response;

        public Task<SafeHttpResponse> SendAsync(SafeHttpRequest request, CancellationToken cancellationToken)
        {
            Sent.Add(request);
            return Task.FromResult(
                _routes.TryGetValue(Key(request.Method.Method, request.Url.AbsoluteUri), out var response)
                    ? response
                    : throw ActException.FailClosed(ErrorCategory.Network, "No stubbed route.", $"Unstubbed '{request.Method.Method} {request.Url.AbsoluteUri}'."));
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;

        private static string Key(string method, string url) => method.ToUpperInvariant() + " " + new Uri(url).AbsoluteUri;
    }

    internal sealed class FakeScopeValidator(bool allowHttp = true, bool allowHttps = true) : IScopeValidator
    {
        public ScopeDecision Evaluate(TargetCandidate candidate)
            => Decision(candidate.Protocol switch
            {
                ProtocolKind.Http => allowHttp,
                ProtocolKind.Https => allowHttps,
                _ => false
            });

        public ScopeDecision EvaluateRedirect(Uri originalUri, Uri redirectTarget) => Decision(false);

        public Task<ScopeDecision> EvaluateResolvedAsync(string host, int port, CancellationToken cancellationToken)
            => Task.FromResult(Decision(true));

        private static ScopeDecision Decision(bool allowed)
            => allowed
                ? ScopeDecision.Allow("unit-stub", "Allowed by unit stub.")
                : ScopeDecision.Deny("STUB_DENIED", "Denied by unit stub.", "Stub denial.");
    }

    internal sealed class PassThroughRateLimiter : IRateLimiter
    {
        public ValueTask WaitForTokenAsync(CancellationToken cancellationToken) => ValueTask.CompletedTask;
    }

    internal sealed class StubLogger : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => false;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
        }
    }

    internal sealed class StubEvidenceFactory : IEvidenceFactory
    {
        public EvidenceItem Create(Guid findingId, EvidenceKind kind, string key, string value,
            CheckId collectedBy, CorrelationId correlation, IReadOnlyDictionary<string, string>? attributes = null)
            => new(Guid.NewGuid(), findingId, kind, key, value, DateTimeOffset.UtcNow, collectedBy, correlation,
                attributes ?? new Dictionary<string, string>());
    }

    internal sealed class StubLedger : IAssessmentLedger
    {
        public Task<AssetRecord> RecordAssetAsync(AssetRecord asset, CancellationToken cancellationToken) => Task.FromResult(asset);
        public Task<ServiceObservation> RecordServiceAsync(ServiceObservation service, CancellationToken cancellationToken) => Task.FromResult(service);
        public IReadOnlyList<ServiceObservation> ObservedServices() => [];
    }

    private static SafeHttpResponse Respond(int statusCode, Dictionary<string, string[]>? headers = null,
        string body = "", string? contentType = null)
        => new(
            StatusCode: statusCode,
            Headers: headers ?? [],
            BodyBytes: Encoding.UTF8.GetBytes(body),
            FinalUri: HttpsBase,
            RedirectTrail: [],
            Elapsed: TimeSpan.FromMilliseconds(1),
            Correlation: CorrelationId.New(),
            TruncatedDueToLimits: false,
            ContentType: contentType);

    private static SecurityCheckContext NewContext(ISafeHttpEngine engine, string? baseUrl,
        FakeScopeValidator? validator = null)
    {
        var scope = new ScopeDefinition(
            ScopeId: Guid.NewGuid(),
            AssessmentId: Guid.NewGuid(),
            OperatorIdentity: "unit-test-operator",
            Organization: "unit-test-org",
            TargetType: TargetTypeKind.Url,
            AllowlistedTargets: ["*.unit-target.test"],
            ExcludedTargets: [],
            PermittedProtocols: [ProtocolKind.Http, ProtocolKind.Https],
            PermittedPorts: [PortRange.Single(80), PortRange.Single(443)],
            RequestsPerSecond: 10,
            ConcurrencyLimit: 2,
            MaxRuntime: TimeSpan.FromMinutes(10),
            MaxRequests: 100,
            AllowedCategories: Enum.GetValues<CheckCategory>(),
            ProhibitedCategories: [],
            EmergencyStopEnabled: true,
            EvidenceRetentionPeriod: TimeSpan.FromDays(1),
            DataRedactionPolicy: RedactionPolicy.Standard,
            AuthorizationStatement: "Authorized for unit testing.");
        var assessment = new AssessmentContext(
            AssessmentId: scope.AssessmentId,
            Scope: scope,
            ScopeValidator: validator ?? new FakeScopeValidator(),
            Http: engine,
            RateLimiter: new PassThroughRateLimiter(),
            Evidence: new StubEvidenceFactory(),
            Logger: new StubLogger(),
            Fixtures: AuthorizationFixtureSet.None,
            Budget: new ResourceBudget(2, 100, 1 << 20, 1 << 20, 1 << 20, 64 << 20,
                TimeSpan.FromSeconds(5), TimeSpan.FromMinutes(10), 2, 5),
            Ledger: new StubLedger(),
            LanguageModel: null)
        { CancellationToken = CancellationToken.None };
        var asset = new AssetRecord(Guid.NewGuid(), scope.AssessmentId, AssetKind.Url, "unit-test-asset",
            baseUrl ?? HttpsUrl, [], DateTimeOffset.UtcNow, WithinScope: true);
        return new SecurityCheckContext(assessment, asset, Service: null, BaseUrl: baseUrl is null ? null : new Uri(baseUrl));
    }

    private static ISecurityCheck[] AllChecks()
        =>
        [
            new HstsCheck(), new CspCheck(), new SecurityHeadersCheck(), new CookieFlagCheck(),
            new CorsCheck(), new TlsRedirectCheck(), new MixedContentCheck(),
            new InfoDisclosureCheck(), new CacheControlCheck()
        ];

    // ---------- HSTS ----------

    [Fact]
    public async Task WebCheck_HstsMissingHeader_EmitsMediumFindingWithEvidence()
    {
        var engine = new StubHttpEngine();
        engine.Register("GET", HttpsUrl, Respond(200, contentType: "text/html"));
        var result = await new HstsCheck().ExecuteAsync(NewContext(engine, HttpsUrl), CancellationToken.None);

        Assert.Equal(CheckExecutionStatus.Completed, result.Status);
        var finding = Assert.Single(result.Findings);
        Assert.Equal(Severity.Medium, finding.TechnicalSeverity);
        Assert.Equal(HstsCheck.CheckIdValue, finding.CheckId.Value);
        Assert.NotEmpty(result.StandaloneEvidence);
        Assert.Equal(1, result.RequestCount);
    }

    [Fact]
    public async Task WebCheck_HstsValidLongMaxAge_PassesClean()
    {
        var engine = new StubHttpEngine();
        engine.Register("GET", HttpsUrl, Respond(200,
            headers: new Dictionary<string, string[]> { ["Strict-Transport-Security"] = ["max-age=63072000; includeSubDomains"] },
            contentType: "text/html"));
        var result = await new HstsCheck().ExecuteAsync(NewContext(engine, HttpsUrl), CancellationToken.None);

        Assert.Equal(CheckExecutionStatus.Completed, result.Status);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task WebCheck_HstsShortMaxAge_EmitsLowNoteFinding()
    {
        var engine = new StubHttpEngine();
        engine.Register("GET", HttpsUrl, Respond(200,
            headers: new Dictionary<string, string[]> { ["strict-transport-security"] = ["max-age=86400"] },
            contentType: "text/html"));
        var result = await new HstsCheck().ExecuteAsync(NewContext(engine, HttpsUrl), CancellationToken.None);

        Assert.Equal(Severity.Low, Assert.Single(result.Findings).TechnicalSeverity);
    }

    [Fact]
    public async Task WebCheck_HstsMalformedHeader_EmitsMediumFinding()
    {
        var engine = new StubHttpEngine();
        engine.Register("GET", HttpsUrl, Respond(200,
            headers: new Dictionary<string, string[]> { ["Strict-Transport-Security"] = ["banana"] },
            contentType: "text/html"));
        var result = await new HstsCheck().ExecuteAsync(NewContext(engine, HttpsUrl), CancellationToken.None);

        Assert.Equal(Severity.Medium, Assert.Single(result.Findings).TechnicalSeverity);
    }

    [Fact]
    public async Task WebCheck_HstsHttpTarget_SkipsBeforeAnyRequest()
    {
        var engine = new StubHttpEngine();
        var result = await new HstsCheck().ExecuteAsync(NewContext(engine, HttpUrl), CancellationToken.None);

        Assert.Equal(CheckExecutionStatus.Skipped_NotApplicable, result.Status);
        Assert.Empty(result.Findings);
        Assert.Empty(engine.Sent);
    }

    // ---------- Cookies ----------

    [Fact]
    public async Task WebCheck_CookieDeficiencies_DedupeToOneFindingPerClassAcrossNames()
    {
        var engine = new StubHttpEngine();
        engine.Register("GET", HttpsUrl, Respond(200, headers: new Dictionary<string, string[]>
        {
            ["Set-Cookie"] =
            [
                "sess_abcd=secretvalue1; Path=/",
                "authtok_99=secretvalue2; Secure",
                "pref=blue"
            ]
        }, contentType: "text/html"));
        var result = await new CookieFlagCheck().ExecuteAsync(NewContext(engine, HttpsUrl), CancellationToken.None);

        Assert.Equal(2, result.Findings.Count(f => f.TechnicalSeverity == Severity.Medium));   // secure + httponly classes
        Assert.Single(result.Findings, f => f.TechnicalSeverity == Severity.Low);              // samesite class
        Assert.Equal(3, result.Findings.Select(f => f.Fingerprint.Hash).Distinct().Count());

        var httpOnlyFinding = result.Findings.Single(f => f.Description.Contains("HttpOnly", StringComparison.Ordinal));
        Assert.Contains("sess_abcd", httpOnlyFinding.Description, StringComparison.Ordinal);
        Assert.Contains("authtok_99", httpOnlyFinding.Description, StringComparison.Ordinal);
        Assert.DoesNotContain("pref", httpOnlyFinding.Description, StringComparison.Ordinal);
        Assert.All(result.Findings, f =>
        {
            Assert.DoesNotContain("secretvalue1", f.Description, StringComparison.Ordinal);
            Assert.DoesNotContain("secretvalue2", f.Description, StringComparison.Ordinal);
        });
    }

    // ---------- CORS ----------

    [Fact]
    public async Task WebCheck_CorsWildcard_HighSeverityRequiresAuthIndicator()
    {
        var authEngine = new StubHttpEngine();
        authEngine.Register("GET", HttpsUrl, Respond(200, headers: new Dictionary<string, string[]>
        {
            ["Access-Control-Allow-Origin"] = ["*"],
            ["Vary"] = ["Accept-Encoding, Authorization"]
        }, contentType: "text/html"));
        authEngine.Register("OPTIONS", HttpsUrl, Respond(204));
        var authResult = await new CorsCheck().ExecuteAsync(NewContext(authEngine, HttpsUrl), CancellationToken.None);
        Assert.Equal(Severity.High, Assert.Single(authResult.Findings).TechnicalSeverity);

        var plainEngine = new StubHttpEngine();
        plainEngine.Register("GET", HttpsUrl, Respond(200, headers: new Dictionary<string, string[]>
        {
            ["Access-Control-Allow-Origin"] = ["*"],
            ["Vary"] = ["User-Agent"]
        }, contentType: "text/html"));
        plainEngine.Register("OPTIONS", HttpsUrl, Respond(204));
        var plainResult = await new CorsCheck().ExecuteAsync(NewContext(plainEngine, HttpsUrl), CancellationToken.None);
        Assert.Equal(Severity.Low, Assert.Single(plainResult.Findings).TechnicalSeverity);
    }

    [Fact]
    public async Task WebCheck_CorsOriginReflection_SendsCredentialFreeOptionsProbeAndEmitsHigh()
    {
        var engine = new StubHttpEngine();
        engine.Register("GET", HttpsUrl, Respond(200, contentType: "text/html"));
        engine.Register("OPTIONS", HttpsUrl, Respond(204,
            headers: new Dictionary<string, string[]> { ["Access-Control-Allow-Origin"] = [CorsCheck.ProbeOrigin] }));
        var result = await new CorsCheck().ExecuteAsync(NewContext(engine, HttpsUrl), CancellationToken.None);

        var finding = Assert.Single(result.Findings);
        Assert.Equal(Severity.High, finding.TechnicalSeverity);
        Assert.Equal(2, result.RequestCount);
        Assert.Equal(new[] { HttpMethod.Get, HttpMethod.Options }, engine.Sent.Select(s => s.Method).ToArray());
        var probe = engine.Sent[1];
        Assert.Equal(HttpMethod.Options, probe.Method);
        Assert.Equal(CorsCheck.ProbeOrigin, probe.Headers["Origin"]);
        Assert.False(probe.Headers.ContainsKey("Authorization"));
        Assert.False(probe.Headers.ContainsKey("Cookie"));
    }

    // ---------- TLS redirect ----------

    [Fact]
    public async Task WebCheck_TlsRedirect_ScopeDenialSkipsWithoutSendingRequests()
    {
        var engine = new StubHttpEngine();
        var validator = new FakeScopeValidator(allowHttp: false, allowHttps: true);
        var result = await new TlsRedirectCheck().ExecuteAsync(NewContext(engine, HttpsUrl, validator), CancellationToken.None);

        Assert.Equal(CheckExecutionStatus.Skipped_OutOfScope, result.Status);
        Assert.Empty(result.Findings);
        Assert.Empty(engine.Sent);
    }

    [Fact]
    public async Task WebCheck_TlsRedirect_HttpOkEmitsMedium_AndUpgradingRedirectPasses()
    {
        var okEngine = new StubHttpEngine();
        okEngine.Register("GET", HttpUrl, Respond(200, contentType: "text/html"));
        var okResult = await new TlsRedirectCheck().ExecuteAsync(NewContext(okEngine, HttpsUrl), CancellationToken.None);
        Assert.Equal(Severity.Medium, Assert.Single(okResult.Findings).TechnicalSeverity);
        Assert.Equal(1, okResult.RequestCount);

        var redirectEngine = new StubHttpEngine();
        redirectEngine.Register("GET", HttpUrl, Respond(301,
            headers: new Dictionary<string, string[]> { ["Location"] = [HttpsUrl] }));
        var redirectResult = await new TlsRedirectCheck().ExecuteAsync(NewContext(redirectEngine, HttpsUrl), CancellationToken.None);
        Assert.Equal(CheckExecutionStatus.Completed, redirectResult.Status);
        Assert.Empty(redirectResult.Findings);
    }

    // ---------- Mixed content ----------

    [Fact]
    public async Task WebCheck_MixedContent_InsecureReferencesProduceSingleMediumPerPage()
    {
        var engine = new StubHttpEngine();
        engine.Register("GET", HttpsUrl, Respond(200, body:
            "<html><script src=\"http://assets.unit-target.test/a.js\"></script>" +
            "<img src='http://img.unit-target.test/b.png'>" +
            "<a href=\"https://safe.unit-target.test/\">ok</a></html>",
            contentType: "text/html"));
        var result = await new MixedContentCheck().ExecuteAsync(NewContext(engine, HttpsUrl), CancellationToken.None);

        var finding = Assert.Single(result.Findings);
        Assert.Equal(Severity.Medium, finding.TechnicalSeverity);
        Assert.Contains("2", finding.Description, StringComparison.Ordinal);
        Assert.DoesNotContain("assets.unit-target.test", finding.Description, StringComparison.Ordinal);
        Assert.Single(result.StandaloneEvidence);
        Assert.Equal(EvidenceKind.HttpResponseMetadata, result.StandaloneEvidence[0].Kind);
    }

    // ---------- Info disclosure ----------

    [Fact]
    public async Task WebCheck_InfoDisclosure_VersionedHeadersEmitSingleLowWithoutLeakingValues()
    {
        var serverEngine = new StubHttpEngine();
        serverEngine.Register("GET", HttpsUrl, Respond(200, headers: new Dictionary<string, string[]>
        {
            ["Server"] = ["nginx/1.24.0 (unit)"],
            ["X-Powered-By"] = ["UnitEngine"]
        }, contentType: "text/html"));
        var serverResult = await new InfoDisclosureCheck().ExecuteAsync(NewContext(serverEngine, HttpsUrl), CancellationToken.None);
        var serverFinding = Assert.Single(serverResult.Findings);
        Assert.Equal(Severity.Low, serverFinding.TechnicalSeverity);
        Assert.Contains("Server", serverFinding.Description, StringComparison.Ordinal);
        Assert.DoesNotContain("1.24.0", serverFinding.Description, StringComparison.Ordinal);

        var poweredByEngine = new StubHttpEngine();
        poweredByEngine.Register("GET", HttpsUrl, Respond(200, headers: new Dictionary<string, string[]>
        {
            ["Server"] = ["unitproxy"],
            ["X-Powered-By"] = ["UnitEngine/9.1"]
        }, contentType: "text/html"));
        var poweredByResult = await new InfoDisclosureCheck().ExecuteAsync(NewContext(poweredByEngine, HttpsUrl), CancellationToken.None);
        var poweredByFinding = Assert.Single(poweredByResult.Findings);
        Assert.Contains("X-Powered-By", poweredByFinding.Description, StringComparison.Ordinal);
    }

    // ---------- CSP ----------

    [Fact]
    public async Task WebCheck_Csp_MissingOnHtmlIsMedium_UnsafeInlineIsInformational_NonceMitigates()
    {
        var missingEngine = new StubHttpEngine();
        missingEngine.Register("GET", HttpsUrl, Respond(200, contentType: "text/html"));
        var missingResult = await new CspCheck().ExecuteAsync(NewContext(missingEngine, HttpsUrl), CancellationToken.None);
        Assert.Equal(Severity.Medium, Assert.Single(missingResult.Findings).TechnicalSeverity);

        var weakEngine = new StubHttpEngine();
        weakEngine.Register("GET", HttpsUrl, Respond(200, headers: new Dictionary<string, string[]>
        {
            ["Content-Security-Policy"] = ["default-src 'self'; script-src 'unsafe-inline'"]
        }, contentType: "text/html"));
        var weakResult = await new CspCheck().ExecuteAsync(NewContext(weakEngine, HttpsUrl), CancellationToken.None);
        Assert.Equal(Severity.Informational, Assert.Single(weakResult.Findings).TechnicalSeverity);

        var hardenedEngine = new StubHttpEngine();
        hardenedEngine.Register("GET", HttpsUrl, Respond(200, headers: new Dictionary<string, string[]>
        {
            ["Content-Security-Policy"] = ["script-src 'unsafe-inline' 'nonce-abc123'"]
        }, contentType: "text/html"));
        var hardenedResult = await new CspCheck().ExecuteAsync(NewContext(hardenedEngine, HttpsUrl), CancellationToken.None);
        Assert.Empty(hardenedResult.Findings);
    }

    // ---------- Cache control ----------

    [Fact]
    public async Task WebCheck_CacheControl_LoginPathWithoutNoStoreEmitsMedium_AndPredicateOverrideSuppresses()
    {
        var loginUrl = "https://unit-target.test/login";
        var engine = new StubHttpEngine();
        engine.Register("GET", loginUrl, Respond(200,
            headers: new Dictionary<string, string[]> { ["Cache-Control"] = ["public, max-age=300"] },
            contentType: "text/html"));

        var context = NewContext(engine, loginUrl);
        var result = await new CacheControlCheck().ExecuteAsync(context, CancellationToken.None);
        var finding = Assert.Single(result.Findings);
        Assert.Equal(Severity.Medium, finding.TechnicalSeverity);
        Assert.Contains("/login", finding.Description, StringComparison.Ordinal);

        var overriddenResult = await new CacheControlCheck(_ => false).ExecuteAsync(context, CancellationToken.None);
        Assert.Empty(overriddenResult.Findings);
    }

    // ---------- Cross-cutting honesty ----------

    [Fact]
    public async Task WebCheck_RequestCount_AccuratelyReflectsEngineTrafficAndCache()
    {
        var engine = new StubHttpEngine();
        engine.Register("GET", HttpsUrl, Respond(200, contentType: "text/html"));
        engine.Register("OPTIONS", HttpsUrl, Respond(204));
        var context = NewContext(engine, HttpsUrl);

        var hstsResult = await new HstsCheck().ExecuteAsync(context, CancellationToken.None);
        Assert.Equal(1, hstsResult.RequestCount);
        Assert.Single(engine.Sent);

        var corsResult = await new CorsCheck().ExecuteAsync(context, CancellationToken.None);
        Assert.Equal(2, corsResult.RequestCount);
        // Exactly one GET in total proves the per-context response cache; the OPTIONS probe is the only extra traffic.
        Assert.Single(engine.Sent, request => request.Method == HttpMethod.Get);
        Assert.Single(engine.Sent, request => request.Method == HttpMethod.Options);
    }

    [Fact]
    public void WebCheck_Metadata_DeclaresHonestSafeRequestOnlyProfile()
    {
        foreach (var check in AllChecks())
        {
            var meta = check.Metadata;
            meta.Validate();
            Assert.Equal(SafetyLevel.SafeRequestOnly, meta.SafetyLevel);
            Assert.Equal("1.0.0", meta.Version);
            Assert.True(meta.SupportsRemediation);
            Assert.True(meta.SupportsRegressionTest);
            Assert.Equal(CheckCategory.Http, meta.Category);
            Assert.Single(meta.SupportedTargetTypes);
            Assert.Contains(TargetTypeKind.Url, meta.SupportedTargetTypes);
            Assert.InRange(meta.NetworkBehavior.MinRequestsPerTarget, 1, 3);
            Assert.InRange(meta.NetworkBehavior.MaxRequestsPerTarget, 1, 3);
            Assert.False(meta.NetworkBehavior.MutatesTargetState);
            Assert.False(meta.NetworkBehavior.SendsAuthenticationHeaders);
        }
    }

    [Fact]
    public async Task WebCheck_NullBaseUrl_SkipsEveryHeaderCheckAsNotApplicable()
    {
        var engine = new StubHttpEngine();
        var context = NewContext(engine, baseUrl: null);
        foreach (var check in AllChecks())
        {
            var result = await check.ExecuteAsync(context, CancellationToken.None);
            Assert.Equal(CheckExecutionStatus.Skipped_NotApplicable, result.Status);
            Assert.Empty(result.Findings);
        }

        Assert.Empty(engine.Sent);
    }
}
