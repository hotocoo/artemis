
using System.Net;
using System.Net.Sockets;
using System.Text;
using ACT.Contracts;
using ACT.Core;
using ACT.Evidence;
using ACT.Network;
using ACT.Policy;
using ACT.Scope;
using ACT.Tls.Checks;
using ACT.Web.Checks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace ACT.IntegrationTests;

/// <summary>
/// Full-stack end-to-end runs: real scope validation, real safe HTTP engine, real checks,
/// real SQLite persistence, against the disposable vulnerable lab.
/// </summary>
[Collection("lab")]
public sealed class EndToEndAssessmentTests(LabFixture lab)
{
    private ScopeDefinition BuildLabScope()
    {
        return new ScopeDefinition(
            ScopeId: Guid.NewGuid(),
            AssessmentId: Guid.NewGuid(),
            OperatorIdentity: "e2e-operator",
            Organization: "artemis-e2e",
            TargetType: TargetTypeKind.Localhost,
            AllowlistedTargets: ["localhost", "127.0.0.1"],
            ExcludedTargets: [],
            PermittedProtocols: [ProtocolKind.Tcp, ProtocolKind.Http, ProtocolKind.Https],
            PermittedPorts: [PortRange.Single(lab.BaseUrl.Port)],
            RequestsPerSecond: 50,
            ConcurrencyLimit: 4,
            MaxRuntime: TimeSpan.FromMinutes(5),
            MaxRequests: 500,
            AllowedCategories: Enum.GetValues<CheckCategory>(),
            ProhibitedCategories: [],
            EmergencyStopEnabled: true,
            EvidenceRetentionPeriod: TimeSpan.FromDays(7),
            DataRedactionPolicy: RedactionPolicy.Standard,
            AuthorizationStatement: "E2E authorization statement for the local test lab.");
    }

    private static List<ISecurityCheck> BuildWebChecks() =>
    [
        new HstsCheck(),
        new CspCheck(),
        new SecurityHeadersCheck(),
        new CookieFlagCheck(),
        new CorsCheck(),
        new TlsRedirectCheck(),
        new MixedContentCheck(),
        new InfoDisclosureCheck(),
        new CacheControlCheck()
    ];

    private AssessmentContext BuildContext(ScopeDefinition scope, ResourceBudget budget)
    {
        var compiled = new CompiledScope(scope);
        var resolver = new PinningDnsResolver();
        var validator = new ScopeValidator(compiled, resolver);
        var limiter = new TokenBucketRateLimiter(scope.RequestsPerSecond);
        var http = new SafeHttpEngine(validator, validator, budget, limiter, NullLogger.Instance);
        var redactor = new StandardEvidenceRedactor(scope.DataRedactionPolicy);
        return new AssessmentContext(
            scope.AssessmentId, scope, validator, http, limiter,
            new EvidenceFactory(redactor),
            NullLogger.Instance,
            AuthorizationFixtureSet.None,
            budget,
            Ledger: new RecordingLedger(),
            LanguageModel: null)
        {
            CancellationToken = CancellationToken.None
        };
    }

    [Fact]
    public async Task VulnerableHeadersProduceExpectedFindings()
    {
        var scope = BuildLabScope();
        var budget = ResourceBudget.FromScope(scope, EngineDefaults.Conservative);
        var context = BuildContext(scope, budget);

        var asset = new AssetRecord(Guid.NewGuid(), scope.AssessmentId, AssetKind.Url,
            "lab", lab.BaseUrl.ToString(), [], DateTimeOffset.UtcNow, WithinScope: true);

        var expectations = new (ISecurityCheck Check, string Path, string CheckId, Severity MinSeverity)[]
        {
            (new SecurityHeadersCheck(), "/headers/missing", "ACT-WEB-SECHEADERS-002", Severity.Medium),
            (new CspCheck(), "/headers/missing", "ACT-WEB-CSP-001", Severity.Medium),
            (new CookieFlagCheck(), "/cookies/bad", "ACT-WEB-COOKIE-001", Severity.Low),
            (new CorsCheck(), "/cors/open", "ACT-WEB-CORS-001", Severity.High),
            (new TlsRedirectCheck(), "/", "ACT-WEB-TLSREDIRECT-001", Severity.Medium),
        };

        foreach (var (check, path, checkId, minSeverity) in expectations)
        {
            var targetUrl = new Uri(lab.BaseUrl, path);
            var checkContext = new SecurityCheckContext(context, asset, Service: null, BaseUrl: targetUrl);
            var result = await check.ExecuteAsync(checkContext, CancellationToken.None);
            Assert.True(result.Status is CheckExecutionStatus.Completed or CheckExecutionStatus.CompletedWithWarnings,
                checkId + " returned " + result.Status);
            Assert.Contains(result.Findings,
                f => f.CheckId.Value == checkId && f.TechnicalSeverity >= minSeverity);
        }
    }

    [Fact]
    public async Task OutOfScopeRedirectIsBlockedFailClosed()
    {
        var scope = BuildLabScope();
        var budget = ResourceBudget.FromScope(scope, EngineDefaults.Conservative);
        var context = BuildContext(scope, budget);

        await Assert.ThrowsAsync<ActException>(async () =>
        {
            var engine = context.Http;
            await using (engine.ConfigureAwait(false))
            {
                await engine.SendAsync(
                    SafeHttpRequest.Get(new Uri(lab.BaseUrl, "/redirect/out"), CorrelationId.New()),
                    CancellationToken.None);
            }
        });
    }

    [Fact]
    public void UnlistedPortAndHostAreDeniedByCompiledScope()
    {
        var scope = BuildLabScope();
        var compiled = new CompiledScope(scope);
        var validator = new ScopeValidator(compiled, new PinningDnsResolver());

        Assert.False(validator.Evaluate(new TargetCandidate("127.0.0.1", 9999, ProtocolKind.Http, null)).Allowed);
        Assert.False(validator.Evaluate(new TargetCandidate("evil.example", lab.BaseUrl.Port, ProtocolKind.Http, null)).Allowed);
        Assert.True(validator.Evaluate(new TargetCandidate("localhost", lab.BaseUrl.Port, ProtocolKind.Http, null)).Allowed);
    }

    [Fact]
    public async Task OversizedGzipResponseIsTruncatedNotFatal()
    {
        // Raw socket server that answers with a gzip bomb: 10 MB of zeros compressed to ~10 KB.
        var port = GetFreeListenerPort();
        using var listener = new TcpListener(IPAddress.Loopback, port);
        listener.Start();
        var serverTask = Task.Run(async () =>
        {
            while (listener.Server.IsBound)
            {
                var client = await listener.AcceptTcpClientAsync();
                _ = Task.Run(async () =>
                {
                    await using var stream = client.GetStream();
                    var body = CompressZeros(10 * 1024 * 1024);
                    var cr = ((char)13).ToString();
                    var lf = ((char)10).ToString();
                    var header = Encoding.ASCII.GetBytes(
                        "HTTP/1.1 200 OK" + cr + lf +
                        "Content-Type: text/plain" + cr + lf +
                        "Content-Encoding: gzip" + cr + lf +
                        "Content-Length: " + body.Length + cr + lf +
                        "Connection: close" + cr + lf + cr + lf);
                    await stream.WriteAsync(header);
                    await stream.WriteAsync(body);
                    await stream.FlushAsync();
                    client.Close();
                });
            }
        });

        try
        {
            var scope = BuildLabScope() with { PermittedPorts = [PortRange.Single(port)] };
            var budget = ResourceBudget.FromScope(scope, EngineDefaults.Conservative) with { MaxBodyBytes = 256 * 1024 };
            var context = BuildContext(scope, budget);

            await using var engine = context.Http;
            var response = await engine.SendAsync(
                SafeHttpRequest.Get(new Uri($"http://127.0.0.1:{port}/bomb"), CorrelationId.New()),
                CancellationToken.None);

            Assert.True(response.TruncatedDueToLimits, "Decompression bomb should have been truncated.");
            Assert.InRange(response.BodyBytes.Length, 128 * 1024, 256 * 1024 + 64 * 1024);
        }
        finally
        {
            listener.Stop();
            try { await serverTask; } catch (Exception) { /* listener loop ends with stop */ }
        }
    }

    private static byte[] CompressZeros(int decompressedSize)
    {
        using var compressed = new MemoryStream();
        using (var gzip = new System.IO.Compression.GZipStream(compressed, System.IO.Compression.CompressionLevel.Optimal))
        {
            var chunk = new byte[64 * 1024];
            var remaining = decompressedSize;
            while (remaining > 0)
            {
                var take = Math.Min(chunk.Length, remaining);
                gzip.Write(chunk, 0, take);
                remaining -= take;
            }
        }
        return compressed.ToArray();
    }

    private static int GetFreeListenerPort()
    {
        var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        try { return ((IPEndPoint)l.LocalEndpoint).Port; }
        finally { l.Stop(); }
    }

    private sealed class RecordingLedger : IAssessmentLedger
    {
        public List<ServiceObservation> Services { get; } = [];
        public List<AssetRecord> Assets { get; } = [];

        public Task<AssetRecord> RecordAssetAsync(AssetRecord asset, CancellationToken cancellationToken)
        {
            lock (Assets) Assets.Add(asset);
            return Task.FromResult(asset);
        }

        public Task<ServiceObservation> RecordServiceAsync(ServiceObservation service, CancellationToken cancellationToken)
        {
            lock (Services) Services.Add(service);
            return Task.FromResult(service);
        }

        public IReadOnlyList<ServiceObservation> ObservedServices() => [.. Services];
    }
}
