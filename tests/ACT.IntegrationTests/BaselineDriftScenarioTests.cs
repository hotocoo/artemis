
using System.Net;
using System.Net.Sockets;
using System.Text;
using ACT.Cli;
using ACT.Cli.Composition;
using ACT.Contracts;
using ACT.Core;
using ACT.Evidence;
using ACT.Network;
using ACT.Network.Checks;
using ACT.Persistence;
using ACT.Reporting;
using ACT.Scope;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace ACT.IntegrationTests;

/// <summary>
/// The service-drift baseline scenario, live: a real ServiceDiscoveryCheck observes real
/// loopback listeners, a baseline is created and hardened with a prohibited port through the
/// production operations, the environment then drifts (expected service down, prohibited
/// service up), and comparison reports exactly the documented drift - audited end to end.
/// </summary>
public sealed class BaselineDriftScenarioTests
{
    [Fact]
    public async Task BaselineCreateHardenThenEnvironmentDriftIsReportedAndAudited()
    {
        var directory = Path.Combine(Path.GetTempPath(), "act-drift-scenario", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var databasePath = Path.Combine(directory, "act.db");
        var db = new ActDatabase(databasePath, new StorageOptions
        {
            DatabasePath = databasePath,
            WalEnabled = false,
            RetentionDays = 90
        });
        var services = new ServiceCollection();
        services.AddSingleton(db);
        services.AddSingleton(new GlobalOptions());
        await using var provider = services.BuildServiceProvider();

        await using (var listenerA = await BannerListener.StartAsync())
        await using (var listenerB = await BannerListener.StartAsync())
        {
            await db.InitializeAsync();

            // Both runs share ONE scope id: baselines are scope-scoped, and drift is a property
            // of one authorization boundary changing state over time.
            var scope = MakeScope(listenerA.Port, listenerB.Port);

            // Run 1: discovery observes BOTH live services through the REAL persistence path.
            var assessment1 = await RegisterAsync(db, scope, "drift-run-1");
            await RunDiscoveryAsync(db, scope, assessment1);
            var observed = await db.ListServicesAsync(assessment1.AssessmentId, 100);
            var expectedPairs = new[] { (listenerA.Port, ProtocolKind.Tcp), (listenerB.Port, ProtocolKind.Tcp) }
                .OrderBy(static p => p.Item1).ToList();
            Assert.Equal(expectedPairs,
                observed.Select(o => (o.Port, o.Protocol)).Distinct().OrderBy(o => o.Port).ToList());

            // Baseline creation snapshots both as EXPECTED...
            var baseline = await BaselineOperations.CreateAsync(
                db, assessment1, "drill baseline", "scenario-operator", CorrelationId.New());
            Assert.Equal(
                [new ServiceBaselineEntry(listenerA.Port, ProtocolKind.Tcp, BaselineServiceStatus.Expected),
                 new ServiceBaselineEntry(listenerB.Port, ProtocolKind.Tcp, BaselineServiceStatus.Expected)],
                baseline.ExpectedServices);

            // ...and the operator hardens it: port B must never answer again. The Expected
            // entry for B is superseded - a port cannot be both wanted and forbidden.
            var hardened = await BaselineOperations.MarkProhibitedAsync(
                db, assessment1.AssessmentId, null, listenerB.Port, ProtocolKind.Tcp,
                "scenario-operator", CorrelationId.New());
            Assert.Single(hardened.ExpectedServices, e => e.Port == listenerB.Port);
            Assert.Contains(hardened.ExpectedServices, e =>
                e.Port == listenerB.Port && e.Status == BaselineServiceStatus.Prohibited);

            // The environment drifts while the operator is away: A goes dark, B stays alive.
            await listenerA.StopAcceptingAsync();

            var scopeRun2 = scope with { AssessmentId = Guid.NewGuid() };
            var assessment2 = await RegisterAsync(db, scopeRun2, "drift-run-2");
            await RunDiscoveryAsync(db, scopeRun2, assessment2);

            var comparison = await BaselineOperations.CompareAsync(
                db, assessment2.AssessmentId, null, "scenario-operator", CorrelationId.New());
            Assert.Contains(comparison.Observations, o =>
                o.Kind == DriftAnalyzer.ExpectedServiceAbsent
                && o.SuggestedSeverity == Severity.Medium
                && o.Detail.Contains(listenerA.Port.ToString()));
            Assert.Contains(comparison.Observations, o =>
                o.Kind == DriftAnalyzer.UnexpectedServiceExposed
                && o.SuggestedSeverity == Severity.High
                && o.Detail.Contains(listenerB.Port.ToString()));

            // The banner finding on the exposed prohibited port is drift too: no accepted
            // fingerprint covers it, so it surfaces as NEW at its own severity.
            Assert.Contains(comparison.Observations, o => o.Kind == DriftAnalyzer.NewFinding);

            // The pipeline gate contract: any drift fails the CLI compare with exit code 5.
            var exit = await BaselineCommands.Run(provider,
                ["compare", "--assessment", assessment2.AssessmentId.ToString()]);
            Assert.Equal(ExitCodes.GateFailed, exit);

            var events = await db.ReadRecentAuditAsync(50);
            Assert.Contains(events, e => e.Action == "baseline.created"
                && e.ObjectId == baseline.BaselineId.ToString());
            Assert.Contains(events, e => e.Action == "baseline.prohibited"
                && e.Result.Contains("marked prohibited"));
            Assert.Contains(events, e => e.Action == "baseline.compared");
            Assert.True(await db.VerifyChainAsync());
        }

        SqlitePoolTeardown(databasePath);
    }

    private static void SqlitePoolTeardown(string databasePath)
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(Path.GetDirectoryName(databasePath)!, recursive: true); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private static ScopeDefinition MakeScope(params int[] ports) => new(
        ScopeId: Guid.NewGuid(),
        AssessmentId: Guid.NewGuid(),
        OperatorIdentity: "drift-operator",
        Organization: "artemis-e2e",
        TargetType: TargetTypeKind.Localhost,
        AllowlistedTargets: ["localhost", "127.0.0.1"],
        ExcludedTargets: [],
        PermittedProtocols: [ProtocolKind.Tcp],
        // Port 80 is permitted because the DNS gate's ResolveVerifiedAsync evaluates every
        // host against port 80 before any probe; nothing listens there, so no baseline row
        // or drift expectation ever involves it. Known composition wart, documented here.
        PermittedPorts: [.. ports.Select(PortRange.Single), PortRange.Single(80)],
        RequestsPerSecond: 50,
        ConcurrencyLimit: 2,
        MaxRuntime: TimeSpan.FromMinutes(5),
        MaxRequests: 100,
        AllowedCategories: [CheckCategory.Network],
        ProhibitedCategories: [],
        EmergencyStopEnabled: true,
        EvidenceRetentionPeriod: TimeSpan.FromDays(7),
        DataRedactionPolicy: RedactionPolicy.Standard,
        AuthorizationStatement: "Service drift scenario authorization.");

    private static async Task<AssessmentRecord> RegisterAsync(ActDatabase db, ScopeDefinition scope, string host)
    {
        var record = new AssessmentRecord(
            scope.AssessmentId, scope.ScopeId, host,
            AssessmentRunState.Created, DateTimeOffset.UtcNow, null, null,
            scope.OperatorIdentity, scope.Organization);
        await db.CreateAssessmentAsync(record, scope);
        return record;
    }

    /// <summary>Executes the production discovery check against real listeners, persisting via the real recorder.</summary>
    private static async Task RunDiscoveryAsync(ActDatabase db, ScopeDefinition scope, AssessmentRecord assessment)
    {
        var compiled = new CompiledScope(scope);
        var validator = new ScopeValidator(compiled, new PinningDnsResolver());
        var limiter = new TokenBucketRateLimiter(scope.RequestsPerSecond);
        var budget = ResourceBudget.FromScope(scope, EngineDefaults.Conservative);
        var http = new SafeHttpEngine(validator, validator, budget, limiter, NullLogger.Instance);
        var redactor = new StandardEvidenceRedactor(scope.DataRedactionPolicy);
        var context = new AssessmentContext(
            scope.AssessmentId, scope, validator, http, limiter,
            new EvidenceFactory(redactor),
            NullLogger.Instance,
            AuthorizationFixtureSet.None,
            budget,
            Ledger: new DatabaseRecorder(db, NullLogger<DatabaseRecorder>.Instance),
            LanguageModel: null)
        {
            CancellationToken = CancellationToken.None
        };

        var asset = new AssetRecord(Guid.NewGuid(), scope.AssessmentId, AssetKind.Host,
            "drift-host", "127.0.0.1", [], DateTimeOffset.UtcNow, WithinScope: true);

        var discovery = new ServiceDiscoveryCheck(new DiscoveryServices(
            validator, validator, new TcpServiceProbeAdapter(new TcpServiceProbe(validator, validator, NullLogger.Instance))));
        var checkContext = new SecurityCheckContext(context, asset, Service: null, BaseUrl: null);
        var result = await discovery.ExecuteAsync(checkContext, CancellationToken.None);
        Assert.Equal(CheckExecutionStatus.Completed, result.Status);

        // The ENGINE owns finding persistence from a check's result; driving the check directly
        // mirrors that step here so drift comparison sees exactly what a real run would store.
        var recorder = new DatabaseRecorder(db, NullLogger<DatabaseRecorder>.Instance);
        foreach (var finding in result.Findings)
        {
            await recorder.UpsertFindingAsync(finding, CancellationToken.None);
        }
    }

    /// <summary>A loopback TCP listener that answers every probe with an FTP-style banner.</summary>
    private sealed class BannerListener : IAsyncDisposable
    {
        private readonly TcpListener _listener;
        private readonly CancellationTokenSource _cancellation = new();
        private Task _acceptLoop;

        public int Port { get; }

        private BannerListener(TcpListener listener, int port, Task acceptLoop)
        {
            _listener = listener;
            Port = port;
            _acceptLoop = acceptLoop;
        }

        public static async Task<BannerListener> StartAsync()
        {
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var instance = new BannerListener(listener, ((IPEndPoint)listener.LocalEndpoint).Port, Task.CompletedTask);
            instance._acceptLoop = AcceptLoopAsync(instance._listener, instance._cancellation.Token);
            await Task.Yield();
            return instance;
        }

        private static async Task AcceptLoopAsync(TcpListener listener, CancellationToken cancellation)
        {
            try
            {
                while (!cancellation.IsCancellationRequested)
                {
                    using var client = await listener.AcceptTcpClientAsync(cancellation);
                    _ = AnswerWithBannerAsync(client, cancellation);
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (SocketException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
        }

        private static async Task AnswerWithBannerAsync(TcpClient client, CancellationToken cancellation)
        {
            try
            {
                await using var stream = client.GetStream();
                var banner = Encoding.ASCII.GetBytes("220 test-ftp ready\r\n");
                await stream.WriteAsync(banner, cancellation);
                await stream.FlushAsync(cancellation);
                client.Close();
            }
            catch (IOException)
            {
            }
            catch (OperationCanceledException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
        }

        /// <summary>Simulates the expected service going dark without disposing the socket.</summary>
        public Task StopAcceptingAsync()
        {
            _listener.Stop();
            return Task.CompletedTask;
        }

        public async ValueTask DisposeAsync()
        {
            _cancellation.Cancel();
            try { _listener.Stop(); } catch (ObjectDisposedException) { }
            try { await _acceptLoop; } catch { /* teardown best effort */ }
            _cancellation.Dispose();
        }
    }
}
