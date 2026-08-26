
using System.Net;
using ACT.Contracts;
using ACT.Network;
using ACT.Reporting;
using ACT.Scope;
using BenchmarkDotNet.Attributes;

namespace ACT.Benchmarks;

/// <summary>
/// Hot-path benchmarks for authorization decisions, fingerprinting, report rendering,
/// and admission control. Run explicitly via:
///   dotnet run -c Release --project tests/ACT.Benchmarks -- --filter *
/// </summary>
[MemoryDiagnoser]
public class ScopeEvaluationBenchmarks
{
    private CompiledScope _compiled = null!;
    private ScopeValidator _validator = null!;
    private TargetCandidate _allowed = null!;
    private TargetCandidate _deniedPort = null!;
    private TargetCandidate _deniedHost = null!;

    [GlobalSetup]
    public void Setup()
    {
        var scope = new ScopeDefinition(
            Guid.NewGuid(), Guid.NewGuid(), "bench", "bench-org",
            TargetTypeKind.PrivateSubnet,
            ["10.60.0.0/16", "app.bench.internal"],
            ["10.60.66.6"],
            [ProtocolKind.Tcp, ProtocolKind.Http, ProtocolKind.Https],
            [new PortRange(8080, 8090), PortRange.Single(443)],
            100, 4, TimeSpan.FromMinutes(30), 50000,
            Enum.GetValues<CheckCategory>(), [], true,
            TimeSpan.FromDays(30), RedactionPolicy.Standard, "benchmark authorization");
        _compiled = new CompiledScope(scope);
        _validator = new ScopeValidator(_compiled, new StaticResolver([]));
        _allowed = new TargetCandidate("10.60.12.34", 8085, ProtocolKind.Http, null);
        _deniedPort = new TargetCandidate("10.60.12.34", 9999, ProtocolKind.Http, null);
        _deniedHost = new TargetCandidate("10.61.12.34", 8085, ProtocolKind.Http, null);
    }

    [Benchmark(Baseline = true)]
    public bool EvaluateAllowed() => _compiled.MatchesAnyAllow(_allowed, out _);

    [Benchmark]
    public int EvaluateThreeVerdicts()
    {
        var score = 0;
        score += _validator.Evaluate(_allowed).Allowed ? 1 : 0;
        score += _validator.Evaluate(_deniedPort).Allowed ? 1 : 0;
        score += _validator.Evaluate(_deniedHost).Allowed ? 1 : 0;
        return score;
    }
}

[MemoryDiagnoser]
public class FingerprintBenchmarks
{
    private FingerprintComponents _components = null!;

    [GlobalSetup]
    public void Setup()
    {
        _components = new FingerprintComponents(
            CheckId.From("ACT-WEB-HSTS-001"),
            "https://target.example.test:8443",
            "/api/v2/items",
            "hsts-missing");
    }

    [Benchmark]
    public string Sha256Fingerprint() => FindingFingerprinter.Fingerprint(_components).Hash;
}

[MemoryDiagnoser]
public class RateLimiterBenchmarks
{
    private TokenBucketRateLimiter _limiter = null!;

    [Params(50, 1000)]
    public double TokensPerSecond { get; set; }

    [GlobalSetup]
    public void Setup()
    {
        // Generous bucket so the benchmark measures admission cost, not wall-clock waits.
        _limiter = new TokenBucketRateLimiter(TokensPerSecond);
        Thread.Sleep(200); // let it refill fully
    }

    [Benchmark]
    public async ValueTask AdmitTenTokens()
    {
        for (var i = 0; i < 10; i++)
        {
            await _limiter.WaitForTokenAsync(CancellationToken.None);
        }
    }
}

[MemoryDiagnoser]
public class ReportRenderingBenchmarks
{
    private ReportInput _input = null!;
    private ReportAssembler _assembler = null!;

    [GlobalSetup]
    public void Setup()
    {
        _assembler = new ReportAssembler();
        var findings = Enumerable.Range(0, 250).Select(i =>
        {
            var finding = FindingFactory.Create(
                Guid.NewGuid(),
                CheckId.From("ACT-BENCH-" + (i % 5).ToString("000")),
                "https://bench.target:" + (8000 + i % 40),
                CheckCategory.Http,
                "Benchmark finding " + i,
                "Generated description body for benchmark load.",
                (Severity)(i % 5),
                ConfidenceLevel.High,
                exploitabilityIndicator: i % 3 == 0,
                BusinessImpactLevel.Limited,
                "why", "how",
                new RemediationGuidance("Fix it.", ["step one", "step two"], []),
                new FingerprintComponents(CheckId.From("ACT-BENCH-" + (i % 5).ToString("000")),
                    "https://bench.target:" + (8000 + i % 40),
                    "/resource/" + i,
                    "class-" + i % 7));
            return finding with { PriorityScore = i % 101 };
        }).ToList();

        _input = new ReportInput(
            new AssessmentRecord(Guid.NewGuid(), Guid.NewGuid(), "benchmark-assessment",
                AssessmentRunState.Completed, DateTimeOffset.UtcNow.AddDays(-1),
                DateTimeOffset.UtcNow.AddDays(-1).AddMinutes(-9), DateTimeOffset.UtcNow.AddDays(-1),
                "bench-operator", "bench-org"),
            new ScopeDefinition(Guid.NewGuid(), Guid.NewGuid(), "b", "o", TargetTypeKind.Url,
                ["https://bench.target"], [], [ProtocolKind.Https], [PortRange.Single(8443)],
                25, 2, TimeSpan.FromHours(1), 9000,
                [CheckCategory.Http], [], true, TimeSpan.FromDays(14),
                RedactionPolicy.Standard, "benchmark scope statement"),
            findings.Select(f => new FindingWithEvidence(f, [])).ToList(),
            new ScanMetricsRecord(Guid.NewGuid(), 4200, 96, 2, 250, TimeSpan.FromMinutes(9.4), 18_400_000),
            new VerificationCoverage(96, 12, 3, 1, 40, 8),
            "Benchmark limitations text.",
            DateTimeOffset.UtcNow,
            "Artemis-bench");
    }

    [Benchmark]
    public Task<string> RenderSarif250Findings() => _assembler.RenderAsync(_input, ReportFormat.Sarif, CancellationToken.None);

    [Benchmark]
    public Task<string> RenderCsv250Findings() => _assembler.RenderAsync(_input, ReportFormat.Csv, CancellationToken.None);

    [Benchmark]
    public Task<string> RenderHtml250Findings() => _assembler.RenderAsync(_input, ReportFormat.Html, CancellationToken.None);
}

public static class Program
{
    public static void Main(string[] args)
    {
        // Route the real command line through BenchmarkSwitcher so documented invocations like
        // '--filter *PlanExclusion*' select benchmarks instead of every class running always.
        BenchmarkDotNet.Running.BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args);
    }
}

internal sealed class StaticResolver(System.Collections.Generic.IReadOnlyList<IPAddress> addresses) : IDnsResolver
{
    public System.Threading.Tasks.Task<System.Collections.Generic.IReadOnlyList<IPAddress>> ResolveAsync(
        string host, System.Threading.CancellationToken cancellationToken) =>
        System.Threading.Tasks.Task.FromResult(addresses);
}
