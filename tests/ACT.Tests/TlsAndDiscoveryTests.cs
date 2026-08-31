using System.Globalization;
using System.Net;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ACT.Contracts;
using ACT.Network;
using ACT.Network.Checks;
using ACT.Scope;
using ACT.Tls.Checks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

#pragma warning disable SYSLIB0039 // Capability detection intentionally references the deprecated constants targets may still accept.

namespace ACT.Tests;

/// <summary>
/// Unit coverage for TCP service discovery (ACT-NET-DISC-001) and the three TLS checks
/// (ACT-TLS-CERT-001, ACT-TLS-PROTOCOL-002, ACT-TLS-CIPHER-003) against recording fakes.
/// </summary>
public class TlsDiscTests
{
    private const string LabHost = "lab-host.test.internal";
    private const int VersionProbeRequestCount = 4; // one forced-version handshake per candidate version

    // ---------- fakes ----------

    private sealed class FakeDnsGate : IDnsGate
    {
        public List<string> ResolvedHosts { get; } = [];

        public Task<IReadOnlyList<IPAddress>> ResolveVerifiedAsync(string host, int port, CancellationToken cancellationToken)
        {
            ResolvedHosts.Add(host);
            IReadOnlyList<IPAddress> addresses = [IPAddress.Loopback];
            return Task.FromResult(addresses);
        }
    }

    private sealed class FakeScopeValidator : IScopeValidator
    {
        private readonly HashSet<int> _deniedPorts = [];

        public void DenyPort(int port) => _deniedPorts.Add(port);

        public ScopeDecision Evaluate(TargetCandidate candidate)
        {
            return _deniedPorts.Contains(candidate.Port)
                ? ScopeDecision.Deny("PORT_NOT_PERMITTED", "Port denied by unit-test validator.", $"Denied {candidate.Port}.")
                : ScopeDecision.Allow("unit-test-entry", $"Allowed {candidate.Host}:{candidate.Port}.");
        }

        public ScopeDecision EvaluateRedirect(Uri originalUri, Uri redirectTarget) =>
            ScopeDecision.Allow("unit-test-redirect", "Redirect allowed.");

        public Task<ScopeDecision> EvaluateResolvedAsync(string host, int port, CancellationToken cancellationToken) =>
            Task.FromResult(Evaluate(new TargetCandidate(host, port, ProtocolKind.Tcp, null)));
    }

    private sealed class FakeTcpProbe : ITcpProbe
    {
        private readonly Dictionary<int, TcpProbeResult> _results = [];
        public List<(string Host, int Port)> Probed { get; } = [];

        public void ServeBanner(int port, string banner, bool tlsNegotiated = false) =>
            _results[port] = new TcpProbeResult(LabHost, port, true, tlsNegotiated, banner,
                TimeSpan.FromMilliseconds(5), null, "Connected within budget.");

        public async Task<TcpProbeResult> ProbeAsync(string host, int port, CancellationToken cancellationToken)
        {
            Probed.Add((host, port));
            await Task.Yield();
            if (_results.TryGetValue(port, out var served))
            {
                return served with { Host = host };
            }
            return new TcpProbeResult(host, port, false, false, null, TimeSpan.FromMilliseconds(5),
                "No connection could be established on this port.", "All pinned addresses refused or timed out.");
        }
    }

    private sealed class FakeTlsProbe : ITlsProbe
    {
        public TlsProbeResult NaturalResult { get; set; } =
            NaturalResultOf(cert: null, chainErrors: [], cipherSuite: "TLS_AES_128_GCM_SHA256");

        public IReadOnlyList<SslProtocols> AcceptedVersions { get; set; } = [SslProtocols.Tls12, SslProtocols.Tls13];

        public bool ThrowPlatformNotSupported { get; set; }

        public Task<TlsProbeResult> ProbeNaturalAsync(string host, int port, CancellationToken cancellationToken)
        {
            if (ThrowPlatformNotSupported) throw new PlatformNotSupportedException();
            return Task.FromResult(NaturalResult);
        }

        public Task<IReadOnlyList<SslProtocols>> ProbeAcceptedVersionsAsync(string host, int port, CancellationToken cancellationToken)
        {
            if (ThrowPlatformNotSupported) throw new PlatformNotSupportedException();
            IReadOnlyList<SslProtocols> accepted = AcceptedVersions;
            return Task.FromResult(accepted);
        }

        internal static TlsProbeResult NaturalResultOf(X509Certificate2? cert, string[] chainErrors, string? cipherSuite) =>
            new(LabHost, 8443, true, SslProtocols.Tls13, cipherSuite, 128, cert, [], chainErrors,
                TimeSpan.FromMilliseconds(10), null);

        internal static TlsProbeResult FailedHandshake() =>
            new(LabHost, 8443, false, null, null, null, null, [],
                ["RemoteCertificateNotAvailable"], TimeSpan.FromMilliseconds(10),
                "TLS handshake failed during natural negotiation.");
    }

    private sealed class FakeLedger : IAssessmentLedger
    {
        public List<AssetRecord> Assets { get; } = [];
        public List<ServiceObservation> Services { get; } = [];
        public int RecordAssetCalls { get; private set; }

        public Task<AssetRecord> RecordAssetAsync(AssetRecord asset, CancellationToken cancellationToken)
        {
            RecordAssetCalls++;
            var existing = Assets.FirstOrDefault(a => a.AssetId == asset.AssetId);
            if (existing is not null) return Task.FromResult(existing);
            Assets.Add(asset);
            return Task.FromResult(asset);
        }

        public Task<ServiceObservation> RecordServiceAsync(ServiceObservation service, CancellationToken cancellationToken)
        {
            Services.Add(service);
            return Task.FromResult(service);
        }

        public IReadOnlyList<ServiceObservation> ObservedServices() => Services;
    }

    private sealed class FakeRateLimiter : IRateLimiter
    {
        public ValueTask WaitForTokenAsync(CancellationToken cancellationToken) => ValueTask.CompletedTask;
    }

    private sealed class FakeSafeHttpEngine : ISafeHttpEngine
    {
        public Task<SafeHttpResponse> SendAsync(SafeHttpRequest request, CancellationToken cancellationToken) =>
            throw ActException.FailClosed(
                ErrorCategory.Internal,
                "The HTTP engine is not used by these checks.",
                "FakeSafeHttpEngine.SendAsync was invoked unexpectedly.");

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FakeEvidenceFactory : IEvidenceFactory
    {
        public EvidenceItem Create(Guid findingId, EvidenceKind kind, string key, string value,
            CheckId collectedBy, CorrelationId correlation, IReadOnlyDictionary<string, string>? attributes = null) =>
            new(Guid.NewGuid(), findingId, kind, key, value, DateTimeOffset.UtcNow, collectedBy, correlation,
                attributes ?? new Dictionary<string, string>());
    }

    // ---------- shared fixtures ----------

    private static readonly Guid AssessmentGuid = Guid.NewGuid();

    private static ScopeDefinition Scope(params int[] ports) => new(
        ScopeId: Guid.NewGuid(),
        AssessmentId: AssessmentGuid,
        OperatorIdentity: "unit-test-operator",
        Organization: "unit-test-org",
        TargetType: TargetTypeKind.Hostname,
        AllowlistedTargets: [LabHost],
        ExcludedTargets: [],
        PermittedProtocols: [ProtocolKind.Tcp, ProtocolKind.Tls, ProtocolKind.Http, ProtocolKind.Https],
        PermittedPorts: ports.Select(PortRange.Single).ToList(),
        RequestsPerSecond: 10,
        ConcurrencyLimit: 2,
        MaxRuntime: TimeSpan.FromMinutes(10),
        MaxRequests: 1000,
        AllowedCategories: Enum.GetValues<CheckCategory>(),
        ProhibitedCategories: [],
        EmergencyStopEnabled: true,
        EvidenceRetentionPeriod: TimeSpan.FromDays(30),
        DataRedactionPolicy: RedactionPolicy.Standard,
        AuthorizationStatement: "Unit-test operator authorized to assess this lab environment.");

    private static AssetRecord HostAsset(AssetKind kind = AssetKind.Host) => new(
        Guid.NewGuid(), AssessmentGuid, kind, "lab-host", LabHost, [], DateTimeOffset.UtcNow, WithinScope: true);

    private static ServiceObservation TlsServiceOn(int port) => new(
        Guid.NewGuid(), Guid.NewGuid(), port, ProtocolKind.Tls, null, true, DateTimeOffset.UtcNow,
        CheckId.From("UNIT-TEST-SOURCE"));

    private static AssessmentContext NewAssessment(IScopeValidator validator, IDnsGate gate,
        IAssessmentLedger ledger, ScopeDefinition scope) => new(
        AssessmentGuid,
        scope,
        validator,
        new FakeSafeHttpEngine(),
        new FakeRateLimiter(),
        new FakeEvidenceFactory(),
        NullLogger.Instance,
        AuthorizationFixtureSet.None,
        ResourceBudget.FromScope(scope, EngineDefaults.Conservative),
        ledger,
        LanguageModel: null)
        { CancellationToken = CancellationToken.None };

    private sealed class DiscoveryFixture
    {
        public SecurityCheckContext Context { get; init; } = null!;
        public FakeLedger Ledger { get; init; } = new();
        public FakeTcpProbe Probe { get; init; } = new();
        public FakeScopeValidator Validator { get; init; } = new();

        public Task<SecurityCheckResult> Run() => RunWith(
            new DiscoveryServices(Validator, new FakeDnsGate(), Probe));

        public Task<SecurityCheckResult> RunWith(DiscoveryServices services)
        {
            var check = new ServiceDiscoveryCheck(services);
            return check.ExecuteAsync(Context, CancellationToken.None);
        }
    }

    private static DiscoveryFixture NewDiscovery(params int[] ports)
    {
        var ledger = new FakeLedger();
        var validator = new FakeScopeValidator();
        var assessment = NewAssessment(validator, new FakeDnsGate(), ledger, Scope(ports));
        return new DiscoveryFixture
        {
            Context = new SecurityCheckContext(assessment, HostAsset(), Service: null, BaseUrl: null),
            Ledger = ledger,
            Validator = validator,
        };
    }

    private sealed class TlsFixture
    {
        public SecurityCheckContext Context { get; init; } = null!;
        public FakeTlsProbe Probe { get; init; } = new();
        public bool? Tls13RuntimeUnsupportedOverride { get; set; }

        public Task<SecurityCheckResult> RunCertificate() =>
            new CertificateTrustCheck(NewServices()).ExecuteAsync(Context, CancellationToken.None);

        public Task<SecurityCheckResult> RunProtocol()
        {
            var check = new ProtocolVersionsCheck(NewServices());
            check.Tls13RuntimeUnsupportedOverride = Tls13RuntimeUnsupportedOverride;
            return check.ExecuteAsync(Context, CancellationToken.None);
        }

        public Task<SecurityCheckResult> RunCipher() =>
            new CipherSuiteCheck(NewServices()).ExecuteAsync(Context, CancellationToken.None);

        private TlsServices NewServices() => new(new FakeScopeValidator(), new FakeDnsGate(), Probe);
    }

    private static TlsFixture NewTls()
    {
        var assessment = NewAssessment(new FakeScopeValidator(), new FakeDnsGate(), new FakeLedger(), Scope(8443));
        return new TlsFixture
        {
            Context = new SecurityCheckContext(assessment, HostAsset(), TlsServiceOn(8443), BaseUrl: null),
        };
    }

    private static Finding? ByTitle(SecurityCheckResult result, string title) =>
        result.Findings.FirstOrDefault(f => f.Title == title);

    private static X509Certificate2 NewRoot()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Lab Test Root", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(5));
    }

    private static X509Certificate2 NewLeafFrom(X509Certificate2 issuer)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=" + LabHost, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.Create(issuer, DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(30),
            RandomNumberGenerator.GetBytes(16));
    }

    private static X509Certificate2 ExpiredSelfSigned()
    {
        using var rsa = RSA.Create(2048);
        return new CertificateRequest("CN=" + LabHost, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(-1));
    }

    private static X509Certificate2 ValidSelfSigned()
    {
        using var rsa = RSA.Create(2048);
        return new CertificateRequest("CN=" + LabHost, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
            .CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(30));
    }

    // ---------- ACT-NET-DISC-001 ----------

    [Fact]
    public async Task Discovery_ProbesOnlyPermittedPorts_AndCountsRequestsHonest()
    {
        var fixture = NewDiscovery(8080, 8443);
        fixture.Probe.ServeBanner(8080, "httpd");
        fixture.Probe.ServeBanner(8443, "secure");

        var result = await fixture.Run();

        Assert.Equal([8080, 8443], fixture.Probe.Probed.Select(p => p.Port).ToArray());
        Assert.All(fixture.Probe.Probed, p => Assert.Equal(LabHost, p.Host));
        Assert.Equal(2, result.RequestCount);
        Assert.Equal(2, result.TargetsExamined);
        Assert.Equal(CheckExecutionStatus.Completed, result.Status);
    }

    [Fact]
    public async Task Discovery_RecordsEachReachableServiceOnce_AndAssetOnce()
    {
        var fixture = NewDiscovery(8080, 8443, 9000);
        fixture.Probe.ServeBanner(8080, "httpd");
        fixture.Probe.ServeBanner(8443, "secure");
        // Port 9000 stays unreachable.

        var result = await fixture.Run();

        Assert.Equal([8080, 8443], fixture.Ledger.Services.Select(s => s.Port).OrderBy(p => p).ToArray());
        Assert.Equal(1, fixture.Ledger.RecordAssetCalls);
        Assert.Single(fixture.Ledger.Assets);
        Assert.Equal(3, result.TargetsExamined); // attempted ports, reachable or not
        Assert.Equal(3, result.RequestCount);
    }

    [Fact]
    public async Task Discovery_CleartextBanner_EmitsMediumFinding_WithSanitizedEvidence()
    {
        var fixture = NewDiscovery(6379);
        var raw = "REDIS server v7" + new string('x', 300);
        fixture.Probe.ServeBanner(6379, raw);

        var result = await fixture.Run();

        var finding = ByTitle(result, "Cleartext protocol service observed");
        Assert.NotNull(finding);
        Assert.Equal(Severity.Medium, finding!.TechnicalSeverity);
        Assert.Equal(CheckCategory.Network, finding.Category);
        Assert.Equal(ServiceDiscoveryCheck.CheckIdentifier, finding.CheckId);

        var evidence = Assert.Single(result.StandaloneEvidence, e => e.Key == "service_banner_redacted");
        Assert.DoesNotContain('\u0002', evidence.RedactedValue);
        Assert.True(evidence.RedactedValue.Length <= 128);
        Assert.StartsWith("REDIS server v7", evidence.RedactedValue);

        var observation = Assert.Single(fixture.Ledger.Services);
        Assert.False(observation.TlsNegotiated);
        Assert.Equal(evidence.RedactedValue, observation.Banner);
    }

    [Fact]
    public async Task Discovery_CleartextKeyword_OnWebHost_IsNotFlagged()
    {
        var fixture = NewDiscovery(80);
        fixture.Probe.ServeBanner(80, "nginx fronting redis cluster");

        var result = await fixture.Run();

        Assert.Empty(result.Findings);
        Assert.Single(fixture.Ledger.Services); // still recorded honestly, just not flagged
    }

    [Fact]
    public async Task Discovery_TlsProtectedBanner_IsNotFlagged()
    {
        var fixture = NewDiscovery(8443);
        fixture.Probe.ServeBanner(8443, "smtp relay ready", tlsNegotiated: true);

        var result = await fixture.Run();

        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task Discovery_UnreachablePorts_CountedSilently_WithoutServicesOrFindings()
    {
        var fixture = NewDiscovery(8080, 8443, 9999);

        var result = await fixture.Run();

        Assert.Equal(CheckExecutionStatus.Completed, result.Status);
        Assert.Empty(result.Findings);
        Assert.Empty(fixture.Ledger.Services);
        Assert.Equal(0, fixture.Ledger.RecordAssetCalls);
        Assert.Equal(3, result.RequestCount);
        Assert.Equal(3, result.TargetsExamined);
    }

    [Fact]
    public async Task Discovery_ScopeValidatorDenial_SkipsPortSilently()
    {
        var fixture = NewDiscovery(8080, 8443);
        fixture.Validator.DenyPort(8443);
        fixture.Probe.ServeBanner(8080, "httpd");

        var result = await fixture.Run();

        Assert.Equal([8080], fixture.Probe.Probed.Select(p => p.Port).ToArray());
        Assert.Equal(1, result.RequestCount);
        Assert.Equal(1, result.TargetsExamined);
        Assert.Single(fixture.Ledger.Services);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task Discovery_NonHostAssetKind_SkipsWithoutContact()
    {
        var ledger = new FakeLedger();
        var assessment = NewAssessment(new FakeScopeValidator(), new FakeDnsGate(), ledger, Scope(8080));
        var context = new SecurityCheckContext(assessment, HostAsset(AssetKind.Repository), null, null);
        var probe = new FakeTcpProbe();

        var result = await new ServiceDiscoveryCheck(
            new DiscoveryServices(new FakeScopeValidator(), new FakeDnsGate(), probe))
            .ExecuteAsync(context, CancellationToken.None);

        Assert.Equal(CheckExecutionStatus.Skipped_NotApplicable, result.Status);
        Assert.Empty(probe.Probed);
        Assert.Equal(0, result.RequestCount);
    }

    [Fact]
    public void Discovery_MissingDependency_FailsClosed()
    {
        var gate = new FakeDnsGate();
        var probe = new FakeTcpProbe();
        Assert.Throws<ActException>(() => new DiscoveryServices(null!, gate, probe));
        Assert.Throws<ActException>(() => new DiscoveryServices(new FakeScopeValidator(), null!, probe));
        Assert.Throws<ActException>(() => new DiscoveryServices(new FakeScopeValidator(), gate, null!));
    }

    // ---------- ACT-TLS-CERT-001 ----------

    [Fact]
    public async Task Cert_ExpiredCertificate_EmitsHighFinding()
    {
        var fixture = NewTls();
        using var expired = ExpiredSelfSigned();
        fixture.Probe.NaturalResult = FakeTlsProbe.NaturalResultOf(expired, [], "TLS_AES_128_GCM_SHA256");

        var result = await fixture.RunCertificate();

        var finding = ByTitle(result, "Expired TLS certificate presented");
        Assert.NotNull(finding);
        Assert.Equal(Severity.High, finding!.TechnicalSeverity);
        Assert.Contains("NotAfter", finding.Description, StringComparison.Ordinal);
        Assert.Equal(CheckExecutionStatus.Completed, result.Status);
        Assert.Equal(1, result.RequestCount);
    }

    [Fact]
    public async Task Cert_SelfSignedValidDate_EmitsMediumFinding()
    {
        var fixture = NewTls();
        using var selfSigned = ValidSelfSigned();
        fixture.Probe.NaturalResult = FakeTlsProbe.NaturalResultOf(selfSigned, [], "TLS_AES_256_GCM_SHA384");

        var result = await fixture.RunCertificate();

        var finding = ByTitle(result, "Self-signed certificate in use");
        Assert.NotNull(finding);
        Assert.Equal(Severity.Medium, finding!.TechnicalSeverity);
        Assert.DoesNotContain(result.Findings, f => f.TechnicalSeverity >= Severity.High);
    }

    [Fact]
    public async Task Cert_NameMismatch_EmitsHighFinding()
    {
        var fixture = NewTls();
        using var root = NewRoot();
        using var leaf = NewLeafFrom(root);
        fixture.Probe.NaturalResult = FakeTlsProbe.NaturalResultOf(
            leaf, ["RemoteCertificateNameMismatch"], "TLS_AES_128_GCM_SHA256");

        var result = await fixture.RunCertificate();

        var finding = ByTitle(result, "TLS certificate does not match the target name");
        Assert.NotNull(finding);
        Assert.Equal(Severity.High, finding!.TechnicalSeverity);
        Assert.True(finding.ExploitabilityIndicator);
    }

    [Fact]
    public async Task Cert_IncompleteChainOnly_EmitsInformational()
    {
        var fixture = NewTls();
        using var root = NewRoot();
        using var leaf = NewLeafFrom(root);
        fixture.Probe.NaturalResult = FakeTlsProbe.NaturalResultOf(
            leaf, ["unable to get local issuer certificate"], "TLS_AES_128_GCM_SHA256");

        var result = await fixture.RunCertificate();

        var finding = ByTitle(result, "Incomplete certificate chain observed");
        Assert.NotNull(finding);
        Assert.Equal(Severity.Informational, finding!.TechnicalSeverity);
        Assert.Single(result.Findings);
    }

    [Fact]
    public async Task Cert_ValidChain_ProducesEvidenceWithoutFindings()
    {
        var fixture = NewTls();
        using var root = NewRoot();
        using var leaf = NewLeafFrom(root);
        fixture.Probe.NaturalResult = FakeTlsProbe.NaturalResultOf(leaf, [], "TLS_AES_128_GCM_SHA256");

        var result = await fixture.RunCertificate();

        Assert.Empty(result.Findings);
        Assert.Equal(CheckExecutionStatus.Completed, result.Status);
        Assert.Contains(result.StandaloneEvidence, e => e.Kind == EvidenceKind.CertificateMetadata && e.Key == "subject");
        Assert.Contains(result.StandaloneEvidence, e => e.Key == "issuer");
        var notAfter = Assert.Single(result.StandaloneEvidence, e => e.Key == "not_after");
        Assert.True(
            DateTimeOffset.TryParse(notAfter.RedactedValue, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out _),
            "not_after evidence must be an O-format round-trippable timestamp.");
        Assert.Contains(result.StandaloneEvidence, e => e.Kind == EvidenceKind.TlsMetadata);
    }

    [Fact]
    public async Task Cert_FailedHandshake_WarnsWithoutFindings()
    {
        var fixture = NewTls();
        fixture.Probe.NaturalResult = FakeTlsProbe.FailedHandshake();

        var result = await fixture.RunCertificate();

        Assert.Equal(CheckExecutionStatus.CompletedWithWarnings, result.Status);
        Assert.NotNull(result.FailureSummarySafe);
        Assert.Empty(result.Findings);
    }

    // ---------- ACT-TLS-PROTOCOL-002 ----------

    [Fact]
    public async Task Protocol_DeprecatedAccepted_EmitsHighPlusCriticalPlusLow()
    {
        var fixture = NewTls();
        fixture.Probe.AcceptedVersions = [SslProtocols.Tls, SslProtocols.Tls11];
        // The server genuinely lacks TLS 1.3: natural negotiation falls back to TLS 1.2, and the
        // runtime can force versions (override=false), so the "not offered" verdict is reliable.
        fixture.Probe.NaturalResult = new TlsProbeResult(
            "lab.target", 8443, true, SslProtocols.Tls12, "TLS_AES_128_GCM_SHA256", 128, null, [], [],
            TimeSpan.FromMilliseconds(10), null);
        fixture.Tls13RuntimeUnsupportedOverride = false;

        var result = await fixture.RunProtocol();

        var deprecated = ByTitle(result, "Deprecated TLS versions enabled");
        var missing12 = ByTitle(result, "TLS 1.2 support missing");
        var missing13 = ByTitle(result, "TLS 1.3 not offered");
        Assert.NotNull(deprecated);
        Assert.NotNull(missing12);
        Assert.NotNull(missing13);
        Assert.Equal(Severity.High, deprecated!.TechnicalSeverity);
        Assert.Equal(Severity.Critical, missing12!.TechnicalSeverity);
        Assert.Equal(Severity.Low, missing13!.TechnicalSeverity);
        Assert.Equal(VersionProbeRequestCount, result.RequestCount);
    }

    [Fact]
    public async Task Protocol_Tls13ProbeFailsOnUnsupportedRuntime_SkipsVerdictHonestly()
    {
        // On runtimes that cannot complete TLS 1.3 handshakes (e.g. .NET on macOS), a failed
        // forced TLS 1.3 probe must not emit a false "not offered" finding even when the server
        // genuinely supports it.
        var fixture = NewTls();
        fixture.Probe.AcceptedVersions = [SslProtocols.Tls12];
        fixture.Probe.NaturalResult = new TlsProbeResult(
            "lab.target", 8443, true, SslProtocols.Tls12, "TLS_AES_128_GCM_SHA256", 128, null, [], [],
            TimeSpan.FromMilliseconds(10), null);
        fixture.Tls13RuntimeUnsupportedOverride = true;

        var result = await fixture.RunProtocol();

        Assert.Null(ByTitle(result, "TLS 1.3 not offered"));
    }

    [Fact]
    public async Task Protocol_ModernOnly_IsCleanWithOrderedEvidence()
    {
        var fixture = NewTls();
        fixture.Probe.AcceptedVersions = [SslProtocols.Tls12, SslProtocols.Tls13];

        var result = await fixture.RunProtocol();

        Assert.Empty(result.Findings);
        Assert.Equal(CheckExecutionStatus.Completed, result.Status);
        var versions = Assert.Single(result.StandaloneEvidence, e => e.Key == "accepted_versions");
        Assert.Equal("Tls13,Tls12", versions.RedactedValue);
    }

    [Fact]
    public async Task Protocol_PlatformUnsupported_SkipsNotApplicable_Honestly()
    {
        var fixture = NewTls();
        fixture.Probe.ThrowPlatformNotSupported = true;

        var result = await fixture.RunProtocol();

        Assert.Equal(CheckExecutionStatus.Skipped_NotApplicable, result.Status);
        Assert.NotNull(result.FailureSummarySafe);
        Assert.Contains("unknown", result.FailureSummarySafe!, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task Protocol_NoVersionAccepted_WarnsInsteadOfGuessing()
    {
        var fixture = NewTls();
        fixture.Probe.AcceptedVersions = [];

        var result = await fixture.RunProtocol();

        Assert.Equal(CheckExecutionStatus.CompletedWithWarnings, result.Status);
        Assert.NotNull(result.FailureSummarySafe);
        Assert.Empty(result.Findings);
    }

    // ---------- ACT-TLS-CIPHER-003 ----------

    [Theory]
    [InlineData("TLS_RSA_WITH_RC4_128_SHA")]
    [InlineData("TLS_NULL_WITH_NULL_NULL")]
    [InlineData("TLS_DH_anon_WITH_AES_128_CBC_SHA")]
    [InlineData("TLS_RSA_EXPORT_WITH_DES40_CBC_SHA")]
    public async Task Cipher_CriticallyWeakSuites_EmitHigh(string suite)
    {
        var fixture = NewTls();
        fixture.Probe.NaturalResult = FakeTlsProbe.NaturalResultOf(null, [], suite);

        var result = await fixture.RunCipher();

        var finding = ByTitle(result, "Cryptographically broken TLS cipher suite negotiated");
        Assert.NotNull(finding);
        Assert.Equal(Severity.High, finding!.TechnicalSeverity);
    }

    [Fact]
    public async Task Cipher_ThreeDes_EmitsMedium()
    {
        var fixture = NewTls();
        fixture.Probe.NaturalResult = FakeTlsProbe.NaturalResultOf(null, [], "TLS_RSA_WITH_3DES_EDE_CBC_SHA");

        var result = await fixture.RunCipher();

        var finding = ByTitle(result, "Legacy 3DES cipher suite negotiated");
        Assert.NotNull(finding);
        Assert.Equal(Severity.Medium, finding!.TechnicalSeverity);
    }

    [Fact]
    public async Task Cipher_ModernSuite_IsCleanButRecorded()
    {
        var fixture = NewTls();
        fixture.Probe.NaturalResult = FakeTlsProbe.NaturalResultOf(null, [], "TLS_AES_128_GCM_SHA256");

        var result = await fixture.RunCipher();

        Assert.Empty(result.Findings);
        var suite = Assert.Single(result.StandaloneEvidence, e => e.Key == "cipher_suite");
        Assert.Equal("TLS_AES_128_GCM_SHA256", suite.RedactedValue);
    }

    [Fact]
    public async Task Cipher_UnreportedSuite_EmitsInformational()
    {
        var fixture = NewTls();
        fixture.Probe.NaturalResult = FakeTlsProbe.NaturalResultOf(null, [], null);

        var result = await fixture.RunCipher();

        var finding = ByTitle(result, "Negotiated cipher suite could not be determined");
        Assert.NotNull(finding);
        Assert.Equal(Severity.Informational, finding!.TechnicalSeverity);
        Assert.Equal(ConfidenceLevel.Low, finding.Confidence);
    }

    // ---------- composition-root guards ----------

    [Fact]
    public void TlsServices_MissingDependency_FailsClosed()
    {
        var gate = new FakeDnsGate();
        var probe = new FakeTlsProbe();
        Assert.Throws<ActException>(() => new TlsServices(null!, gate, probe));
        Assert.Throws<ActException>(() => new TlsServices(new FakeScopeValidator(), null!, probe));
        Assert.Throws<ActException>(() => new TlsServices(new FakeScopeValidator(), gate, null!));
    }

    [Fact]
    public void Adapters_MissingUnderlyingProbe_FailClosed()
    {
        Assert.Throws<ActException>(() => new TcpServiceProbeAdapter(null!));
        Assert.Throws<ActException>(() => new TlsHandshakeProbeAdapter(null!));
    }
}
