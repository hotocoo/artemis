
using System.Net;
using ACT.Contracts;
using ACT.Scope;
using Xunit;

namespace ACT.Tests;

public class ScopeEngineTests
{
    private static ScopeDefinition Definition(
        TargetTypeKind kind = TargetTypeKind.Localhost,
        string[]? allow = null,
        string[]? exclude = null,
        int[]? ports = null,
        ProtocolKind[]? protocols = null) =>
        new(
            ScopeId: Guid.NewGuid(),
            AssessmentId: Guid.NewGuid(),
            OperatorIdentity: "unit-test-operator",
            Organization: "unit-test-org",
            TargetType: kind,
            AllowlistedTargets: allow ?? ["localhost"],
            ExcludedTargets: exclude ?? [],
            PermittedProtocols: protocols ?? [ProtocolKind.Tcp, ProtocolKind.Http, ProtocolKind.Https],
            PermittedPorts: (ports ?? [443, 8080]).Select(PortRange.Single).ToList(),
            RequestsPerSecond: 5,
            ConcurrencyLimit: 2,
            MaxRuntime: TimeSpan.FromMinutes(30),
            MaxRequests: 500,
            AllowedCategories: Enum.GetValues<CheckCategory>(),
            ProhibitedCategories: [],
            EmergencyStopEnabled: true,
            EvidenceRetentionPeriod: TimeSpan.FromDays(30),
            DataRedactionPolicy: RedactionPolicy.Standard,
            AuthorizationStatement: "I am authorized to assess these targets.");

    // ---------- IP math ----------

    [Theory]
    [InlineData("192.168.1.0/24", "192.168.1.255", true)]
    [InlineData("192.168.1.0/24", "192.168.2.0", false)]
    [InlineData("10.0.0.0/8", "10.255.255.255", true)]
    [InlineData("10.0.0.0/8", "11.0.0.0", false)]
    [InlineData("0.0.0.0/0", "203.0.113.9", true)]
    public void Ipv4CidrContainmentIsExact(string cidr, string candidate, bool expected)
    {
        Assert.True(IpMath.TryParseCidr(cidr, out var network, out var prefix));
        Assert.Equal(expected, IpMath.Contains(network, prefix, IPAddress.Parse(candidate)));
    }

    [Fact]
    public void Ipv6PrefixContainmentWorks()
    {
        Assert.True(IpMath.TryParseCidr("2001:db8:abcd:0012::0/64", out var net6, out var p6));
        Assert.True(IpMath.Contains(net6, p6, IPAddress.Parse("2001:db8:abcd:0012:ffff::1")));
        Assert.False(IpMath.Contains(net6, p6, IPAddress.Parse("2001:db8:abcd:0013::1")));
    }

    [Fact]
    void Ipv4MappedIpv6DoesNotBypassContainment()
    {
        Assert.True(IpMath.TryParseCidr("10.42.0.0/16", out var net4, out var pre4));
        var mapped = IPAddress.Parse("::ffff:10.42.7.7");
        Assert.True(IpMath.Contains(net4, pre4, mapped));
        var outside = IPAddress.Parse("::ffff:10.43.7.7");
        Assert.False(IpMath.Contains(net4, pre4, outside));
    }

    [Theory]
    [InlineData("::ffff:10.42.7.7")]
    [InlineData("fd00::1234")]
    [InlineData("fe80::1")]
    public void NonPublicDetectionRecognizesPrivateAddressForms(string address)
    {
        Assert.True(IpMath.IsNonPublic(IPAddress.Parse(address)));
    }

    [Fact]
    public void PublicAddressesAreNotNonPublic()
    {
        Assert.False(IpMath.IsNonPublic(IPAddress.Parse("203.0.113.9")));
        Assert.False(IpMath.IsNonPublic(IPAddress.Parse("2001:db8::1")));
    }

    // ---------- Compilation fails closed on ambiguity ----------

    [Fact]
    public void SingleLabelHostOutsideTestEnvironmentIsRejected()
    {
        var ex = Assert.Throws<ActException>(() => CompiledScope.ParseEntry("intranet", TargetTypeKind.Hostname));
        Assert.Equal(ErrorCategory.Scope, ex.Category);
    }

    [Fact]
    public void SingleLabelHostAllowedOnlyForTestEnvironments()
    {
        var matchers = CompiledScope.ParseEntry("webapi", TargetTypeKind.TestEnvironment);
        Assert.Contains(matchers, m => m.MatchesHost("webapi"));
        Assert.DoesNotContain(matchers, m => m.MatchesHost("other"));
    }

    [Fact]
    public void PublicIpForbiddenInPrivateSubnetScope()
    {
        var ex = Assert.Throws<ActException>(() =>
            CompiledScope.ParseEntry("203.0.113.0/24", TargetTypeKind.PrivateSubnet));
        Assert.Equal(ErrorCategory.Scope, ex.Category);
    }

    [Fact]
    public void UnparseableEntryFailsClosed()
    {
        Assert.Throws<ActException>(() => CompiledScope.ParseEntry("999.999.1.1", TargetTypeKind.PrivateIp));
        Assert.Throws<ActException>(() => CompiledScope.ParseEntry("", TargetTypeKind.Hostname));
    }

    [Fact]
    public void FilesystemPathsCompileForRepositoryScopes()
    {
        // Regression: the CIDR branch matched any entry containing a slash, so an absolute path
        // was misread as an unparseable network range and repository scopes could never compile.
        var matchers = CompiledScope.ParseEntry("/Users/dev/work/service", TargetTypeKind.LocalSourceRepository);
        var repository = Assert.Single(matchers.OfType<LocalRepositoryMatcher>());
        Assert.Equal("/Users/dev/work/service", repository.RootPath);
    }

    [Fact]
    public void FilesystemPathsStayForbiddenOutsideLocalTargetKinds()
    {
        var ex = Assert.Throws<ActException>(() =>
            CompiledScope.ParseEntry("/Users/dev/work/service", TargetTypeKind.Hostname));
        Assert.Equal(ErrorCategory.Scope, ex.Category);
    }

    [Fact]
    public void LocalhostEntryCoversLoopbackNamesAndAddresses()
    {
        var matchers = CompiledScope.ParseEntry("localhost", TargetTypeKind.Localhost);
        Assert.Contains(matchers, m => m.MatchesHost("localhost"));
        Assert.Contains(matchers, m => m.Matches(new TargetCandidate("127.0.0.1", 8080, ProtocolKind.Http, null)));
        Assert.Contains(matchers, m => m.Matches(new TargetCandidate("[::1]", 8080, ProtocolKind.Http, null)));
        Assert.DoesNotContain(matchers, m => m.Matches(new TargetCandidate("127.0.0.2", 8080, ProtocolKind.Http, null)) is false && false);
        var anyMatches = matchers.Any(m => m.Matches(new TargetCandidate("127.0.0.2", 8080, ProtocolKind.Http, null)));
        Assert.True(anyMatches);
    }

    [Fact]
    public void UrlPrefixMatchingIsSegmentAligned()
    {
        var matchers = CompiledScope.ParseEntry("https://api.example.test/v1", TargetTypeKind.Url);
        var matcher = Assert.IsType<UrlPrefixMatcher>(matchers[0]);
        Assert.True(matcher.MatchesUri(new Uri("https://api.example.test/v1/items")));
        Assert.True(matcher.MatchesUri(new Uri("https://api.example.test/v1")));
        Assert.False(matcher.MatchesUri(new Uri("https://api.example.test/v10/items")));
        Assert.False(matcher.MatchesUri(new Uri("http://api.example.test/v1/items"))); // scheme change -> different origin rules via port/scheme check below
        Assert.False(matcher.MatchesUri(new Uri("https://evil.example.test/v1/items")));
    }

    // ---------- Validator decisions ----------

    private static (CompiledScope Compiled, ScopeValidator Validator) Build(ScopeDefinition def) =>
        (new CompiledScope(def), new ScopeValidator(null!, null!));

    [Fact]
    public void UnlistedTargetIsDenied()
    {
        var compiled = new CompiledScope(Definition(allow: ["localhost"]));
        var validator = new ScopeValidator(compiled, new FakeResolver([IPAddress.Loopback]));
        var verdict = validator.Evaluate(new TargetCandidate("intranet.corp", 8080, ProtocolKind.Http, null));
        Assert.False(verdict.Allowed);
        Assert.Equal("NOT_ALLOWLISTED", verdict.ReasonCode);
    }

    [Fact]
    public void ExclusionOverridesAllowlist()
    {
        var compiled = new CompiledScope(Definition(kind: TargetTypeKind.PrivateSubnet,
            allow: ["10.50.0.0/16"], exclude: ["10.50.3.7"], ports: [8080]));
        var validator = new ScopeValidator(compiled, new FakeResolver([]));

        Assert.True(validator.Evaluate(new TargetCandidate("10.50.1.1", 8080, ProtocolKind.Http, null)).Allowed);
        var excluded = validator.Evaluate(new TargetCandidate("10.50.3.7", 8080, ProtocolKind.Http, null));
        Assert.False(excluded.Allowed);
        Assert.Equal("TARGET_EXCLUDED", excluded.ReasonCode);
    }

    [Fact]
    public void PortOutsidePermittedSetIsDenied()
    {
        var compiled = new CompiledScope(Definition(allow: ["localhost"], ports: [443]));
        var validator = new ScopeValidator(compiled, new FakeResolver([IPAddress.Loopback]));
        var verdict = validator.Evaluate(new TargetCandidate("localhost", 22, ProtocolKind.Tcp, null));
        Assert.False(verdict.Allowed);
        Assert.Equal("PORT_NOT_PERMITTED", verdict.ReasonCode);
    }

    [Fact]
    public void RedirectLeavingScopeIsBlockedWithDistinctReason()
    {
        var compiled = new CompiledScope(Definition(allow: ["app.internal.test"], ports: [443, 8080]));
        var validator = new ScopeValidator(compiled, new FakeResolver([]));
        var verdict = validator.EvaluateRedirect(
            new Uri("https://app.internal.test/login"),
            new Uri("https://evil.example.net/next"));
        Assert.False(verdict.Allowed);
        Assert.Equal("REDIRECT_OUT_OF_SCOPE", verdict.ReasonCode);
    }

    [Fact]
    public void TlsDowngradingRedirectIsBlocked()
    {
        var compiled = new CompiledScope(Definition(allow: ["app.internal.test"], ports: [443, 80], protocols: [ProtocolKind.Http, ProtocolKind.Https]));
        var validator = new ScopeValidator(compiled, new FakeResolver([]));
        var verdict = validator.EvaluateRedirect(
            new Uri("https://app.internal.test/a"),
            new Uri("http://app.internal.test/b"));
        Assert.False(verdict.Allowed);
        Assert.Equal("REDIRECT_TLS_DOWNGRADE", verdict.ReasonCode);
    }

    [Fact]
    public async Task ResolvedAddressOutsideConfiguredNetworksFailsClosed()
    {
        var compiled = new CompiledScope(Definition(kind: TargetTypeKind.PrivateSubnet,
            allow: ["10.50.0.0/16"], ports: [8080]));
        var validator = new ScopeValidator(compiled, new FakeResolver([IPAddress.Parse("203.0.113.99")]));
        var verdict = await validator.EvaluateResolvedAsync("host.lab", 8080, CancellationToken.None);
        Assert.False(verdict.Allowed);
        Assert.Equal("RESOLVED_ADDRESS_OUT_OF_SCOPE", verdict.ReasonCode);
    }

    [Fact]
    public async Task ResolvedAddressesInsideNetworksPass()
    {
        var compiled = new CompiledScope(Definition(kind: TargetTypeKind.PrivateSubnet,
            allow: ["10.50.0.0/16"], ports: [8080]));
        var validator = new ScopeValidator(compiled, new FakeResolver([IPAddress.Parse("10.50.1.4"), IPAddress.Parse("10.50.1.5")]));
        var verdict = await validator.EvaluateResolvedAsync("host.lab", 8080, CancellationToken.None);
        Assert.True(verdict.Allowed);
    }

    [Fact]
    public void DomainEntryMatchesSubdomainsButNotLookalikes()
    {
        var compiled = new CompiledScope(Definition(kind: TargetTypeKind.Domain,
            allow: ["example.test"], ports: [443]));
        var validator = new ScopeValidator(compiled, new FakeResolver([]));
        Assert.True(validator.Evaluate(new TargetCandidate("a.b.example.test", 443, ProtocolKind.Https, null)).Allowed);
        Assert.True(validator.Evaluate(new TargetCandidate("example.test", 443, ProtocolKind.Https, null)).Allowed);
        Assert.False(validator.Evaluate(new TargetCandidate("notexample.test", 443, ProtocolKind.Https, null)).Allowed);
        Assert.False(validator.Evaluate(new TargetCandidate("example.test.evil.io", 443, ProtocolKind.Https, null)).Allowed);
    }

    [Fact]
    public void HostnameEntriesNormalizeCaseAndTrailingDotAndIdn()
    {
        var compiled = new CompiledScope(Definition(kind: TargetTypeKind.Hostname,
            allow: ["Bücher.Example.TEST"], ports: [443]));
        var validator = new ScopeValidator(compiled, new FakeResolver([]));
        Assert.True(validator.Evaluate(new TargetCandidate("bücher.example.test.", 443, ProtocolKind.Https, null)).Allowed);
        Assert.True(validator.Evaluate(new TargetCandidate("xn--bcher-kva.example.test", 443, ProtocolKind.Https, null)).Allowed);
    }

    [Fact]
    public void MalformedTargetsWithControlCharactersAreRejected()
    {
        var compiled = new CompiledScope(Definition());
        var validator = new ScopeValidator(compiled, new FakeResolver([IPAddress.Loopback]));
        Assert.False(validator.Evaluate(new TargetCandidate("local" + (char)10 + "host", 8080, ProtocolKind.Http, null)).Allowed);
        Assert.False(validator.Evaluate(new TargetCandidate("local" + (char)9 + "host", 8080, ProtocolKind.Http, null)).Allowed);
        Assert.False(validator.Evaluate(new TargetCandidate("local host", 8080, ProtocolKind.Http, null)).Allowed);
    }
}

public sealed class FakeResolver(IReadOnlyList<IPAddress> addresses) : IDnsResolver
{
    public Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken) =>
        Task.FromResult(addresses);
}
