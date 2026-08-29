using ACT.Contracts;
using ACT.Evidence;
using ACT.Network;
using ACT.Scope;
using Microsoft.Extensions.Logging;

namespace ACT.Remediation;

/// <summary>
/// Orchestrates "fix on the spot": derive a plan for a finding, apply it through a local
/// remediation proxy, and verify the fix by re-running the originating check against the
/// corrected endpoint. Verification is honest - the finding is only "Remediated" when the
/// re-check no longer reports it.
/// </summary>
public sealed class RemediationEngine
{
    /// <summary>
    /// Remediates one finding. 'check' is the check that produced the finding; 'upstream' is the
    /// original vulnerable origin. Returns the outcome with the corrected endpoint and before/after
    /// finding counts.
    /// </summary>
    public async Task<RemediationResult> RemediateAsync(
        Finding finding,
        ISecurityCheck check,
        Uri upstream,
        CancellationToken cancellationToken)
    {
        var plan = RemediationPlanner.PlanFor(finding);
        if (plan is null)
        {
            return new RemediationResult(
                finding.FindingId, RemediationOutcome.NotRemediable, null,
                "No executable remediation exists for check " + finding.CheckId.Value + " (" + finding.Title + ").",
                DateTimeOffset.UtcNow, DateTimeOffset.UtcNow, 1, 1);
        }

        await using var proxy = new RemediationProxy(upstream, plan.Actions);
        proxy.Start();
        var endpoint = new Uri(proxy.EndpointUrl);

        // Give the listener a moment to bind.
        await Task.Delay(150, cancellationToken);

        // 'Before' is measured against the ORIGINAL vulnerable upstream; 'after' against the
        // corrected proxy endpoint. The finding is only Remediated when the fix removes it.
        // The upstream's own ports are permitted so a TLS-redirect fix can be followed honestly.
        var extraPorts = new[] { upstream.Port };
        var before = await RunCheckAsync(check, upstream, extraPorts, cancellationToken).ConfigureAwait(false);

        // The TLS-redirect fix makes the proxy bounce HTTP->HTTPS. Re-running the check would
        // follow that bounce into the (possibly self-signed) HTTPS origin, so verify the redirect
        // directly instead: the fix is proven when the corrected endpoint answers 301/302/308 to https.
        if (plan.Actions.Any(a => a.Kind == RemediationActionKind.ForceHttpsRedirect))
        {
            var (redirects, location) = await ProbeRedirectAsync(endpoint, cancellationToken).ConfigureAwait(false);
            var upgrades = location is not null &&
                Uri.TryCreate(location, UriKind.RelativeOrAbsolute, out var loc) &&
                (loc.IsAbsoluteUri ? loc.Scheme : "http").Equals("https", StringComparison.OrdinalIgnoreCase);
            var tlsResolved = redirects && upgrades;
            return new RemediationResult(
                finding.FindingId,
                tlsResolved ? RemediationOutcome.Remediated : RemediationOutcome.AppliedNotVerified,
                proxy.EndpointUrl,
                tlsResolved
                    ? "Fix verified: corrected endpoint redirects to HTTPS (" + location + ")."
                    : "Fix applied but the corrected endpoint does not redirect to HTTPS yet.",
                DateTimeOffset.UtcNow, DateTimeOffset.UtcNow,
                before.Count, 0);
        }

        var after = await RunCheckAsync(check, endpoint, extraPorts, cancellationToken).ConfigureAwait(false);
        var resolved = after.Count == 0;
        var outcome = resolved ? RemediationOutcome.Remediated : RemediationOutcome.AppliedNotVerified;

        return new RemediationResult(
            finding.FindingId,
            outcome,
            proxy.EndpointUrl,
            resolved
                ? "Fix verified: re-check reports " + after.Count + " finding(s) (was " + before.Count + ")."
                : "Fix applied but re-check still reports " + after.Count + " finding(s).",
            DateTimeOffset.UtcNow, DateTimeOffset.UtcNow,
            before.Count, after.Count);
    }

    /// <summary>
    /// Makes a single non-redirect-following request to the corrected endpoint and reports whether
    /// it answers with an HTTP->HTTPS upgrade redirect and where. Used to verify TLS-redirect fixes
    /// without following the bounce into a possibly self-signed HTTPS origin.
    /// </summary>
    private static async Task<(bool Redirects, string? Location)> ProbeRedirectAsync(
        Uri endpoint, CancellationToken cancellationToken)
    {
        using var handler = new SocketsHttpHandler { AllowAutoRedirect = false, UseCookies = false };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(10) };
        using var response = await client.GetAsync(endpoint, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        var status = (int)response.StatusCode;
        var redirects = status is 301 or 302 or 308;
        var location = response.Headers.Location?.ToString();
        return (redirects, location);
    }

    /// <summary>Runs one check against a base URL with a minimal, self-contained context.</summary>
    private static async Task<IReadOnlyList<Finding>> RunCheckAsync(
        ISecurityCheck check, Uri baseUrl, IReadOnlyCollection<int>? extraPorts, CancellationToken cancellationToken)
    {
        var scopeId = Guid.NewGuid();
        var assessmentId = Guid.NewGuid();
        var port = baseUrl.Port;
        // Permit the base URL's port plus any extra ports (e.g. the upstream's HTTPS port that a
        // TLS-redirect remediation bounces to), so verification can follow the corrected behavior.
        var ports = new List<PortRange> { new(port, port) };
        if (extraPorts is not null)
        {
            foreach (var p in extraPorts.Distinct().Where(p => p > 0 && p != port))
            {
                ports.Add(new PortRange(p, p));
            }
        }
        var scope = new ScopeDefinition(
            ScopeId: scopeId,
            AssessmentId: assessmentId,
            OperatorIdentity: "artemis-remediation",
            Organization: "artemis-remediation",
            TargetType: TargetTypeKind.Localhost,
            AllowlistedTargets: ["127.0.0.1", "localhost", baseUrl.ToString()],
            ExcludedTargets: [],
            PermittedProtocols: [ProtocolKind.Tcp, ProtocolKind.Http, ProtocolKind.Https, ProtocolKind.Tls],
            PermittedPorts: ports,
            RequestsPerSecond: 50,
            ConcurrencyLimit: 4,
            MaxRuntime: TimeSpan.FromSeconds(60),
            MaxRequests: 500,
            AllowedCategories: [CheckCategory.Network, CheckCategory.Tls, CheckCategory.Http, CheckCategory.Api, CheckCategory.Authorization],
            ProhibitedCategories: [],
            EmergencyStopEnabled: true,
            EvidenceRetentionPeriod: TimeSpan.FromDays(1),
            DataRedactionPolicy: RedactionPolicy.Standard,
            AuthorizationStatement: "Remediation verification against a local loopback target.");
        scope.Validate();

        var compiled = new CompiledScope(scope);
        var resolver = new PinningDnsResolver();
        var validator = new ScopeValidator(compiled, resolver);
        var limiter = new TokenBucketRateLimiter(scope.RequestsPerSecond);
        var budget = ResourceBudget.FromScope(scope, EngineDefaults.Conservative);
        var redactor = new StandardEvidenceRedactor(scope.DataRedactionPolicy);

        await using var http = new SafeHttpEngine(
            validator, validator, budget, limiter, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance);

        var evidenceFactory = new EvidenceFactory(redactor);
        var context = new AssessmentContext(
            assessmentId, scope, validator, http, limiter,
            evidenceFactory, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance,
            AuthorizationFixtureSet.None, budget,
            Ledger: new NoopLedger(), LanguageModel: null);

        var asset = new AssetRecord(
            Guid.NewGuid(), assessmentId, AssetKind.Url,
            baseUrl.Host, baseUrl.ToString(), [], DateTimeOffset.UtcNow, WithinScope: true);
        await context.Ledger.RecordAssetAsync(asset, cancellationToken);

        var checkContext = new SecurityCheckContext(context, asset, Service: null, BaseUrl: baseUrl);

        var result = await check.ExecuteAsync(checkContext, cancellationToken).ConfigureAwait(false);
        return result.Findings;
    }

    /// <summary>A read-only ledger for verification runs that must not touch the real database.</summary>
    private sealed class NoopLedger : IAssessmentLedger
    {
        public Task<AssetRecord> RecordAssetAsync(AssetRecord asset, CancellationToken cancellationToken) =>
            Task.FromResult(asset);

        public Task<ServiceObservation> RecordServiceAsync(ServiceObservation service, CancellationToken cancellationToken) =>
            Task.FromResult(service);

        public IReadOnlyList<ServiceObservation> ObservedServices() => [];
    }
}
