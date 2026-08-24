using System.Security.Authentication;
using ACT.Contracts;
using ACT.Network;

namespace ACT.Tls.Checks;

/// <summary>
/// ACT-TLS-PROTOCOL-002: determines which TLS protocol versions the endpoint accepts via
/// forced-version handshakes. Deprecated versions are High; a missing TLS 1.2 floor is
/// Critical; a missing TLS 1.3 ceiling is Low. Platform limits skip honestly.
/// </summary>
public sealed class ProtocolVersionsCheck : ISecurityCheck
{
    /// <summary>Stable identifier of this check.</summary>
    public static readonly CheckId CheckIdentifier = CheckId.From("ACT-TLS-PROTOCOL-002");

    private static readonly SecurityCheckMetadata s_metadata = new(
        Id: CheckIdentifier,
        Name: "TLS Protocol Version Capability",
        Version: "1.0.0",
        Category: CheckCategory.Tls,
        MaxEmittingSeverity: Severity.Critical,
        SafetyLevel: SafetyLevel.Passive,
        RequiredPermissions: PermissionRequirement.OutboundNetworkToLocalTargets,
        RequiredProtocols: new HashSet<ProtocolKind>([ProtocolKind.Tls]),
        SupportedTargetTypes: new HashSet<TargetTypeKind>(
            [TargetTypeKind.Hostname, TargetTypeKind.TestEnvironment, TargetTypeKind.LocalContainer]),
        NetworkBehavior: new NetworkBehaviorProfile(1, TlsCheckRuntime.MaxHandshakesPerTarget, OpensConnections: true, SendsAuthenticationHeaders: false, MutatesTargetState: false),
        EvidenceTypesProduced: [EvidenceKind.TlsMetadata],
        SupportsRemediation: false,
        SupportsRegressionTest: false,
        Description: "Probes accepted protocol versions with bounded handshakes and reports deprecated or insufficient version support.");

    private readonly TlsServices _services;

    /// <summary>Initializes the check and fails closed when its dependencies are missing.</summary>
    public ProtocolVersionsCheck(TlsServices services)
    {
        _services = services ?? throw ActException.FailClosed(
            ErrorCategory.Internal,
            "The TLS check dependencies were not configured.",
            "ProtocolVersionsCheck received a null TlsServices.");
    }

    /// <inheritdoc />
    public SecurityCheckMetadata Metadata => s_metadata;

    /// <inheritdoc />
    public async Task<SecurityCheckResult> ExecuteAsync(SecurityCheckContext context, CancellationToken cancellationToken)
    {
        s_metadata.Validate();
        var started = DateTimeOffset.UtcNow;
        if (!TlsCheckRuntime.IsSupportedAsset(context.Asset.Kind))
        {
            return TlsCheckRuntime.Skip(s_metadata, started,
                "This check applies to host-like targets only; no handshake was attempted.");
        }

        var (host, port) = TlsCheckRuntime.ResolveEndpoint(context);

        IReadOnlyList<SslProtocols> accepted;
        try
        {
            accepted = await _services.Probe.ProbeAcceptedVersionsAsync(host, port, cancellationToken).ConfigureAwait(false);
        }
        catch (PlatformNotSupportedException)
        {
            return TlsCheckRuntime.Skip(s_metadata, started,
                "Forced-version handshakes are unavailable on this platform; the endpoint's accepted TLS versions remain unknown.");
        }

        if (accepted.Count == 0)
        {
            return TlsCheckRuntime.Warn(s_metadata, started,
                "No TLS protocol version completed a handshake; the endpoint may not terminate TLS on this port.",
                requests: TlsCheckRuntime.VersionProbeRequests);
        }

#pragma warning disable SYSLIB0039 // Capability detection must reference the legacy constants the target may still accept.
        var deprecatedAccepted = accepted.Contains(SslProtocols.Tls) || accepted.Contains(SslProtocols.Tls11);
        var tls12Missing = !accepted.Contains(SslProtocols.Tls12);
        var tls13Missing = !accepted.Contains(SslProtocols.Tls13);
#pragma warning restore SYSLIB0039

        var findings = new List<Finding>();
        var evidence = new List<EvidenceItem>();
        var correlation = CorrelationId.New();

        if (deprecatedAccepted)
        {
            findings.Add(CreateFinding(context, host, port, Severity.High,
                title: "Deprecated TLS versions enabled",
                description: "The endpoint still completes handshakes with TLS 1.0 or TLS 1.1, versions formally deprecated by the IETF.",
                whyItMatters:
                    "Legacy TLS versions lack modern cipher and integrity requirements, letting attackers downgrade connections and tamper with sessions.",
                technicalExplanation:
                    "Forced-version handshakes succeeded with at least one of TLS 1.0 and TLS 1.1 during capability probing.",
                remediation: new RemediationGuidance(
                    "Disable TLS 1.0 and 1.1 and require TLS 1.2 as the minimum version.",
                    ["Restrict the listener's EnabledSslProtocols to TLS 1.2 and above.",
                     "Confirm no operational client still depends on the deprecated versions."],
                    ["RFC 8996"]),
                fingerprintClass: "deprecated-tls-enabled"));
        }

        if (tls12Missing)
        {
            findings.Add(CreateFinding(context, host, port, Severity.Critical,
                title: "TLS 1.2 support missing",
                description: "The endpoint refused every handshake attempt that required TLS 1.2, leaving no compliant baseline version available.",
                whyItMatters:
                    "Without TLS 1.2 the service cannot offer a broadly supported, non-deprecated protocol, forcing clients onto weak or obsolete choices.",
                technicalExplanation:
                    "A forced TLS 1.2 handshake failed while at least one other version was accepted during capability probing.",
                remediation: new RemediationGuidance(
                    "Enable TLS 1.2 on the endpoint as the minimum interoperable version.",
                    ["Update the TLS stack or configuration to allow TLS 1.2.",
                     "Verify the negotiated versions after the change."],
                    ["RFC 8446"]),
                fingerprintClass: "tls12-missing"));
        }

        if (tls13Missing)
        {
            findings.Add(CreateFinding(context, host, port, Severity.Low,
                title: "TLS 1.3 not offered",
                description: "The endpoint does not complete TLS 1.3 handshakes, forgoing its performance and privacy improvements.",
                whyItMatters:
                    "TLS 1.3 removes legacy primitives, cuts handshake latency, and encrypts more of the exchange; lacking it signals an aging configuration.",
                technicalExplanation:
                    "A forced TLS 1.3 handshake did not succeed during capability probing.",
                remediation: new RemediationGuidance(
                    "Upgrade the endpoint's TLS stack to support TLS 1.3.",
                    ["Update the runtime or library to a release supporting TLS 1.3.",
                     "Enable TLS 1.3 alongside TLS 1.2 for compatibility."],
                    ["RFC 8446"]),
                fingerprintClass: "tls13-missing"));
        }

        if (findings.Count > 0)
        {
            findings.Sort(static (left, right) => right.TechnicalSeverity.CompareTo(left.TechnicalSeverity));
        }

        Guid attachTo = findings.Count > 0 ? findings[0].FindingId : Guid.Empty;
#pragma warning disable SYSLIB0039
        var orderedNames = string.Join(",", new[] { SslProtocols.Tls13, SslProtocols.Tls12, SslProtocols.Tls11, SslProtocols.Tls }
            .Where(accepted.Contains)
            .Select(v => v.ToString()));
#pragma warning restore SYSLIB0039
        evidence.Add(context.Assessment.Evidence.Create(
            attachTo,
            EvidenceKind.TlsMetadata,
            "accepted_versions",
            orderedNames,
            s_metadata.Id,
            correlation));

        return new SecurityCheckResult(
            s_metadata.Id,
            CheckExecutionStatus.Completed,
            started,
            DateTimeOffset.UtcNow,
            findings,
            evidence,
            FailureSummarySafe: null,
            RequestCount: TlsCheckRuntime.VersionProbeRequests,
            TargetsExamined: 1);
    }

    private static Finding CreateFinding(SecurityCheckContext context, string host, int port,
        Severity severity, string title, string description, string whyItMatters,
        string technicalExplanation, RemediationGuidance remediation, string fingerprintClass) =>
        FindingFactory.Create(
            context.Assessment.AssessmentId,
            s_metadata.Id,
            host + ":" + port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            CheckCategory.Tls,
            title,
            description,
            severity,
            ConfidenceLevel.High,
            exploitabilityIndicator: severity >= Severity.High,
            businessImpact: severity switch
            {
                Severity.Critical => BusinessImpactLevel.Severe,
                Severity.High => BusinessImpactLevel.Significant,
                _ => BusinessImpactLevel.Limited
            },
            whyItMatters,
            technicalExplanation + " Endpoint: permitted port " +
                port.ToString(System.Globalization.CultureInfo.InvariantCulture) + ".",
            remediation,
            new FingerprintComponents(s_metadata.Id, host, TlsCheckRuntime.Resource(host, port), fingerprintClass),
            assetReference: context.Asset.CanonicalTarget);
}
