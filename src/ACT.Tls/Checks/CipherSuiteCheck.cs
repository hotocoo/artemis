using ACT.Contracts;
using ACT.Network;

namespace ACT.Tls.Checks;

/// <summary>
/// ACT-TLS-CIPHER-003: inspects the cipher suite negotiated during natural TLS handshakes.
/// NULL/EXPORT/anon/RC4 suites are High, 3DES is Medium; an unreported suite yields an
/// honest Informational note and a known-modern suite emits no finding.
/// </summary>
public sealed class CipherSuiteCheck : ISecurityCheck
{
    /// <summary>Stable identifier of this check.</summary>
    public static readonly CheckId CheckIdentifier = CheckId.From("ACT-TLS-CIPHER-003");

    private static readonly string[] CriticallyWeakTokens = ["NULL", "EXPORT", "anon", "RC4"];
    private static readonly string[] WeakTokens = ["3DES"];

    private static readonly SecurityCheckMetadata s_metadata = new(
        Id: CheckIdentifier,
        Name: "TLS Cipher Suite Inspection",
        Version: "1.0.0",
        Category: CheckCategory.Tls,
        MaxEmittingSeverity: Severity.High,
        SafetyLevel: SafetyLevel.Passive,
        RequiredPermissions: PermissionRequirement.OutboundNetworkToLocalTargets,
        RequiredProtocols: new HashSet<ProtocolKind>([ProtocolKind.Tls]),
        SupportedTargetTypes: new HashSet<TargetTypeKind>(
            [TargetTypeKind.Hostname, TargetTypeKind.TestEnvironment, TargetTypeKind.LocalContainer]),
        NetworkBehavior: new NetworkBehaviorProfile(1, TlsCheckRuntime.MaxHandshakesPerTarget, OpensConnections: true, SendsAuthenticationHeaders: false, MutatesTargetState: false),
        EvidenceTypesProduced: [EvidenceKind.TlsMetadata],
        SupportsRemediation: false,
        SupportsRegressionTest: false,
        Description: "Inspects the naturally negotiated cipher suite and reports cryptographically weak selections.");

    private readonly TlsServices _services;

    /// <summary>Initializes the check and fails closed when its dependencies are missing.</summary>
    public CipherSuiteCheck(TlsServices services)
    {
        _services = services ?? throw ActException.FailClosed(
            ErrorCategory.Internal,
            "The TLS check dependencies were not configured.",
            "CipherSuiteCheck received a null TlsServices.");
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
        var correlation = CorrelationId.New();

        TlsProbeResult natural;
        try
        {
            natural = await _services.Probe.ProbeNaturalAsync(host, port, cancellationToken).ConfigureAwait(false);
        }
        catch (PlatformNotSupportedException)
        {
            return TlsCheckRuntime.Skip(s_metadata, started,
                "TLS inspection is not supported on this platform; the negotiated cipher suite could not be observed.");
        }

        if (!natural.HandshakeSucceeded)
        {
            return TlsCheckRuntime.Warn(s_metadata, started,
                natural.FailureSafe ?? "The TLS handshake did not complete; no cipher suite was observed.", requests: 1);
        }

        var findings = new List<Finding>();
        var evidence = new List<EvidenceItem>();
        var suite = normalizedName(natural.CipherSuite);
        var portText = port.ToString(System.Globalization.CultureInfo.InvariantCulture);

        if (suite is null)
        {
            // The platform did not expose a suite name; honesty demands an informational gap note.
            findings.Add(FindingFactory.Create(
                context.Assessment.AssessmentId,
                s_metadata.Id,
                host + ":" + portText,
                CheckCategory.Tls,
                "Negotiated cipher suite could not be determined",
                "The platform completed the handshake but did not report which cipher suite was selected.",
                Severity.Informational,
                ConfidenceLevel.Low,
                exploitabilityIndicator: false,
                businessImpact: BusinessImpactLevel.Unknown,
                whyItMatters:
                    "Without knowing the negotiated suite, weak-cipher exposure cannot be ruled out for this endpoint.",
                technicalExplanation:
                    "The TLS stack returned no cipher suite identifier for the natural negotiation on permitted port " +
                        portText + ".",
                remediation: new RemediationGuidance(
                    "Re-assess from a platform that reports negotiated suites to close this observation gap.",
                    ["Repeat inspection on a platform exposing NegotiatedCipherSuite.",
                     "Prefer explicit cipher configuration server-side."],
                    ["RFC 7525"]),
                new FingerprintComponents(s_metadata.Id, host, TlsCheckRuntime.Resource(host, port), "cipher-suite-unknown"),
                assetReference: context.Asset.CanonicalTarget));
        }
        else if (ContainsAny(suite, CriticallyWeakTokens))
        {
            findings.Add(CreateWeakSuiteFinding(context, host, port, Severity.High,
                title: "Cryptographically broken TLS cipher suite negotiated",
                description: "The endpoint negotiated a suite built on null encryption, export-grade primitives, anonymous key exchange, or RC4.",
                whyItMatters:
                    "These suites provide no meaningful confidentiality or authentication and are exploitable with modest resources.",
                technicalExplanation:
                    "The negotiated suite name matched a critically weak token family during observation of permitted port " +
                        portText + ".",
                fingerprintClass: "critically-weak-cipher"));
        }
        else if (ContainsAny(suite, WeakTokens))
        {
            findings.Add(CreateWeakSuiteFinding(context, host, port, Severity.Medium,
                title: "Legacy 3DES cipher suite negotiated",
                description: "The endpoint accepted a 3DES-based suite, whose small block size enables birthday-bound attacks on long sessions.",
                whyItMatters:
                    "Sweet32-class attacks recover plaintext fragments from long-lived 3DES sessions without breaking the key exchange itself.",
                technicalExplanation:
                    "The negotiated suite name matched the 3DES family during observation of permitted port " +
                        portText + ".",
                fingerprintClass: "legacy-3des-cipher"));
        }

        Guid attachTo = findings.Count > 0 ? findings[0].FindingId : Guid.Empty;
        var attributes = new Dictionary<string, string>();
        if (natural.CipherStrengthBits is { } bits)
        {
            attributes["strength_bits"] = bits.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
        evidence.Add(context.Assessment.Evidence.Create(
            attachTo,
            EvidenceKind.TlsMetadata,
            "cipher_suite",
            suite ?? "unreported",
            s_metadata.Id,
            correlation,
            attributes));

        return new SecurityCheckResult(
            s_metadata.Id,
            CheckExecutionStatus.Completed,
            started,
            DateTimeOffset.UtcNow,
            findings,
            evidence,
            FailureSummarySafe: null,
            RequestCount: 1,
            TargetsExamined: 1);
    }

    /// <summary>Normalizes platform output; an absent or placeholder name becomes null.</summary>
    private static string? normalizedName(string? raw) =>
        string.IsNullOrWhiteSpace(raw) || string.Equals(raw.Trim(), "None", StringComparison.OrdinalIgnoreCase)
            ? null
            : raw!.Trim();

    private static bool ContainsAny(string suite, string[] tokens) =>
        tokens.Any(token => suite.Contains(token, StringComparison.OrdinalIgnoreCase));

    private static Finding CreateWeakSuiteFinding(SecurityCheckContext context, string host, int port,
        Severity severity, string title, string description, string whyItMatters,
        string technicalExplanation, string fingerprintClass) =>
        FindingFactory.Create(
            context.Assessment.AssessmentId,
            s_metadata.Id,
            host + ":" + port.ToString(System.Globalization.CultureInfo.InvariantCulture),
            CheckCategory.Tls,
            title,
            description,
            severity,
            ConfidenceLevel.High,
            exploitabilityIndicator: true,
            businessImpact: BusinessImpactLevel.Significant,
            whyItMatters,
            technicalExplanation,
            new RemediationGuidance(
                "Remove the weak suites from the endpoint's cipher configuration and require AEAD suites.",
                ["Restrict the listener's cipher list to modern AEAD suites.",
                 "Retest the negotiation after the change."],
                ["RFC 7525"]),
            new FingerprintComponents(s_metadata.Id, host, TlsCheckRuntime.Resource(host, port), fingerprintClass),
            assetReference: context.Asset.CanonicalTarget);
}
