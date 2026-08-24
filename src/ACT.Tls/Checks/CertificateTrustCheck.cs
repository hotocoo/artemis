using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using ACT.Contracts;
using ACT.Network;

namespace ACT.Tls.Checks;

/// <summary>
/// ACT-TLS-CERT-001: inspects the certificate served during one natural TLS negotiation.
/// Reports expiry (High), name mismatch (High), self-signed material (Medium), and
/// incomplete-chain-only states (Informational). Purely observational; never trusts the target.
/// </summary>
public sealed class CertificateTrustCheck : ISecurityCheck
{
    /// <summary>Stable identifier of this check.</summary>
    public static readonly CheckId CheckIdentifier = CheckId.From("ACT-TLS-CERT-001");

    private static readonly SecurityCheckMetadata s_metadata = new(
        Id: CheckIdentifier,
        Name: "TLS Certificate Trust Inspection",
        Version: "1.0.0",
        Category: CheckCategory.Tls,
        MaxEmittingSeverity: Severity.High,
        SafetyLevel: SafetyLevel.Passive,
        RequiredPermissions: PermissionRequirement.OutboundNetworkToLocalTargets,
        RequiredProtocols: new HashSet<ProtocolKind>([ProtocolKind.Tls]),
        SupportedTargetTypes: new HashSet<TargetTypeKind>(
            [TargetTypeKind.Host, TargetTypeKind.TestEnvironment, TargetTypeKind.LocalContainer]),
        NetworkBehavior: new NetworkBehaviorProfile(1, TlsCheckRuntime.MaxHandshakesPerTarget, OpensConnections: true, SendsAuthenticationHeaders: false, MutatesTargetState: false),
        EvidenceTypesProduced: [EvidenceKind.CertificateMetadata, EvidenceKind.TlsMetadata],
        SupportsRemediation: false,
        SupportsRegressionTest: false,
        Description: "Observes the served certificate and chain during a passive handshake and reports expiry, naming, and trust-path defects.");

    private readonly TlsServices _services;

    /// <summary>Initializes the check and fails closed when its dependencies are missing.</summary>
    public CertificateTrustCheck(TlsServices services)
    {
        _services = services ?? throw ActException.FailClosed(
            ErrorCategory.Internal,
            "The TLS check dependencies were not configured.",
            "CertificateTrustCheck received a null TlsServices.");
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
                "TLS inspection is not supported on this platform; the served certificate could not be observed.");
        }

        if (!natural.HandshakeSucceeded)
        {
            return TlsCheckRuntime.Warn(s_metadata, started,
                natural.FailureSafe ?? "The TLS handshake did not complete; certificate state is unknown.", requests: 1);
        }

        var findings = new List<Finding>();
        var evidence = new List<EvidenceItem>();
        var nowUtc = DateTimeOffset.UtcNow;
        var certificate = natural.Certificate;

        var expired = (certificate is { } dated && dated.NotAfter < nowUtc) ||
                      natural.ChainErrors.Any(IsExpiryToken);
        var nameMismatch = natural.ChainErrors.Any(
            e => e.Contains("RemoteCertificateNameMismatch", StringComparison.Ordinal));
        var selfSigned = (certificate is { } pair &&
                          string.Equals(pair.Subject.Trim(), pair.Issuer.Trim(), StringComparison.OrdinalIgnoreCase)) ||
                         natural.ChainErrors.Any(e =>
                             e.Contains("UntrustedRoot", StringComparison.OrdinalIgnoreCase) ||
                             e.Contains("self signed", StringComparison.OrdinalIgnoreCase));

        if (expired)
        {
            findings.Add(CreateFinding(context, host, port, Severity.High, ConfidenceLevel.High,
                exploitabilityIndicator: false, businessImpact: BusinessImpactLevel.Limited,
                title: "Expired TLS certificate presented",
                description: "The certificate served on this endpoint is past its NotAfter validity date.",
                whyItMatters:
                    "Expired certificates break trust validation for clients and often indicate neglected operational hygiene around secrets and renewals.",
                technicalExplanation:
                    "The observed certificate's NotAfter timestamp precedes the assessment time, so every validating client rejects it.",
                remediation: new RemediationGuidance(
                    "Renew the certificate from the operator's CA and deploy it before the current one lapses.",
                    ["Issue a replacement certificate with an extended validity window.",
                     "Deploy it to the endpoint and restart or reload the TLS listener.",
                     "Enable automated renewal before the next expiry."],
                    ["RFC 5280"]),
                fingerprintClass: "certificate-expired",
                expiryDetail: certificate?.NotAfter));
        }

        if (nameMismatch)
        {
            findings.Add(CreateFinding(context, host, port, Severity.High, ConfidenceLevel.High,
                exploitabilityIndicator: true, businessImpact: BusinessImpactLevel.Significant,
                title: "TLS certificate does not match the target name",
                description: "The endpoint presented a certificate whose subject does not match the contacted hostname.",
                whyItMatters:
                    "Name mismatches defeat server identity verification, allowing machine-in-the-middle interception even with otherwise valid certificates.",
                technicalExplanation:
                    "The handshake validation callback reported RemoteCertificateNameMismatch while observing the natural negotiation.",
                remediation: new RemediationGuidance(
                    "Deploy a certificate issued for the exact hostname clients use.",
                    ["Request a certificate whose subject alternative names cover the contacted hostname.",
                     "Replace the mismatched certificate on the endpoint."],
                    ["RFC 6125"]),
                fingerprintClass: "certificate-name-mismatch",
                expiryDetail: null));
        }

        if (selfSigned)
        {
            findings.Add(CreateFinding(context, host, port, Severity.Medium, ConfidenceLevel.Medium,
                exploitabilityIndicator: false, businessImpact: BusinessImpactLevel.Limited,
                title: "Self-signed certificate in use",
                description: "The endpoint presented a certificate that signs itself instead of chaining to a trusted authority.",
                whyItMatters:
                    "Clients cannot independently verify self-signed certificates, which normalizes bypass warnings and enables silent substitution attacks.",
                technicalExplanation:
                    "The certificate's subject equals its issuer, or chain evaluation reported an untrusted root during observation.",
                remediation: new RemediationGuidance(
                    "Enroll the endpoint in a certificate chain that terminates at a trusted authority.",
                    ["Issue a CA-signed certificate for the endpoint.",
                     "Distribute the issuing CA through managed trust stores where internal CAs are used."],
                    ["RFC 5280"]),
                fingerprintClass: "certificate-self-signed",
                expiryDetail: null));
        }

        if (!expired && !nameMismatch && !selfSigned &&
            natural.ChainErrors.Count > 0)
        {
            findings.Add(CreateFinding(context, host, port, Severity.Informational, ConfidenceLevel.Low,
                exploitabilityIndicator: false, businessImpact: BusinessImpactLevel.Unknown,
                title: "Incomplete certificate chain observed",
                description: "The endpoint did not serve every intermediate certificate needed to reach a trusted root.",
                whyItMatters:
                    "Incomplete chains work against some clients and fail against others, producing intermittent trust errors that are hard to diagnose.",
                technicalExplanation:
                    "Chain evaluation reported errors beyond expiry, naming, and untrusted-root conditions while observing the handshake.",
                remediation: new RemediationGuidance(
                    "Serve the full intermediate chain alongside the leaf certificate.",
                    ["Append the intermediate certificates to the endpoint's TLS configuration.",
                     "Re-run chain validation with a representative client set."],
                    ["RFC 8446"]),
                fingerprintClass: "certificate-incomplete-chain",
                expiryDetail: null));
        }

        Guid attachTo = findings.Count > 0 ? findings[0].FindingId : Guid.Empty;
        AddObservationEvidence(evidence, context.Assessment.Evidence, attachTo, correlation, natural);

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

    private static bool IsExpiryToken(string error) =>
        error.Contains("NotTimeValid", StringComparison.OrdinalIgnoreCase) ||
        error.Contains("validity period", StringComparison.OrdinalIgnoreCase);

    private static Finding CreateFinding(SecurityCheckContext context, string host, int port,
        Severity severity, ConfidenceLevel confidence, bool exploitabilityIndicator,
        BusinessImpactLevel businessImpact, string title, string description, string whyItMatters,
        string technicalExplanation, RemediationGuidance remediation, string fingerprintClass,
        DateTimeOffset? expiryDetail)
    {
        var portText = port.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var descriptionWithDetail = expiryDetail is { } notAfter
            ? description + " Observed NotAfter: " + notAfter.ToString("O") + "."
            : description;
        return FindingFactory.Create(
            context.Assessment.AssessmentId,
            s_metadata.Id,
            host + ":" + portText,
            CheckCategory.Tls,
            title,
            descriptionWithDetail,
            severity,
            confidence,
            exploitabilityIndicator,
            businessImpact,
            whyItMatters,
            technicalExplanation + " Endpoint: permitted port " + portText + ".",
            remediation,
            new FingerprintComponents(s_metadata.Id, host, TlsCheckRuntime.Resource(host, port), fingerprintClass),
            assetReference: context.Asset.CanonicalTarget);
    }

    /// <summary>Records certificate and session metadata as redacted evidence items.</summary>
    private static void AddObservationEvidence(List<EvidenceItem> sink, IEvidenceFactory factory,
        Guid findingId, CorrelationId correlation, TlsProbeResult natural)
    {
        var attributes = new Dictionary<string, string>
        {
            ["negotiated_protocol"] = natural.NegotiatedProtocol?.ToString() ?? "unknown"
        };
        if (natural.CipherSuite is { } suite)
        {
            attributes["cipher_suite"] = suite;
        }
        if (natural.CipherStrengthBits is { } bits)
        {
            attributes["strength_bits"] = bits.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }
        if (natural.Certificate is { } certificate)
        {
            sink.Add(factory.Create(findingId, EvidenceKind.CertificateMetadata, "subject",
                certificate.Subject, s_metadata.Id, correlation));
            sink.Add(factory.Create(findingId, EvidenceKind.CertificateMetadata, "issuer",
                certificate.Issuer, s_metadata.Id, correlation));
            sink.Add(factory.Create(findingId, EvidenceKind.CertificateMetadata, "not_after",
                certificate.NotAfter.ToString("O"), s_metadata.Id, correlation));
        }
        sink.Add(factory.Create(findingId, EvidenceKind.TlsMetadata, "handshake_observation",
            "chain_errors=" + natural.ChainErrors.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
            s_metadata.Id, correlation, attributes));
    }
}
