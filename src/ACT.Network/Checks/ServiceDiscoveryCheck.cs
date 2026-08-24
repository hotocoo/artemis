using ACT.Contracts;
using ACT.Scope;
using Microsoft.Extensions.Logging;

namespace ACT.Network.Checks;

/// <summary>
/// Passive TCP service discovery across the explicitly permitted ports of the scope only.
/// Records reachable services in the assessment ledger and flags cleartext application
/// protocols announced by banners. One probe request is spent per attempted port.
/// </summary>
public sealed class ServiceDiscoveryCheck : ISecurityCheck
{
    /// <summary>Stable identifier of this check.</summary>
    public static readonly CheckId CheckIdentifier = CheckId.From("ACT-NET-DISC-001");

    private static readonly string[] CleartextKeywords = ["ftp", "smtp", "telnet", "redis", "mysql", "postgres"];

    private const int MaxBannerLength = 128;

    private static readonly SecurityCheckMetadata s_metadata = new(
        Id: CheckIdentifier,
        Name: "TCP Service Discovery",
        Version: "1.0.0",
        Category: CheckCategory.Network,
        MaxEmittingSeverity: Severity.Medium,
        SafetyLevel: SafetyLevel.Passive,
        RequiredPermissions: PermissionRequirement.OutboundNetworkToLocalTargets,
        RequiredProtocols: new HashSet<ProtocolKind>([ProtocolKind.Tcp]),
        SupportedTargetTypes: new HashSet<TargetTypeKind>(
            [TargetTypeKind.Hostname, TargetTypeKind.TestEnvironment, TargetTypeKind.LocalContainer]),
        NetworkBehavior: new NetworkBehaviorProfile(1, 1, OpensConnections: true, SendsAuthenticationHeaders: false, MutatesTargetState: false),
        EvidenceTypesProduced: [EvidenceKind.NetworkObservation],
        SupportsRemediation: false,
        SupportsRegressionTest: false,
        Description: "Probes each permitted port once, records reachable services in the ledger, and reports cleartext application protocols.");

    private readonly DiscoveryServices _services;

    /// <summary>Initializes the check and fails closed when its dependencies are missing.</summary>
    public ServiceDiscoveryCheck(DiscoveryServices services)
    {
        _services = services ?? throw ActException.FailClosed(
            ErrorCategory.Internal,
            "The network discovery dependencies were not configured.",
            "ServiceDiscoveryCheck received a null DiscoveryServices.");
    }

    /// <inheritdoc />
    public SecurityCheckMetadata Metadata => s_metadata;

    /// <inheritdoc />
    public async Task<SecurityCheckResult> ExecuteAsync(SecurityCheckContext context, CancellationToken cancellationToken)
    {
        s_metadata.Validate();
        var started = DateTimeOffset.UtcNow;
        if (!IsSupportedAsset(context.Asset.Kind))
        {
            return SecurityCheckResult.Empty(s_metadata, started, CheckExecutionStatus.Skipped_NotApplicable,
                "Discovery applies to host-like targets only; this asset kind is out of scope for the check.");
        }

        var scope = context.Assessment.Scope;
        if (scope.PermittedPorts.Count == 0)
        {
            return SecurityCheckResult.Empty(s_metadata, started, CheckExecutionStatus.Skipped_NotApplicable,
                "The scope permits no ports; no discovery contact was made.");
        }

        var host = HostOf(context.Asset.CanonicalTarget);

        // Defense in depth: authorize the resolved host before iterating ports. Each probe
        // re-validates host+port internally and fails closed on any drift.
        _ = await _services.Gate.ResolveVerifiedAsync(host, cancellationToken).ConfigureAwait(false);

        var findings = new List<Finding>();
        var evidence = new List<EvidenceItem>();
        var correlation = CorrelationId.New();
        long requests = 0;
        var examined = 0;
        AssetRecord? registeredAsset = null;

        foreach (var range in scope.PermittedPorts)
        {
            for (var port = range.First; port <= range.Last; port++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var verdict = _services.Validator.Evaluate(new TargetCandidate(host, port, ProtocolFor(port), null));
                if (!verdict.Allowed)
                {
                    continue;
                }

                await context.Assessment.RateLimiter.WaitForTokenAsync(cancellationToken).ConfigureAwait(false);
                requests++;
                examined++;

                var probe = await _services.Probe.ProbeAsync(host, port, cancellationToken).ConfigureAwait(false);
                if (!probe.Reachable)
                {
                    context.Assessment.Logger.LogDebug(
                        "Discovery port {Port} unreachable after {ElapsedMs}ms",
                        port, (long)probe.Elapsed.TotalMilliseconds);
                    continue;
                }

                registeredAsset ??= await context.Assessment.Ledger
                    .RecordAssetAsync(context.Asset, cancellationToken).ConfigureAwait(false);

                var banner = SanitizeBanner(probe.Banner);
                var observation = new ServiceObservation(
                    Guid.NewGuid(),
                    registeredAsset.AssetId,
                    port,
                    ProtocolFor(port),
                    banner,
                    probe.TlsNegotiated,
                    DateTimeOffset.UtcNow,
                    s_metadata.Id);
                _ = await context.Assessment.Ledger.RecordServiceAsync(observation, cancellationToken).ConfigureAwait(false);

                evidence.Add(context.Assessment.Evidence.Create(
                    Guid.Empty,
                    EvidenceKind.NetworkObservation,
                    "reachable_service",
                    "port=" + port.ToString(System.Globalization.CultureInfo.InvariantCulture) + "; tls=" + (probe.TlsNegotiated ? "yes" : "no"),
                    s_metadata.Id,
                    correlation));

                if (!probe.TlsNegotiated && !IsWebPort(port) &&
                    TryMatchCleartext(banner, out var keyword))
                {
                    var finding = FindingFactory.Create(
                        context.Assessment.AssessmentId,
                        s_metadata.Id,
                        host + ":" + port.ToString(System.Globalization.CultureInfo.InvariantCulture),
                        CheckCategory.Network,
                        "Cleartext protocol service observed",
                        "A service answering on permitted port " +
                            port.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                            " announced the '" + keyword + "' application protocol while serving plaintext traffic.",
                        Severity.Medium,
                        ConfidenceLevel.High,
                        exploitabilityIndicator: false,
                        businessImpact: BusinessImpactLevel.Limited,
                        whyItMatters:
                            "Cleartext protocols expose credentials, session content, and server metadata to anyone able to observe the network path.",
                        technicalExplanation:
                            "The service banner on port " +
                                port.ToString(System.Globalization.CultureInfo.InvariantCulture) +
                                " matched the '" + keyword + "' protocol signature and the connection carried no TLS protection.",
                        remediation: new RemediationGuidance(
                            "Replace the cleartext protocol with a TLS-protected equivalent or isolate it from untrusted networks.",
                            [
                                "Enable the protocol's native TLS mode or wrap it behind an authenticated tunnel.",
                                "Restrict plaintext access to trusted management networks.",
                                "Verify that operational clients connect with TLS enforced."
                            ],
                            ["RFC 9325"]),
                        fingerprintComponents: new FingerprintComponents(
                            s_metadata.Id, host, "port:" + port.ToString(System.Globalization.CultureInfo.InvariantCulture), "cleartext-protocol-banner"),
                        assetReference: context.Asset.CanonicalTarget);
                    findings.Add(finding);
                    evidence.Add(context.Assessment.Evidence.Create(
                        finding.FindingId,
                        EvidenceKind.NetworkObservation,
                        "service_banner_redacted",
                        banner!,
                        s_metadata.Id,
                        correlation));
                }
            }
        }

        return new SecurityCheckResult(
            s_metadata.Id,
            CheckExecutionStatus.Completed,
            started,
            DateTimeOffset.UtcNow,
            findings,
            evidence,
            FailureSummarySafe: null,
            requests,
            examined);
    }

    private static bool IsSupportedAsset(AssetKind kind) =>
        kind is AssetKind.Host or AssetKind.Container or AssetKind.TestEnvironment;

    private static ProtocolKind ProtocolFor(int port) => port switch
    {
        443 => ProtocolKind.Https,
        80 => ProtocolKind.Http,
        _ => ProtocolKind.Tcp
    };

    private static bool IsWebPort(int port) => port is 80 or 443;

    private static bool TryMatchCleartext(string? sanitizedBanner, out string keyword)
    {
        if (sanitizedBanner is not null)
        {
            foreach (var candidate in CleartextKeywords)
            {
                if (sanitizedBanner.Contains(candidate, StringComparison.OrdinalIgnoreCase))
                {
                    keyword = candidate;
                    return true;
                }
            }
        }
        keyword = string.Empty;
        return false;
    }

    /// <summary>Strips control characters, trims, and bounds the banner to a safe length.</summary>
    private static string? SanitizeBanner(string? raw)
    {
        if (string.IsNullOrEmpty(raw))
        {
            return null;
        }

        var builder = new System.Text.StringBuilder(raw.Length);
        foreach (var character in raw)
        {
            if (!char.IsControl(character))
            {
                builder.Append(character);
            }
        }
        var sanitized = builder.ToString().Trim();
        if (sanitized.Length == 0)
        {
            return null;
        }
        return sanitized.Length <= MaxBannerLength ? sanitized : sanitized[..MaxBannerLength];
    }

    /// <summary>Reduces the canonical target to a safe host identifier; unusable values fail closed.</summary>
    private static string HostOf(string canonicalTarget)
    {
        var trimmed = canonicalTarget.Trim();
        if (Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) && uri.Scheme is "http" or "https")
        {
            trimmed = uri.Host;
        }
        var host = HostNormalizer.NormalizeHost(trimmed);
        if (host.Length == 0 || host.AsSpan().IndexOfAny([' ', '\t', '\r', '\n', '\0', '/', '\\']) >= 0)
        {
            throw ActException.FailClosed(
                ErrorCategory.Configuration,
                "The assessed asset does not carry a usable host identifier.",
                $"CanonicalTarget '{canonicalTarget}' did not reduce to a safe host.");
        }
        return host;
    }
}
