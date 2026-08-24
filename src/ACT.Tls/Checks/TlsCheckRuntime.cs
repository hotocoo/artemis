using ACT.Contracts;
using ACT.Scope;

namespace ACT.Tls.Checks;

/// <summary>Shared, internal plumbing for the TLS checks: endpoint resolution and result shaping.</summary>
internal static class TlsCheckRuntime
{
    /// <summary>Upper bound on handshakes a TLS check spends per target (1 natural + up to 4 version probes).</summary>
    internal const int MaxHandshakesPerTarget = 5;

    /// <summary>Handshakes spent by one forced-version capability sweep of <see cref="TlsHandshakeProbe"/>.</summary>
    internal const int VersionProbeRequests = 4;

    /// <summary>Fingerprint resource prefix shared by every TLS finding.</summary>
    internal static string Resource(string host, int port) =>
        "tls-" + host + ":" + port.ToString(System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>True for asset kinds TLS checks are declared to support.</summary>
    internal static bool IsSupportedAsset(AssetKind kind) =>
        kind is AssetKind.Host or AssetKind.Container or AssetKind.TestEnvironment;

    /// <summary>Builds an honest not-applicable result carrying a safe note.</summary>
    internal static SecurityCheckResult Skip(SecurityCheckMetadata metadata, DateTimeOffset started, string safeNote) =>
        SecurityCheckResult.Empty(metadata, started, CheckExecutionStatus.Skipped_NotApplicable, safeNote);

    /// <summary>Builds a completed-with-warnings result when observation was impossible.</summary>
    internal static SecurityCheckResult Warn(SecurityCheckMetadata metadata, DateTimeOffset started,
        string safeNote, long requests) =>
        new(metadata.Id, CheckExecutionStatus.CompletedWithWarnings, started, DateTimeOffset.UtcNow,
            [], [], safeNote, requests, 0);

    /// <summary>
    /// Resolves the host and port to inspect from the check context. The service port wins,
    /// then the base URL port, then the HTTPS default. Unusable hosts fail closed.
    /// </summary>
    internal static (string Host, int Port) ResolveEndpoint(SecurityCheckContext context)
    {
        var host = HostOf(context.Asset.CanonicalTarget);
        var port = context.Service?.Port ?? PortFrom(context.BaseUrl);
        return (host, port);
    }

    private static int PortFrom(Uri? baseUrl)
    {
        if (baseUrl is null)
        {
            return 443;
        }
        if (!baseUrl.IsDefaultPort)
        {
            return baseUrl.Port;
        }
        return baseUrl.Scheme is "https" ? 443 : 80;
    }

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
