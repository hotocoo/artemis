
using System.Net;
using System.Net.Sockets;
using ACT.Contracts;

namespace ACT.Scope;

/// <summary>Minimal DNS surface so the validator and the HTTP engine share one pinned view.</summary>
public interface IDnsResolver
{
    Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken);
}

/// <summary>Resolves once per host and caches for the lifetime of the instance (one assessment).</summary>
public sealed class PinningDnsResolver : IDnsResolver
{
    private readonly Dictionary<string, IReadOnlyList<IPAddress>> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _lock = new();

    public async Task<IReadOnlyList<IPAddress>> ResolveAsync(string host, CancellationToken cancellationToken)
    {
        lock (_lock)
        {
            if (_cache.TryGetValue(host, out var cached)) return cached;
        }

        var addresses = await Dns.GetHostAddressesAsync(host, cancellationToken);
        if (addresses.Length == 0)
        {
            throw ActException.FailClosed(ErrorCategory.Network,
                "The target host could not be resolved.",
                $"DNS returned zero addresses for '{host}'.");
        }

        lock (_lock)
        {
            _cache[host] = addresses;
        }
        return addresses;
    }
}

/// <summary>
/// Authorization gate used by the HTTP engine and the orchestrator. DNS resolution is never
/// treated as authorization: names authorize nothing by themselves, and for private-target
/// scopes every resolved address must land inside the configured networks.
/// </summary>
public sealed class ScopeValidator : IScopeValidator, IDnsGate
{
    private readonly CompiledScope _compiled;
    private readonly IDnsResolver _resolver;

    public ScopeValidator(CompiledScope compiled, IDnsResolver resolver)
    {
        _compiled = compiled;
        _resolver = resolver;
    }

    public ScopeDecision Evaluate(TargetCandidate candidate)
    {
        if (string.IsNullOrWhiteSpace(candidate.Host) ||
            candidate.Host.AsSpan().IndexOfAny([' ', '\t', '\r', '\n', '\0']) >= 0)
        {
            return ScopeDecision.Deny("MALFORMED_TARGET",
                "The target identifier is malformed.", $"Candidate host '{candidate.Host}' malformed.");
        }

        if (candidate.Port is < 1 or > 65535)
        {
            return ScopeDecision.Deny("PORT_OUT_OF_RANGE",
                "The target port is outside the valid range.", $"Port {candidate.Port} invalid.");
        }

        if (!_compiled.IsProtocolPermitted(candidate.Protocol))
        {
            return ScopeDecision.Deny("PROTOCOL_NOT_PERMITTED",
                "The protocol is not permitted by this assessment's scope.",
                $"Protocol {candidate.Protocol} rejected for '{candidate.Host}:{candidate.Port}'.");
        }

        if (!_compiled.IsPortPermitted(candidate.Port))
        {
            return ScopeDecision.Deny("PORT_NOT_PERMITTED",
                "The port is not within the permitted port set of this assessment's scope.",
                $"Port {candidate.Port} not in permitted ranges.");
        }

        if (_compiled.MatchesAnyExclusion(candidate))
        {
            return ScopeDecision.Deny("TARGET_EXCLUDED",
                "The target matches this assessment's exclusion list, which overrides the allowlist.",
                $"Excluded target '{candidate.Host}:{candidate.Port}'.");
        }

        if (_compiled.MatchesAnyAllow(candidate, out var matched))
        {
            return ScopeDecision.Allow(matched!, $"Allowed by entry '{matched}' for '{candidate.Host}:{candidate.Port}'.");
        }

        return ScopeDecision.Deny("NOT_ALLOWLISTED",
            "The target is not covered by any allowlist entry of this assessment.",
            $"No allowlist entry matched '{candidate.Host}:{candidate.Port}'.");
    }

    public ScopeDecision EvaluateRedirect(Uri originalUri, Uri redirectTarget)
    {
        if (redirectTarget.Scheme is not ("http" or "https"))
        {
            return ScopeDecision.Deny("REDIRECT_UNSUPPORTED_SCHEME",
                "A redirect pointed to an unsupported scheme and was not followed.",
                $"Redirect '{originalUri}' -> '{redirectTarget}' scheme '{redirectTarget.Scheme}'.");
        }

        if (string.Equals(originalUri.Scheme, "https", StringComparison.OrdinalIgnoreCase) &&
            string.Equals(redirectTarget.Scheme, "http", StringComparison.OrdinalIgnoreCase))
        {
            return ScopeDecision.Deny("REDIRECT_TLS_DOWNGRADE",
                "A redirect attempted to downgrade HTTPS to plaintext and was blocked.",
                $"Downgrade redirect '{originalUri}' -> '{redirectTarget}'.");
        }

        var verdict = Evaluate(TargetCandidate.FromUri(redirectTarget));
        if (verdict.Allowed) return verdict;

        return verdict.ReasonCode switch
        {
            "NOT_ALLOWLISTED" => ScopeDecision.Deny("REDIRECT_OUT_OF_SCOPE",
                "A redirect tried to leave the authorized scope and was blocked.", verdict.DiagnosticDetail),
            "PORT_NOT_PERMITTED" => ScopeDecision.Deny("REDIRECT_PORT_NOT_PERMITTED",
                "A redirect tried to move to a port outside the permitted set and was blocked.", verdict.DiagnosticDetail),
            "TARGET_EXCLUDED" => ScopeDecision.Deny("REDIRECT_TO_EXCLUDED",
                "A redirect pointed at an excluded target and was blocked.", verdict.DiagnosticDetail),
            _ => ScopeDecision.Deny("REDIRECT_DENIED",
                "A redirect was blocked by scope policy.", verdict.DiagnosticDetail)
        };
    }

    public async Task<ScopeDecision> EvaluateResolvedAsync(string host, int port, CancellationToken cancellationToken)
    {
        var nameVerdict = Evaluate(new TargetCandidate(host, port, ProtocolFor(port), null));

        // Exclusions apply to resolved addresses as well as to names.
        bool RequiresResolution() => !nameVerdict.Allowed || _compiled.RequireResolvedAddressesInCidrs;

        IReadOnlyList<IPAddress> addresses = [];
        if (RequiresResolution())
        {
            addresses = await ResolveOrThrowAsync(host, cancellationToken);

            foreach (var address in addresses)
            {
                var asCandidate = new TargetCandidate(address.ToString(), port, ProtocolFor(port), null);
                if (_compiled.MatchesAnyExclusion(asCandidate))
                {
                    return ScopeDecision.Deny("TARGET_EXCLUDED",
                        "The target resolves to an address on this assessment's exclusion list.",
                        $"'{host}' resolved to excluded '{address}'.");
                }
            }

            if (!nameVerdict.Allowed)
            {
                var matched = FirstAddressMatch(addresses);
                if (matched is null)
                {
                    return _compiled.RequireResolvedAddressesInCidrs
                        ? ScopeDecision.Deny("RESOLVED_ADDRESS_OUT_OF_SCOPE",
                            "A DNS name inside this private-target scope resolved to an address outside the configured networks.",
                            $"'{host}' resolved outside all configured CIDRs. Failing closed.")
                        : ScopeDecision.Deny("NOT_ALLOWLISTED",
                            "The target is not covered by any allowlist entry of this assessment.",
                            $"No allowlist entry matched '{host}' or its resolved addresses.");
                }
                nameVerdict = ScopeDecision.Allow(matched,
                    $"'{host}' authorized because every resolved address falls within entry '{matched}'.");
            }
            else if (_compiled.RequireResolvedAddressesInCidrs && FirstAddressMatch(addresses) is null)
            {
                return ScopeDecision.Deny("RESOLVED_ADDRESS_OUT_OF_SCOPE",
                    "A DNS name inside this private-target scope resolved to an address outside the configured networks.",
                    $"'{host}' resolved outside all configured CIDRs. Failing closed.");
            }
        }

        return nameVerdict;
    }

    /// <summary>Returns an allowlist raw entry covering EVERY resolved address, or null.</summary>
    private string? FirstAddressMatch(IReadOnlyList<IPAddress> addresses)
    {
        if (addresses.Count == 0) return null;
        foreach (var matcher in _compiled.AllowMatchers.OfType<IpRangeMatcher>())
        {
            var coversAll = addresses.All(address =>
                IPAddress.TryParse(address.ToString(), out var parsed) &&
                IpMath.Contains(matcher.NetworkOfFirst(), 0, parsed) is var _ &&
                matcher.MatchesHost(address.ToString()));
            if (coversAll) return matcher.RawEntry;
        }
        return null;
    }

    private async Task<IReadOnlyList<IPAddress>> ResolveOrThrowAsync(string host, CancellationToken cancellationToken)
    {
        try
        {
            var found = await _resolver.ResolveAsync(host, cancellationToken);
            if (found.Count == 0)
            {
                throw ActException.FailClosed(ErrorCategory.Network,
                    "The target host could not be resolved.",
                    $"DNS returned zero addresses for '{host}'.");
            }
            return found;
        }
        catch (ActException)
        {
            throw;
        }
        catch (SocketException ex)
        {
            throw ActException.FailClosed(ErrorCategory.Network,
                "The target host could not be resolved.",
                $"DNS failure for '{host}': {ex.SocketErrorCode}", ex);
        }
    }

    public async Task<IReadOnlyList<IPAddress>> ResolveVerifiedAsync(string host, CancellationToken cancellationToken)
    {
        var verdict = await EvaluateResolvedAsync(host, 80, cancellationToken);
        if (!verdict.Allowed)
        {
            throw ActException.FailClosed(ErrorCategory.Scope, verdict.SafeMessage, verdict.DiagnosticDetail);
        }
        return await _resolver.ResolveAsync(host, cancellationToken);
    }

    private static ProtocolKind ProtocolFor(int port) =>
        port switch
        {
            443 => ProtocolKind.Https,
            80 => ProtocolKind.Http,
            _ => ProtocolKind.Tcp
        };
}

/// <summary>Resolves and authorizes hosts before any socket connects; supplies pinned addresses.</summary>
public interface IDnsGate
{
    /// <summary>Throws ActException unless the host resolves entirely inside scope.</summary>
    Task<IReadOnlyList<IPAddress>> ResolveVerifiedAsync(string host, CancellationToken cancellationToken);
}
