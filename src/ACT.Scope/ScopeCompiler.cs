
using ACT.Contracts;

namespace ACT.Scope;

/// <summary>Scope definition compiled into fast, unambiguous matchers. Compilation fails closed.</summary>
public sealed class CompiledScope
{
    public ScopeDefinition Definition { get; }
    public IReadOnlyList<TargetMatcher> AllowMatchers { get; }
    public IReadOnlyList<TargetMatcher> ExcludeMatchers { get; }
    public IReadOnlySet<ProtocolKind> Protocols { get; }
    public IReadOnlyList<PortRange> Ports { get; }
    public bool RequireResolvedAddressesInCidrs { get; }

    private static readonly PortRange[] LoopbackPorts = [new PortRange(1, 65535)];

    public CompiledScope(ScopeDefinition definition)
    {
        Definition = definition;
        Protocols = definition.PermittedProtocols.ToHashSet();
        Ports = definition.PermittedPorts;

        var allow = new List<TargetMatcher>();
        foreach (var entry in definition.AllowlistedTargets)
        {
            allow.AddRange(ParseEntry(entry, definition.TargetType));
        }

        // Repository/container scopes need no ports; everything else must declare at least one.
        if (definition.TargetType is not (TargetTypeKind.LocalSourceRepository or TargetTypeKind.LocalContainer))
        {
            if (Ports.Count == 0 && !Protocols.Contains(ProtocolKind.Tcp))
            {
                throw ActException.FailClosed(ErrorCategory.Scope,
                    "The scope permits no ports, so no network target could ever be contacted.",
                    $"Scope {definition.ScopeId}: empty PermittedPorts for network target type.");
            }
        }

        var exclude = new List<TargetMatcher>();
        foreach (var entry in definition.ExcludedTargets)
        {
            exclude.AddRange(ParseEntry(entry, definition.TargetType));
        }

        AllowMatchers = allow;
        ExcludeMatchers = exclude;
        RequireResolvedAddressesInCidrs =
            definition.TargetType is TargetTypeKind.PrivateIp or TargetTypeKind.PrivateSubnet or TargetTypeKind.Localhost;
    }

    /// <summary>Parses one raw entry into one or more concrete matchers; ambiguity is a hard failure.</summary>
    public static IReadOnlyList<TargetMatcher> ParseEntry(string raw, TargetTypeKind targetType)
    {
        var trimmed = raw.Trim().TrimEnd('.');
        if (trimmed.Length == 0)
        {
            throw ActException.FailClosed(ErrorCategory.Scope,
                "The scope configuration contains an empty target entry.",
                $"Empty allow/exclude entry in scope '{targetType}'.");
        }

        // URL form
        if (trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            if (!Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) || uri.Host.Length == 0)
            {
                throw ActException.FailClosed(ErrorCategory.Scope,
                    "A URL target in the scope configuration could not be parsed.",
                    $"Unparseable URL entry '{raw}'.");
            }
            return [new UrlPrefixMatcher(raw, uri)];
        }

        // CIDR / bare IP form
        if (trimmed.Contains('/') || IPAddressLike(trimmed))
        {
            if (!IpMath.TryParseCidr(trimmed, out var network, out _))
            {
                throw ActException.FailClosed(ErrorCategory.Scope,
                    "An IP target in the scope configuration could not be parsed.",
                    $"Unparseable IP/CIDR entry '{raw}'.");
            }
            if ((targetType is TargetTypeKind.PrivateIp or TargetTypeKind.PrivateSubnet or TargetTypeKind.Localhost)
                && !IpMath.IsNonPublic(network))
            {
                throw ActException.FailClosed(ErrorCategory.Scope,
                    "A private-target scope lists a public address; use an explicitly authorized hostname, domain, URL, or test-environment target instead.",
                    $"Entry '{raw}' is public but scope target type is {targetType}.");
            }
            return [new IpRangeMatcher(raw, [trimmed])];
        }

        // Filesystem form
        if (trimmed.StartsWith('/') || trimmed.StartsWith("~/") || trimmed.StartsWith("./") ||
            trimmed.Contains(Path.DirectorySeparatorChar) || trimmed.Contains(Path.AltDirectorySeparatorChar))
        {
            if (targetType != TargetTypeKind.LocalSourceRepository && targetType != TargetTypeKind.LocalContainer &&
                targetType != TargetTypeKind.TestEnvironment)
            {
                throw ActException.FailClosed(ErrorCategory.Scope,
                    "A filesystem path appeared in a scope whose target type is not a local repository, container, or test environment.",
                    $"Path entry '{raw}' incompatible with {targetType}.");
            }
            var expanded = trimmed.StartsWith("~/")
                ? Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) + trimmed[1..]
                : trimmed;
            return [new LocalRepositoryMatcher(raw, expanded)];
        }

        // Numeric-looking garbage that failed strict parsing must never become a hostname.
        var looksLikeAddress = trimmed.Contains(':') ||
            (trimmed.Split('.').Length == 4 && trimmed.Split('.').All(part =>
                part.Length > 0 && part.All(char.IsAsciiDigit)));
        if (looksLikeAddress)
        {
            throw ActException.FailClosed(ErrorCategory.Scope,
                "An IP target in the scope configuration could not be parsed.",
                $"Unparseable IP/CIDR entry '{raw}'.");
        }

        // Hostname forms
        var normalized = HostNormalizer.NormalizeHost(trimmed);
        if (normalized.Equals("localhost", StringComparison.Ordinal))
        {
            return [new ExactHostnameMatcher(raw, normalized), new IpRangeMatcher(raw, ["127.0.0.0/8", "::1"])];
        }

        if (normalized.Contains('.'))
        {
            return targetType == TargetTypeKind.Domain
                ? [new DomainSuffixMatcher(raw, normalized)]
                : [new ExactHostnameMatcher(raw, normalized)];
        }

        // Single-label names only make sense for explicitly configured test environments.
        if (targetType != TargetTypeKind.TestEnvironment)
        {
            throw ActException.FailClosed(ErrorCategory.Scope,
                $"Target entry '{raw}' is ambiguous: it is neither an IP, URL, path, nor fully-qualified hostname.",
                $"Ambiguous single-label entry '{raw}' for {targetType}; refusing to guess.");
        }
        return [new ExactHostnameMatcher(raw, normalized)];
    }

    private static bool IPAddressLike(string text)
    {
        var addressPart = text.Split('/')[0];
        if (!addressPart.Contains(':') && !addressPart.Contains('.')) return false;
        return System.Net.IPAddress.TryParse(addressPart, out _);
    }

    public bool IsProtocolPermitted(ProtocolKind protocol) => Protocols.Contains(protocol);

    public bool IsPortPermitted(int port) => Ports.Any(range => range.Contains(port));

    public bool MatchesAnyExclusion(TargetCandidate candidate) =>
        ExcludeMatchers.Any(matcher => matcher.Matches(candidate));

    public bool MatchesAnyAllow(TargetCandidate candidate, out string? matchedRaw)
    {
        foreach (var matcher in AllowMatchers)
        {
            if (matcher.Matches(candidate))
            {
                matchedRaw = matcher.RawEntry;
                return true;
            }
        }
        matchedRaw = null;
        return false;
    }
}
