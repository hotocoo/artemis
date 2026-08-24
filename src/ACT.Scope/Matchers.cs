
using System.Globalization;
using System.Net;
using ACT.Contracts;

namespace ACT.Scope;

/// <summary>Structured matcher compiled from one allowlist/exclusion entry. All matching is deterministic.</summary>
public abstract class TargetMatcher
{
    public string RawEntry { get; }

    protected TargetMatcher(string rawEntry) => RawEntry = rawEntry;

    /// <summary>Decides whether this matcher accepts the exact endpoint candidate.</summary>
    public abstract bool Matches(TargetCandidate candidate);

    /// <summary>Decides whether this matcher accepts a bare host string (no port context).</summary>
    public abstract bool MatchesHost(string normalizedHost);
}

/// <summary>Exact hostname equality after case-fold, trailing-dot strip, and IDN punycode normalization.</summary>
public sealed class ExactHostnameMatcher : TargetMatcher
{
    private readonly string _host;

    public ExactHostnameMatcher(string raw, string host) : base(raw) => _host = HostNormalizer.NormalizeHost(host);

    public override bool Matches(TargetCandidate candidate) => MatchesHost(candidate.Host);

    public override bool MatchesHost(string normalizedHost) =>
        string.Equals(_host, HostNormalizer.NormalizeHost(normalizedHost), StringComparison.Ordinal);
}

/// <summary>Matches the domain itself and any depth of subdomain beneath it.</summary>
public sealed class DomainSuffixMatcher : TargetMatcher
{
    private readonly string _domain;

    public DomainSuffixMatcher(string raw, string domain) : base(raw) => _domain = HostNormalizer.NormalizeHost(domain);

    public override bool Matches(TargetCandidate candidate) => MatchesHost(candidate.Host);

    public override bool MatchesHost(string normalizedHost)
    {
        var host = HostNormalizer.NormalizeHost(normalizedHost);
        return string.Equals(host, _domain, StringComparison.Ordinal)
               || host.EndsWith("." + _domain, StringComparison.Ordinal);
    }
}

/// <summary>Matches any address inside one or more CIDR networks. IPv4 and IPv6 both supported.</summary>
public sealed class IpRangeMatcher : TargetMatcher
{
    private readonly List<(IPAddress Network, int Prefix)> _networks = [];

    public IpRangeMatcher(string raw, IEnumerable<string> cidrs) : base(raw)
    {
        foreach (var cidr in cidrs)
        {
            if (!IpMath.TryParseCidr(cidr, out var network, out var prefix))
            {
                throw ActException.FailClosed(ErrorCategory.Scope,
                    "An IP range in the scope configuration could not be parsed.",
                    $"Unparseable CIDR '{cidr}' in entry '{raw}'.");
            }
            _networks.Add((network, prefix));
        }
    }

    public override bool Matches(TargetCandidate candidate) =>
        IPAddress.TryParse(HostNormalizer.StripBrackets(candidate.Host), out var ip) &&
        _networks.Any(n => IpMath.Contains(n.Network, n.Prefix, ip));

    public override bool MatchesHost(string normalizedHost) =>
        IPAddress.TryParse(HostNormalizer.StripBrackets(normalizedHost), out var ip) &&
        _networks.Any(n => IpMath.Contains(n.Network, n.Prefix, ip));

    internal System.Net.IPAddress NetworkOfFirst() => _networks[0].Network;
}

/// <summary>Matches URLs under a configured origin and optional path prefix (segment-aligned).</summary>
public sealed class UrlPrefixMatcher : TargetMatcher
{
    private readonly Uri _baseUri;

    public UrlPrefixMatcher(string raw, Uri baseUri) : base(raw)
    {
        if (baseUri.Scheme is not ("http" or "https"))
        {
            throw ActException.FailClosed(ErrorCategory.Scope,
                "A URL target in the scope configuration does not use HTTP or HTTPS.",
                $"URL entry '{raw}' had scheme '{baseUri.Scheme}'.");
        }
        _baseUri = baseUri;
    }

    public Uri Base => _baseUri;

    public override bool Matches(TargetCandidate candidate)
    {
        if (candidate.Url is null) return MatchesHost(candidate.Host);
        return MatchesUri(candidate.Url);
    }

    public bool MatchesUri(Uri uri)
    {
        if (!string.Equals(uri.Host, _baseUri.Host, StringComparison.OrdinalIgnoreCase)) return false;
        var thisPort = _baseUri.IsDefaultPort ? (_baseUri.Scheme == "https" ? 443 : 80) : _baseUri.Port;
        var otherPort = uri.IsDefaultPort ? (uri.Scheme == "https" ? 443 : 80) : uri.Port;
        if (thisPort != otherPort) return false;
        if (!uri.AbsolutePath.StartsWith(_baseUri.AbsolutePath, StringComparison.Ordinal)) return false;

        var basePath = _baseUri.AbsolutePath;
        if (basePath.Length > 1)
        {
            var rest = uri.AbsolutePath[basePath.Length..];
            if (rest.Length > 0 && rest[0] != '/') return false;
        }
        return true;
    }

    public override bool MatchesHost(string normalizedHost) =>
        string.Equals(_baseUri.Host, HostNormalizer.NormalizeHost(normalizedHost), StringComparison.Ordinal);
}

/// <summary>Local filesystem repository root; never a network matcher.</summary>
public sealed class LocalRepositoryMatcher : TargetMatcher
{
    public string RootPath { get; }

    public LocalRepositoryMatcher(string raw, string rootPath) : base(raw) =>
        RootPath = Path.GetFullPath(rootPath);

    public override bool Matches(TargetCandidate candidate) => false;

    public override bool MatchesHost(string normalizedHost) => false;

    /// <summary>True when path is inside the repository root; symlink escapes cannot pass this.</summary>
    public bool ContainsPath(string fullPath)
    {
        var rooted = Path.GetFullPath(fullPath);
        return rooted.StartsWith(RootPath + Path.DirectorySeparatorChar, StringComparison.Ordinal)
               || rooted.Equals(RootPath, StringComparison.Ordinal);
    }
}

/// <summary>Host-string normalization shared by all matchers.</summary>
public static class HostNormalizer
{
    private static readonly IdnMapping Idn = new();

    public static string NormalizeHost(string host)
    {
        var trimmed = StripBrackets(host.Trim()).TrimEnd('.');
        if (trimmed.Length == 0) return trimmed;
        try
        {
            return Idn.GetAscii(trimmed).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            return trimmed.ToLowerInvariant();
        }
    }

    public static string StripBrackets(string host) =>
        host.StartsWith('[') && host.EndsWith(']') && host.Length >= 2 ? host[1..^1] : host;
}
