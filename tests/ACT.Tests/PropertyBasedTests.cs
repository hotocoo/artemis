
using System.Net;
using ACT.Scope;
using ACT.DependencyAnalysis;
using FsCheck;
using FsCheck.Xunit;
using Xunit;

namespace ACT.Tests;

/// <summary>
/// Property-based tests using FsCheck to verify invariants of core subsystems.
/// These tests generate thousands of random inputs and verify mathematical
/// and logical properties that must hold for all valid inputs.
/// </summary>
public class PropertyBasedTests
{
    // ===== IP/CIDR Properties =====

    /// <summary>
    /// Property: Any IPv4 address is contained in its own /32 network.
    /// </summary>
    [Property(MaxTest = 1000)]
    public bool CidrContainmentIsReflexive(byte a, byte b, byte c, byte d)
    {
        var ip = new IPAddress(new byte[] { a, b, c, d });
        return IpMath.Contains(ip, 32, ip);
    }

    /// <summary>
    /// Property: If an IP is in network/prefix, it's also in network/(prefix-1)
    /// (monotonicity of prefix relaxation).
    /// </summary>
    [Property(MaxTest = 1000)]
    public bool PrefixRelaxationIsMonotonic(byte a, byte b, byte c, byte d, byte prefix)
    {
        var ip = new IPAddress(new byte[] { a, b, c, d });
        var p = (int)(prefix % 31) + 1; // 1 to 31
        var network = IpMath.Canonical(ip);

        // If in /prefix, must also be in /(prefix-1)
        if (IpMath.Contains(network, p, ip))
        {
            return IpMath.Contains(network, p - 1, ip);
        }
        return true;
    }

    /// <summary>
    /// Property: Canonical form is idempotent.
    /// </summary>
    [Property(MaxTest = 1000)]
    public bool CanonicalFormIsIdempotent(byte a, byte b, byte c, byte d)
    {
        var ip = new IPAddress(new byte[] { a, b, c, d });
        var once = IpMath.Canonical(ip);
        var twice = IpMath.Canonical(once);
        return once.Equals(twice);
    }

    /// <summary>
    /// Property: IPv4-mapped IPv6 addresses canonicalize to the same IPv4 address.
    /// </summary>
    [Property(MaxTest = 500)]
    public bool MappedIpv6CanonicalizesCorrectly(byte a, byte b, byte c, byte d)
    {
        var ip = new IPAddress(new byte[] { a, b, c, d });
        var mapped = ip.MapToIPv6();
        return IpMath.Canonical(mapped).Equals(ip);
    }

    /// <summary>
    /// Property: All loopback addresses are non-public.
    /// </summary>
    [Property(MaxTest = 100)]
    public bool LoopbackIsAlwaysNonPublic()
    {
        return IpMath.IsNonPublic(IPAddress.Loopback);
    }

    /// <summary>
    /// Property: RFC1918 10.x.x.x addresses are non-public.
    /// </summary>
    [Property(MaxTest = 500)]
    public bool Rfc1918_10_IsNonPublic(byte b, byte c, byte d)
    {
        var ip = new IPAddress(new byte[] { 10, b, c, d });
        return IpMath.IsNonPublic(ip);
    }

    /// <summary>
    /// Property: RFC1918 172.16-31.x.x addresses are non-public.
    /// </summary>
    [Property(MaxTest = 500)]
    public bool Rfc1918_172_IsNonPublic(byte b, byte c, byte d)
    {
        var secondOctet = (byte)(16 + (b % 16)); // 16-31
        var ip = new IPAddress(new byte[] { 172, secondOctet, c, d });
        return IpMath.IsNonPublic(ip);
    }

    /// <summary>
    /// Property: RFC1918 192.168.x.x addresses are non-public.
    /// </summary>
    [Property(MaxTest = 500)]
    public bool Rfc1918_192_IsNonPublic(byte c, byte d)
    {
        var ip = new IPAddress(new byte[] { 192, 168, c, d });
        return IpMath.IsNonPublic(ip);
    }

    // ===== CIDR Parse Properties =====

    /// <summary>
    /// Property: Parsing a valid CIDR and re-formatting gives back the same network.
    /// </summary>
    [Property(MaxTest = 500)]
    public bool CidrParseIsConsistent(byte a, byte b, byte c, byte d, byte prefixByte)
    {
        var ip = new IPAddress(new byte[] { a, b, c, d });
        var prefix = (int)(prefixByte % 33); // 0 to 32
        var cidr = $"{ip}/{prefix}";

        if (!IpMath.TryParseCidr(cidr, out var network, out var prefixLength))
            return false;

        return prefixLength == prefix && network.Equals(IpMath.Canonical(ip));
    }

    /// <summary>
    /// Property: A bare IP address parses as a /32 network.
    /// </summary>
    [Property(MaxTest = 500)]
    public bool BareIpParsesAsFullPrefix(byte a, byte b, byte c, byte d)
    {
        var ip = new IPAddress(new byte[] { a, b, c, d });
        if (!IpMath.TryParseCidr(ip.ToString(), out var network, out var prefixLength))
            return false;

        return prefixLength == 32 && network.Equals(ip);
    }

    // ===== Version Range Properties =====

    /// <summary>
    /// Property: Version range parsing and matching is reflexive for exact versions.
    /// </summary>
    [Property(MaxTest = 500)]
    public bool VersionRangeMatchesExactVersion(byte major, byte minor, byte patch)
    {
        var version = $"{major}.{minor}.{patch}";
        var range = RangeSpec.Parse($"={version}");
        return range.Satisfied(version);
    }

    /// <summary>
    /// Property: Wildcard range matches any version.
    /// </summary>
    [Property(MaxTest = 500)]
    public bool WildcardRangeMatchesAll(byte major, byte minor, byte patch)
    {
        var version = $"{major}.{minor}.{patch}";
        var range = RangeSpec.Parse("*");
        return range.Satisfied(version);
    }

    /// <summary>
    /// Property: >= range matches versions at or above the bound.
    /// </summary>
    [Property(MaxTest = 500)]
    public bool GreaterEqualRangeMatches(byte major, byte minor, byte patch)
    {
        var version = $"{major}.{minor}.{patch}";
        var range = RangeSpec.Parse($">={version}");
        return range.Satisfied(version);
    }

    /// <summary>
    /// Property: <= range matches versions at or below the bound.
    /// </summary>
    [Property(MaxTest = 500)]
    public bool LessEqualRangeMatches(byte major, byte minor, byte patch)
    {
        var version = $"{major}.{minor}.{patch}";
        var range = RangeSpec.Parse($"<={version}");
        return range.Satisfied(version);
    }

    // ===== Semantic Version Parsing Properties =====

    /// <summary>
    /// Property: Parsing a version and converting back to string is consistent.
    /// </summary>
    [Property(MaxTest = 1000)]
    public bool VersionParseToStringIsConsistent(byte major, byte minor, byte patch)
    {
        var version = $"{major}.{minor}.{patch}";
        if (!SemanticVersion.TryParse(version, out var parsed))
            return false;
        return parsed.ToString() == version;
    }

    /// <summary>
    /// Property: Version comparison is antisymmetric.
    /// </summary>
    [Property(MaxTest = 500)]
    public bool VersionComparisonIsAntisymmetric(byte a, byte b, byte c, byte d, byte e, byte f)
    {
        var v1 = new SemanticVersion(a, b, c);
        var v2 = new SemanticVersion(d, e, f);

        if (v1.CompareTo(v2) == 0) return true;
        if (v1.CompareTo(v2) < 0) return v2.CompareTo(v1) > 0;
        return v1.CompareTo(v2) > 0;
    }

    /// <summary>
    /// Property: Version comparison is transitive.
    /// </summary>
    [Property(MaxTest = 500)]
    public bool VersionComparisonIsTransitive(byte a, byte b, byte c, byte d, byte e, byte f, byte g, byte h, byte i)
    {
        var v1 = new SemanticVersion(a, b, c);
        var v2 = new SemanticVersion(d, e, f);
        var v3 = new SemanticVersion(g, h, i);

        if (v1.CompareTo(v2) < 0 && v2.CompareTo(v3) < 0) return v1.CompareTo(v3) < 0;
        return true;
    }
}
