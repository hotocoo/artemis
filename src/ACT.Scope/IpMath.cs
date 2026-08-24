
using System.Net;
using System.Net.Sockets;

namespace ACT.Scope;

/// <summary>
/// Correct, allocation-conscious IP/CIDR arithmetic for IPv4 and IPv6, including
/// IPv4-mapped IPv6 forms. Used by every authorization decision.
/// </summary>
public static class IpMath
{
    /// <summary>Normalizes any IP form (including ::ffff:a.b.c.d) into a 16-byte big-endian buffer.</summary>
    public static byte[] ToNormalizedBytes(IPAddress address)
    {
        var normalized = address.AddressFamily == AddressFamily.InterNetwork || address.IsIPv4MappedToIPv6
            ? address.MapToIPv6()
            : address;
        return normalized.GetAddressBytes();
    }

    /// <summary>Parses "a.b.c.d/nn", "ip", and IPv6 equivalents. Bare IPs get their full prefix.</summary>
    public static bool TryParseCidr(string text, out IPAddress network, out int prefixLength)
    {
        network = IPAddress.None;
        prefixLength = 0;
        if (string.IsNullOrWhiteSpace(text)) return false;

        var slash = text.IndexOf('/');
        var addressPart = slash < 0 ? text : text[..slash];
        var prefixPart = slash < 0 ? null : text[(slash + 1)..];

        if (!StrictlyValidIp(addressPart) || !IPAddress.TryParse(addressPart, out var parsed)) return false;

        var familyBits = parsed.AddressFamily == AddressFamily.InterNetworkV6 && !parsed.IsIPv4MappedToIPv6 ? 128 : 32;

        if (prefixPart is null)
        {
            network = Canonical(parsed);
            prefixLength = familyBits;
            return true;
        }

        if (!int.TryParse(prefixPart, out var requested) || requested < 0 || requested > familyBits) return false;
        network = Canonical(parsed);
        prefixLength = requested;
        return true;
    }

    /// <summary>
    /// Rejects inputs that System.Net.IPAddress.TryParse would wrongly accept, such as
    /// "999.999.1.1" (out-of-range quads) or strings with embedded whitespace/signs.
    /// </summary>
    internal static bool StrictlyValidIp(string text)
    {
        if (text.Length == 0 || text.Any(char.IsWhiteSpace)) return false;
        if (text.Contains(':')) return Uri.CheckHostName(text.Trim('[', ']')) == UriHostNameType.IPv6;

        var parts = text.Split('.');
        if (parts.Length != 4) return false;
        foreach (var part in parts)
        {
            if (part.Length is 0 or > 3 || part.Any(c => !char.IsAsciiDigit(c))) return false;
            // No leading zeros like 010 (ambiguous legacy octal form).
            if (part.Length > 1 && part[0] == '0') return false;
            if (int.Parse(part, System.Globalization.CultureInfo.InvariantCulture) > 255) return false;
        }
        return true;
    }

    /// <summary>Collapses IPv4-mapped forms onto plain IPv4 so masks operate in the native family width.</summary>
    public static IPAddress Canonical(IPAddress address) =>
        address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;

    /// <summary>
    /// True when candidate falls inside network/prefix. Both sides are reduced to their native
    /// family (IPv4 stays 32-bit), so IPv4-mapped forms can never smuggle a mismatch past the mask.
    /// </summary>
    public static bool Contains(IPAddress network, int prefixLength, IPAddress candidate)
    {
        var n = Canonical(network);
        var c = Canonical(candidate);
        if (n.AddressFamily != c.AddressFamily) return false;

        var networkBytes = n.GetAddressBytes();
        var candidateBytes = c.GetAddressBytes();
        var familyBits = networkBytes.Length * 8;
        if (prefixLength < 0 || prefixLength > familyBits) return false;

        var wholeBytes = prefixLength / 8;
        var remainingBits = prefixLength % 8;

        for (var i = 0; i < wholeBytes; i++)
        {
            if (networkBytes[i] != candidateBytes[i]) return false;
        }

        if (remainingBits == 0) return true;

        var mask = (byte)(0xFF << (8 - remainingBits));
        return (networkBytes[wholeBytes] & mask) == (candidateBytes[wholeBytes] & mask);
    }

    /// <summary>True for addresses that are meaningless on the public Internet: loopback, RFC1918, ULA, link-local.</summary>
    public static bool IsNonPublic(IPAddress address)
    {
        var v4 = address.AddressFamily == AddressFamily.InterNetwork ? address
            : address.IsIPv4MappedToIPv6 ? address.MapToIPv4()
            : null;

        if (v4 is not null)
        {
            if (IPAddress.IsLoopback(v4)) return true;
            var b = v4.GetAddressBytes();
            if (b[0] == 10) return true;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
            if (b[0] == 192 && b[1] == 168) return true;
            if (b[0] == 169 && b[1] == 254) return true;
            if (b[0] == 127) return true;
            return false;
        }

        if (IPAddress.IsLoopback(address)) return true;
        if (address.IsIPv6LinkLocal || address.IsIPv6SiteLocal) return true;
        var bytes = address.GetAddressBytes();
        if (bytes.Length >= 2 && (bytes[0] & 0xFE) == 0xFC) return true; // fc00::/7 unique local
        return false;
    }
}
