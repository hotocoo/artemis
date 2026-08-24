using System.Security.Cryptography;
using System.Text;

namespace ACT.Lab;

/// <summary>Minting and comparison helpers for the lab's administrative token.</summary>
public static class LabTokens
{
    /// <summary>Mints a fresh random hexadecimal lab token carrying 192 bits of entropy.</summary>
    public static string NewToken() => Convert.ToHexString(RandomNumberGenerator.GetBytes(24)).ToLowerInvariant();

    /// <summary>Compares a presented token against the expected token in constant time.</summary>
    public static bool Matches(string presented, string expected) =>
        CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(presented), Encoding.UTF8.GetBytes(expected));
}
