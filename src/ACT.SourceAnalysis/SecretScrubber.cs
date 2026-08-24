using System.Security.Cryptography;
using System.Text;

namespace ACT.SourceAnalysis;

/// <summary>Replaces matched secret values with stable, non-reversible fingerprints for evidence snippets.</summary>
internal static class SecretScrubber
{
    /// <summary>Renders a secret as "type:12-hex sha256 prefix"; the original value is never persisted.</summary>
    public static string Fingerprint(string secretType, string secretValue)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(secretValue));
        return secretType + ":" + Convert.ToHexString(digest).ToLowerInvariant().AsSpan(0, 12).ToString();
    }
}

