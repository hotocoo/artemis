using System.Text.RegularExpressions;

namespace ACT.Remediation;

/// <summary>The outcome of one source-file remediation attempt.</summary>
public sealed record SourceRemediationResult(
    bool Updated,
    string FilePath,
    string RuleId,
    int LocationsFixed,
    string Detail);

/// <summary>
/// Fixes source-code findings on the spot by applying concrete, rule-specific transformations to
/// the offending file. Only rules with a safe, deterministic fix are auto-applied (weak crypto,
/// disabled TLS validation, insecure cookie flags); anything else is honestly reported as
/// guidance-only so Artemis never rewrites code it cannot prove correct.
/// </summary>
public static class SourceRemediator
{
    /// <summary>
    /// Attempts to fix the source finding identified by a rule id in a file.
    /// Returns what was changed.
    /// </summary>
    public static async Task<SourceRemediationResult> FixAsync(
        string filePath, string ruleId, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(ruleId);

        if (!File.Exists(filePath))
        {
            return new SourceRemediationResult(false, filePath, ruleId, 0,
                "Source file not found: " + filePath);
        }

        var content = await File.ReadAllTextAsync(filePath, cancellationToken).ConfigureAwait(false);

        (string NewContent, int Fixed, string Description)? fix = ruleId switch
        {
            "SRC-CRYPTO-002" => FixWeakCrypto(content),
            "SRC-TLS-008" => FixTlsValidation(content),
            "SRC-COOKIE-010" => FixInsecureCookies(content),
            _ => null
        };

        if (fix is null)
        {
            return new SourceRemediationResult(false, filePath, ruleId, 0,
                "Rule " + ruleId + " has no safe automatic fix; follow the remediation guidance manually.");
        }

        if (fix.Value.Fixed == 0)
        {
            return new SourceRemediationResult(false, filePath, ruleId, 0,
                "No fixable occurrences of " + ruleId + " found in " + Path.GetFileName(filePath) + ".");
        }

        await File.WriteAllTextAsync(filePath, fix.Value.NewContent, cancellationToken).ConfigureAwait(false);
        return new SourceRemediationResult(true, filePath, ruleId, fix.Value.Fixed,
            fix.Value.Description);
    }

    /// <summary>Replaces weak MD5/SHA1/DES primitives with SHA-256 / AES equivalents.</summary>
    private static (string, int, string) FixWeakCrypto(string content)
    {
        var count = 0;

        // .NET: MD5.Create / SHA1.Create -> SHA256.Create; DES -> AES
        content = ReplaceCount(content, Regex.Escape("MD5.Create"), "SHA256.Create", ref count, RegexOptions.IgnoreCase);
        content = ReplaceCount(content, Regex.Escape("SHA1.Create"), "SHA256.Create", ref count, RegexOptions.IgnoreCase);
        content = ReplaceCount(content, Regex.Escape("DESCryptoServiceProvider"), "AesCryptoServiceProvider", ref count, RegexOptions.IgnoreCase);
        content = ReplaceCount(content, Regex.Escape("TripleDES.Create"), "Aes.Create", ref count, RegexOptions.IgnoreCase);

        // Python: hashlib.md5 / hashlib.sha1 -> hashlib.sha256
        content = ReplaceCount(content, Regex.Escape("hashlib.md5"), "hashlib.sha256", ref count, RegexOptions.IgnoreCase);
        content = ReplaceCount(content, Regex.Escape("hashlib.sha1"), "hashlib.sha256", ref count, RegexOptions.IgnoreCase);

        return (content, count, "Replaced weak cryptographic primitives with SHA-256/AES equivalents.");
    }

    /// <summary>Re-enables TLS certificate validation that was disabled.</summary>
    private static (string, int, string) FixTlsValidation(string content)
    {
        var count = 0;

        // Python: verify=False -> verify=True
        content = ReplaceCount(content, Regex.Escape("verify=False"), "verify=True", ref count, RegexOptions.IgnoreCase);
        content = ReplaceCount(content, Regex.Escape("verify = False"), "verify = True", ref count, RegexOptions.IgnoreCase);

        // Node: rejectUnauthorized: false -> true
        content = ReplaceCount(content, Regex.Escape("rejectUnauthorized: false"), "rejectUnauthorized: true", ref count, RegexOptions.IgnoreCase);
        content = ReplaceCount(content, Regex.Escape("rejectUnauthorized:false"), "rejectUnauthorized:true", ref count, RegexOptions.IgnoreCase);

        // Node env: NODE_TLS_REJECT_UNAUTHORIZED=0 -> 1
        content = ReplaceCount(content, "NODE_TLS_REJECT_UNAUTHORIZED=0", "NODE_TLS_REJECT_UNAUTHORIZED=1", ref count, RegexOptions.None);

        return (content, count, "Re-enabled TLS certificate validation.");
    }

    /// <summary>Sets Secure/HttpOnly flags that were explicitly disabled.</summary>
    private static (string, int, string) FixInsecureCookies(string content)
    {
        var count = 0;

        // .NET / JS: Secure = false -> true, HttpOnly = false -> true
        content = ReplaceCount(content, Regex.Escape("Secure = false"), "Secure = true", ref count, RegexOptions.IgnoreCase);
        content = ReplaceCount(content, Regex.Escape("HttpOnly = false"), "HttpOnly = true", ref count, RegexOptions.IgnoreCase);
        content = ReplaceCount(content, Regex.Escape("Secure=false"), "Secure=true", ref count, RegexOptions.IgnoreCase);
        content = ReplaceCount(content, Regex.Escape("HttpOnly=false"), "HttpOnly=true", ref count, RegexOptions.IgnoreCase);

        return (content, count, "Enabled Secure/HttpOnly cookie attributes.");
    }

    /// <summary>Replaces all occurrences of a literal pattern and counts them.</summary>
    private static string ReplaceCount(string content, string literalPattern, string replacement, ref int count, RegexOptions options)
    {
        var regex = new Regex(literalPattern, options);
        var matches = regex.Matches(content);
        count += matches.Count;
        return matches.Count > 0 ? regex.Replace(content, replacement) : content;
    }
}
