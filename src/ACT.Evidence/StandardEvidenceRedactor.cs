using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using ACT.Contracts;

namespace ACT.Evidence;

/// <summary>
/// Deterministic redactor implementing <see cref="RedactionPolicy"/>. Recognized secrets are
/// replaced by "[REDACTED:sha256:&lt;12 hex&gt;]" fingerprints computed from the original value,
/// so the same secret always yields the same stable fingerprint and nothing reversible remains.
/// The Authorization header line is replaced wholesale by "REDACTED(len=&lt;N&gt;)". Strict mode
/// redacts every header line except a fixed operational allowlist. Value-level patterns (JWTs,
/// bearer tokens, AWS access keys, secret-named query/body parameters, PEM private keys, long
/// keyword-named assignments) are redacted in every mode.
/// </summary>
public sealed class StandardEvidenceRedactor : IEvidenceRedactor
{
    private static readonly Regex HeaderLinePattern = new(
        @"^(?<name>[!#$%&'*+\-.^_`|~0-9A-Za-z]+)[ \t]*:[ \t]?(?<value>.*)$",
        RegexOptions.Multiline | RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex PemPrivateKeyBlock = new(
        @"-----BEGIN [A-Z ]*PRIVATE KEY-----(?s:.)*?-----END [A-Z ]*PRIVATE KEY-----",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex JsonWebToken = new(
        @"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex AwsAccessKeyId = new(
        @"\bAKIA[A-Z0-9]{16}\b",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex BearerCredential = new(
        @"(?<=\bbearer[ \t])[A-Za-z0-9\-._~+/]{10,}={0,2}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex NamedSecretParameter = new(
        @"(?<![\w.+])(?<name>access[_-]?token|refresh[_-]?token|session[_-]?token|csrf[_-]?token|auth[_-]?token|id[_-]?token|api[_-]?key|client[_-]?secret|private[_-]?key|password|passwd|secret|token|pwd)\s*[""']?\s*=\s*(?<quote>[""']?)(?<value>[^\s&;""'<>[\]]+)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex GenericAssignedSecret = new(
        @"(?<prefix>\b[A-Za-z0-9_.\-]*(?:key|token|secret|password)[A-Za-z0-9_.\-]*\b\s*[""']?\s*[:=]\s*[""']?)(?<value>[^\s&;""':[\]]{32,})",
        RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private const string MarkerPrefix = "[REDACTED:sha256:";

    private const string LengthMarkerPrefix = "REDACTED(len=";

    // Fixed strict-mode allowlist of operational headers that never carry credentials.
    private static readonly HashSet<string> StrictHeaderAllowlist = new(StringComparer.Ordinal)
    {
        "host",
        "content-type",
        "content-length",
        "date",
        "server",
        "user-agent",
        "location",
        "cache-control",
        "expires",
        "pragma",
        "x-request-id"
    };

    /// <summary>Gets the effective policy mode.</summary>
    public RedactionPolicy Policy { get; }

    /// <summary>Creates the redactor for the given policy mode.</summary>
    public StandardEvidenceRedactor(RedactionPolicy policy) => Policy = policy;

    /// <inheritdoc />
    public bool IsSensitiveHeader(string headerName)
    {
        var normalized = headerName.Trim().ToLowerInvariant();
        return normalized is "authorization" or "proxy-authorization" or "cookie" or "set-cookie"
            || normalized.Contains("api-key", StringComparison.Ordinal)
            || normalized.Contains("apikey", StringComparison.Ordinal);
    }

    /// <inheritdoc />
    public string Redact(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length == 0)
        {
            return value;
        }

        var text = RedactHeaderLines(value);
        text = PemPrivateKeyBlock.Replace(text, static match => Fingerprint(match.Value));
        text = JsonWebToken.Replace(text, static match => Fingerprint(match.Value));
        text = AwsAccessKeyId.Replace(text, static match => Fingerprint(match.Value));
        text = BearerCredential.Replace(text, static match => Fingerprint(match.Value));
        text = NamedSecretParameter.Replace(text, static match => SwapValueGroup(match));
        text = GenericAssignedSecret.Replace(text, static match => SwapValueGroup(match));
        return text;
    }

    /// <summary>
    /// Redacts one complete header value: authorization becomes REDACTED(len=N); any other
    /// sensitive header becomes a fingerprint of the full value; non-sensitive headers fall back
    /// to normal value-level redaction.
    /// </summary>
    public string RedactHeaderValue(string headerName, string value)
    {
        ArgumentNullException.ThrowIfNull(headerName);
        ArgumentNullException.ThrowIfNull(value);
        if (!IsSensitiveHeader(headerName))
        {
            return Redact(value);
        }

        if (IsAuthorization(headerName) || value.Length == 0)
        {
            return LengthMarkerPrefix + value.Length.ToString(CultureInfo.InvariantCulture) + ")";
        }

        return Fingerprint(value);
    }

    private string RedactHeaderLines(string value)
    {
        return HeaderLinePattern.Replace(value, match =>
        {
            var name = match.Groups["name"].Value;
            var headerValue = match.Groups["value"].Value;
            if (headerValue.Length == 0)
            {
                return match.Value;
            }

            var strictDeny = Policy == RedactionPolicy.Strict && !StrictHeaderAllowlist.Contains(name.ToLowerInvariant());
            if (!strictDeny && !IsSensitiveHeader(name))
            {
                return match.Value;
            }

            return name + ": " + WholeHeaderReplacement(name, headerValue);
        });
    }

    private string WholeHeaderReplacement(string name, string headerValue) =>
        IsAuthorization(name)
            ? LengthMarkerPrefix + headerValue.Length.ToString(CultureInfo.InvariantCulture) + ")"
            : Fingerprint(headerValue);

    private static bool IsAuthorization(string name) =>
        name.Trim().Equals("authorization", StringComparison.OrdinalIgnoreCase)
        || name.Trim().Equals("proxy-authorization", StringComparison.OrdinalIgnoreCase);

    private static string SwapValueGroup(Match match)
    {
        var valueGroup = match.Groups["value"];
        var text = match.Value;
        var index = valueGroup.Index - match.Index;
        return string.Concat(
            text[..index],
            Fingerprint(valueGroup.Value),
            text[(index + valueGroup.Length)..]);
    }

    private static string Fingerprint(string secret)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(secret));
        return MarkerPrefix + Convert.ToHexString(hash, 0, 6).ToLowerInvariant() + "]";
    }
}
