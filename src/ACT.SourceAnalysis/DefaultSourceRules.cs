
using System.Text.RegularExpressions;
using ACT.Contracts;

namespace ACT.SourceAnalysis;

/// <summary>One declarative static-analysis rule evaluated against repository source files.</summary>
public sealed record SourceRule(
    string RuleId,
    string Title,
    string WhyItMatters,
    RemediationGuidance Remediation,
    string FindingClass,
    Severity Severity,
    ConfidenceLevel Confidence,
    bool ExploitabilityIndicator,
    IReadOnlySet<SourceLanguage>? Languages,
    Regex Pattern,
    int MaxMatchesPerFile,
    bool RedactMatches,
    Func<string, bool>? MatchValidator = null);

/// <summary>The built-in Artemis source rule set: low-false-positive, timeout-guarded patterns.</summary>
public static class DefaultSourceRules
{
    /// <summary>Hard per-match regex evaluation budget applied to every built-in rule (ReDoS defense).</summary>
    public static readonly TimeSpan RuleMatchTimeout = TimeSpan.FromMilliseconds(100);

    /// <summary>Default cap on reported matches per rule per file.</summary>
    public const int DefaultMaxMatchesPerFile = 5;

    /// <summary>The complete built-in rule set, in stable reporting order.</summary>
    public static IReadOnlyList<SourceRule> All { get; } =
    [
        Secret(),
        WeakCrypto(),
        SqlInjection(),
        CommandInjection(),
        PathTraversalGuard(),
        ServerSideRequestForgery(),
        SensitiveDataLogging(),
        TlsValidationDisabled(),
        PermissiveCors(),
        InsecureCookie(),
        UnsafeDeserialization(),
        InsecureDefaults()
    ];

    private static Regex Rx(string pattern) =>
        new(
            pattern,
            RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnorePatternWhitespace,
            RuleMatchTimeout);

    private static SourceRule New(
        string id,
        string title,
        string whyItMatters,
        string remediationSummary,
        string findingClass,
        Severity severity,
        ConfidenceLevel confidence,
        bool exploitability,
        IReadOnlySet<SourceLanguage>? languages,
        Regex pattern,
        bool redactMatches = false,
        Func<string, bool>? validator = null) => new(
            id, title, whyItMatters,
            new RemediationGuidance(remediationSummary, [remediationSummary], []),
            findingClass, severity, confidence, exploitability, languages,
            pattern, DefaultMaxMatchesPerFile, redactMatches, validator);

    /// <summary>SRC-SECRET-001: credential material committed to source.</summary>
    private static SourceRule Secret() => New(
        "SRC-SECRET-001",
        "Hard-coded secret in repository file",
        "Credentials committed to version control allow anyone with repository access to authenticate as the service and are frequently harvested by automated scanners within minutes of being pushed.",
        "Revoke and rotate the exposed credential immediately, move it into a managed secret store or environment injection mechanism, and purge the value from history.",
        "HardcodedSecret",
        Severity.High,
        ConfidenceLevel.Medium,
        exploitability: true,
        languages: null,
        Rx(@"(?-i:\bAKIA[0-9A-Z]{16}\b)
|(?-i:\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b)
|\bgithub_pat_[A-Za-z0-9_]{22,255}\b
|\bxox[bapro]-[A-Za-z0-9-]{10,127}\b
|(?i:-----BEGIN(?:\s[A-Z]+)*\sPRIVATE\sKEY(?:\sBLOCK)?-----)
|(?i:(?<![A-Za-z])(?:password|passwd|pwd|secret|api[_\-]?key|apikey|access[_\-]?key|auth[_\-]?token|client[_\-]?secret)[""']?\s*[:=]\s*[""'])(?<secret>[A-Za-z0-9_/+=.!@#$%^&*~?-]{16,200})[""']
|(?i:(?<![A-Za-z])(?:password|passwd|secret|api[_\-]?key|token)\s*[:=]\s*)(?![""'])(?<secret>[A-Za-z0-9_/+=.!@#$%^&*~?-]{16,200})"),
        redactMatches: true,
        validator: LooksLikeRealCredential);

    /// <summary>SRC-CRYPTO-002: broken or legacy cryptographic primitives used for security purposes.</summary>
    private static SourceRule WeakCrypto() => New(
        "SRC-CRYPTO-002",
        "Weak cryptographic primitive in security-relevant use",
        "DES, TripleDES, MD5, and SHA1 no longer provide adequate security margins; their use for passwords, signatures, or confidentiality exposes data to practical attacks.",
        "Replace with modern primitives: AES-GCM for encryption and SHA-256 or better for hashing; use a password-specific KDF such as PBKDF2, bcrypt, scrypt, or Argon2 for credentials.",
        "WeakCryptographicPrimitive",
        Severity.Medium,
        ConfidenceLevel.Medium,
        exploitability: false,
        languages: Lang(SourceLanguage.Cs, SourceLanguage.Py, SourceLanguage.Rust),
        Rx(@"(?i:\bnew\s+(?:TripleDES|DES)(?:CryptoServiceProvider|Managed|Cng)?\s*\()
|(?i:\b(?:MD5|SHA1)(?:CryptoServiceProvider|Managed|Cng)?\.Create\s*\()
|(?i:\bHashAlgorithmName\.(?:MD5|SHA1)\b)
|(?i:\bhashlib\.(?:md5|sha1)\s*\()
|(?-i:\b(?:Md5|Sha1)::new\b)
|(?i:\buse\s+(?:md5|sha1)::)"));

    /// <summary>SRC-INJECT-SQL-003: SQL execution fed by concatenated or interpolated strings.</summary>
    private static SourceRule SqlInjection() => New(
        "SRC-INJECT-SQL-003",
        "SQL query assembled through string concatenation or interpolation",
        "Queries built from untrusted text allow attackers to change query semantics, read arbitrary data, or modify the database.",
        "Use parameterized queries or an ORM query API everywhere; pass user input exclusively as bound parameters, never as query text.",
        "SqlInjectionSink",
        Severity.High,
        ConfidenceLevel.High,
        exploitability: true,
        languages: Lang(SourceLanguage.Cs, SourceLanguage.Js, SourceLanguage.Py),
        Rx(@"(?i:\bExecute(?:Reader|NonQuery|Scalar|XmlReader)\s*\(\s*\$\{
|(?i:\bExecute(?:Reader|NonQuery|Scalar|XmlReader)\s*\([^()\n]*[""]\s*\+
|(?i:\bFromSqlRaw\s*\(\s*\$\{
|(?i:\.execute\s*\(\s*f['""]
|(?i:\.execute\s*\(\s*['""][^'\n]*['""]\s*[%+]
|(?i:\.(?:query|execute)\s*\(\s*`[^`\n]*\$\{"));

    /// <summary>SRC-INJECT-CMD-004: operating-system command execution fed by interpolated input.</summary>
    private static SourceRule CommandInjection() => New(
        "SRC-INJECT-CMD-004",
        "Operating-system command built from interpolated input",
        "Commands assembled from request-controlled text let an attacker run arbitrary statements on the host with the privileges of the application process.",
        "Invoke fixed executables with argument arrays and never route untrusted text through a shell interpreter; validate any dynamic argument against a strict allowlist.",
        "CommandInjectionSink",
        Severity.Critical,
        ConfidenceLevel.Medium,
        exploitability: true,
        languages: Lang(SourceLanguage.Cs, SourceLanguage.Py, SourceLanguage.Js, SourceLanguage.Rust),
        Rx(@"(?i:\bProcess\.Start\s*\(\s*(?:new\s+ProcessStartInfo\s*\(\s*)?\$\{
|(?i:\bProcessStartInfo\s*\(\s*@?\s*[""](?:cmd|powershell|pwsh|bash|sh)\b)
|(?i:\bos\.system\s*\()
|(?i:\bsubprocess\.\w+\s*\([^()\n]*shell\s*=\s*True\b)
|(?i:\bexec(?:Sync)?\s*\(\s*`[^`\n]*\$\{)
|(?-i:\.arg(?:s)?\s*\(\s*&?\[?&?format!\s*\()"));

    /// <summary>SRC-PATH-TRAV-005: file paths composed from request-derived values.</summary>
    private static SourceRule PathTraversalGuard() => New(
        "SRC-PATH-TRAV-005",
        "File path composed from request-derived value without traversal defense",
        "Paths that join request-controlled segments, or that strip leading separators before joining, can be steered outside the intended directory and disclose or overwrite arbitrary files.",
        "Resolve the final path and verify it remains inside an allowlisted base directory; reject absolute segments and parent-directory components instead of trimming separators.",
        "UnsafePathComposition",
        Severity.Medium,
        ConfidenceLevel.Low,
        exploitability: true,
        languages: Lang(SourceLanguage.Cs),
        Rx(@"(?i:\bPath\.Combine\s*\([^()\n]*(?:request|query|param|input|user|upload|client|form|header))
|(?i:\.TrimStart\s*\(\s*(?:'[//]'|""[//]""|Path\.(?:DirectorySeparatorChar|AltDirectorySeparatorChar))\s*\))"));

    /// <summary>SRC-SSRF-006: outbound HTTP requests whose URL is assembled at runtime.</summary>
    private static SourceRule ServerSideRequestForgery() => New(
        "SRC-SSRF-006",
        "Outbound request URL assembled from runtime-composed string",
        "When request parameters influence the target URL, attackers can make the server issue requests to internal services such as metadata endpoints or administrative interfaces.",
        "Validate destination hosts against a strict allowlist before requesting and never build URLs from raw request values without scheme and authority validation.",
        "RequestDrivenOutboundRequest",
        Severity.Medium,
        ConfidenceLevel.Medium,
        exploitability: true,
        languages: Lang(SourceLanguage.Cs, SourceLanguage.Py, SourceLanguage.Js),
        Rx(@"(?i:\b(?:GetAsync|GetStringAsync|GetByteArrayAsync|GetStreamAsync|GetFromJson\w*|PostAsync|PutAsync|PatchAsync|DownloadString\w*|DownloadData\w*|UploadString\w*)\s*\(\s*(?:\$\{|new\s+Uri\s*\(\s*\$\{))
|(?i:\brequests\.(?:get|post|put|patch|delete|head|request)\s*\(\s*f['""]https?://)
|(?i:\bfetch\s*\(\s*`https?://[^`\n]*\$\{)
|(?i:\bnew\s+Uri\s*\(\s*\$\{""[^""\n]*\{[^}\n]*(?:request|query|param|url|user|input|target))"));

    /// <summary>SRC-LOGSENS-007: secrets flowing into log statements.</summary>
    private static SourceRule SensitiveDataLogging() => New(
        "SRC-LOGSENS-007",
        "Sensitive variable passed into logging statement",
        "Passwords, tokens, and API keys written to logs persist in log aggregation systems where they are readable by anyone with log access and are exempt from credential rotation workflows.",
        "Log stable correlation identifiers instead of credential material and ensure structured logging redaction covers sensitive field names.",
        "SensitiveDataLogging",
        Severity.Low,
        ConfidenceLevel.Medium,
        exploitability: false,
        languages: null,
        Rx(@"(?i:\bLog(?:Trace|Debug|Information|Warning|Error|Critical)\s*\(\s*[^;\n]{0,200}\b(?:password|passwd|secret|api[_\-]?key|apikey|authorization|bearer|access[_\-]?token)\b)
|(?i:\bconsole\.(?:log|debug|info|warn|error)\s*\([^\n]{0,200}\b(?:password|passwd|secret|api[_\-]?key|apikey|token)\b)
|(?i:\blogger\.(?:trace|debug|information|info|warning|warn|error|critical)\s*\([^\n]{0,200}\b(?:password|passwd|secret|api[_\-]?key|token)\b)
|(?i:\bprint\s*\([^\n]{0,160}\b(?:password|passwd|secret|api[_\-]?key)\b)"));

    /// <summary>SRC-TLS-008: TLS certificate validation disabled in code or configuration.</summary>
    private static SourceRule TlsValidationDisabled() => New(
        "SRC-TLS-008",
        "TLS server-certificate validation disabled",
        "Accepting every presented certificate converts TLS into a plaintext transport: man-in-the-middle attackers can read and modify all traffic, including authentication exchanges.",
        "Remove the validation bypass and rely on the platform trust store; if a custom root must be trusted, pin that specific issuer instead of accepting any certificate.",
        "DisabledTlsValidation",
        Severity.Medium,
        ConfidenceLevel.High,
        exploitability: true,
        languages: null,
        Rx(@"DangerousAcceptAnyServerCertificateValidator
|(?i:ServerCertificate(?:Custom)?ValidationCallback\s*=[^;\n]{0,120}=>\s*true\b)
|(?i:\bverify\s*=\s*False\b)
|(?i:NODE_TLS_REJECT_UNAUTHORIZED[""' \t]*[=:][= \t]*[""']?0\b)
|(?i:rejectUnauthorized\s*:\s*false\b)"));

    /// <summary>SRC-CORS-009: wildcard cross-origin access declared in code or configuration.</summary>
    private static SourceRule PermissiveCors() => New(
        "SRC-CORS-009",
        "Wildcard cross-origin resource sharing policy",
        "Reflecting any origin lets hostile websites read authenticated responses from victim browsers, defeating the same-origin policy for every visitor.",
        "Enumerate the exact origins that require access and configure them explicitly; combine credentialed responses only with those named origins.",
        "PermissiveCorsConfiguration",
        Severity.Medium,
        ConfidenceLevel.High,
        exploitability: true,
        languages: null,
        Rx(@"AllowAnyOrigin\s*\(\s*\)
|(?i:Access-Control-Allow-Origin[""']?\s*[:=]\s*[""']?\*)
|(?i:access_control_allow_origin\s*:\s*[""']?\*)"));

    /// <summary>SRC-COOKIE-010: session cookies missing protective attributes.</summary>
    private static SourceRule InsecureCookie() => New(
        "SRC-COOKIE-010",
        "Cookie declared without transport and disclosure protections",
        "Cookies without Secure travel over plaintext connections and cookies without HttpOnly are readable by injected scripts, exposing session identifiers to interception and theft.",
        "Mark session cookies Secure, HttpOnly, and SameSite=Lax or Strict; pair SameSite=None with Secure so the cookie survives only on protected transports.",
        "InsecureCookieConfiguration",
        Severity.Medium,
        ConfidenceLevel.Medium,
        exploitability: false,
        languages: Lang(SourceLanguage.Cs, SourceLanguage.Ts, SourceLanguage.Js, SourceLanguage.Py),
        Rx(@"(?-i:\bSecure\s*=\s*false\b)
|(?-i:\bHttpOnly\s*=\s*false\b)
|(?i:\bsecure\s*:\s*false\b)
|(?i:\bhttpOnly\s*:\s*false\b)
|(?i:sameSite\s*[:=]\s*[""']?(?:None\b|SameSiteMode\.None\b)(?![^;\n]{0,80}(?:secure\s*[=:]\s*true|Secure\s*=\s*true)))"));

    /// <summary>SRC-DESERS-011: dangerous deserialization entry points.</summary>
    private static SourceRule UnsafeDeserialization() => New(
        "SRC-DESERS-011",
        "Deserialization sink accepts attacker-shaped payloads",
        "Binary formatters and type-name-driven deserializers execute code embedded in crafted payloads; unsafe YAML and pickle loaders behave identically in Python ecosystems.",
        "Exchange data with JSON using concrete DTO types, restrict polymorphism with explicit serializer binders, and load YAML only through its safe schema.",
        "UnsafeDeserialization",
        Severity.High,
        ConfidenceLevel.High,
        exploitability: true,
        languages: Lang(SourceLanguage.Cs, SourceLanguage.Py, SourceLanguage.Yaml),
        Rx(@"BinaryFormatter\s*\.\s*Deserialize
|(?i:\bTypeNameHandling\s*=\s*TypeNameHandling\.(?:Auto|All)\b)
|(?i:\bpickle\.loads\s*\()
|(?i:\byaml\.load\s*\((?![^)\n]*SafeLoader))"));

    /// <summary>SRC-DEFAULT-012: insecure defaults shipped in build or configuration files.</summary>
    private static SourceRule InsecureDefaults() => New(
        "SRC-DEFAULT-012",
        "Insecure default environment or debug setting shipped",
        "Development-mode settings disable error masking and expose detailed diagnostics; shipping them to production discloses internals that aid further attacks.",
        "Set production as the default environment in deployment images and gate verbose diagnostics behind explicit operator opt-in.",
        "InsecureDefaultConfiguration",
        Severity.Low,
        ConfidenceLevel.High,
        exploitability: false,
        languages: Lang(SourceLanguage.Dockerfile, SourceLanguage.Yaml, SourceLanguage.Json),
        Rx(@"(?i:^[ \t]*ENV\s+ASPNETCORE_ENVIRONMENT[= ]+Development\b)
|(?i:\bdebug\s*[:=]\s*true\b)"));

    private static IReadOnlySet<SourceLanguage> Lang(params SourceLanguage[] languages) =>
        new HashSet<SourceLanguage>(languages);

    /// <summary>
    /// Second-stage filter for the generic credential assignment alternative: requires length at
    /// least sixteen, at least three character classes, and rejects well-known placeholder text.
    /// </summary>
    public static bool LooksLikeRealCredential(string candidate)
    {
        if (candidate.Length < 16)
        {
            return false;
        }

        var lowered = candidate.ToLowerInvariant();
        foreach (var marker in PlaceholderMarkers)
        {
            if (lowered.Contains(marker, StringComparison.Ordinal))
            {
                return false;
            }
        }

        var classes = 0;
        if (candidate.Any(char.IsAsciiLetterUpper)) classes++;
        if (candidate.Any(char.IsAsciiLetterLower)) classes++;
        if (candidate.Any(char.IsAsciiDigit)) classes++;
        if (candidate.Any(static c => !char.IsAsciiLetterOrDigit(c))) classes++;
        return classes >= 3;
    }

    private static readonly string[] PlaceholderMarkers =
    [
        "changeme", "change-me", "change_me", "example", "placeholder", "sample", "dummy",
        "todo", "xxxx", "****", "insert-", "replace", "redacted", "<", "{", "%("
    ];
}

