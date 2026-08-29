using System.Text.RegularExpressions;
using ACT.Contracts;

namespace ACT.SourceAnalysis;

/// <summary>The built-in Artemis rule set. Conservative patterns; ReDoS timeout per Regex; per-file match budgets in the engine.</summary>
public static class DefaultSourceRules
{
    /// <summary>The complete built-in set.</summary>
    public static IReadOnlyList<SourceRule> All { get; } =
    [
        new SourceRule(
            RuleId: "SRC-SECRET-001",
            Title: "Hard-coded credential or secret in a recognized format",
            WhyItMatters: "Recognized credential formats grant immediate impersonation when committed.",
            Remediation: new RemediationGuidance("Remove from source, purge history, rotate the credential.", [], []),
            FindingClass: "SecretSink",
            Severity: Severity.High,
            Confidence: ConfidenceLevel.High,
            ExploitabilityIndicator: false,
            Languages: Lang(SourceLanguage.Cs, SourceLanguage.Ts, SourceLanguage.Js, SourceLanguage.Py, SourceLanguage.Rust, SourceLanguage.Cpp, SourceLanguage.Yaml, SourceLanguage.Json, SourceLanguage.Shell, SourceLanguage.Unknown),
            MaxMatchesPerFile: 5,
            Pattern: Rx("""(?i)(?<secret>AKIA[0-9A-Z]{16})""", """(?i)(?<secret>gh[pousr]_[A-Za-z0-9]{20,})""", """(?i)(?<secret>xox[baprs]-[A-Za-z0-9-]{10,})""", """(?is)(?<secret>-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----)"""),
            RedactMatches: true),

        new SourceRule(
            RuleId: "SRC-SECRET-002",
            Title: "Generic credential assignment with high-variety value",
            WhyItMatters: "Long mixed-class values assigned to password-like names are probable live secrets.",
            Remediation: new RemediationGuidance("Replace with configuration or a secret store; verify the value was never deployed.", [], []),
            FindingClass: "GenericSecretSink",
            Severity: Severity.Medium,
            Confidence: ConfidenceLevel.Medium,
            ExploitabilityIndicator: false,
            Languages: Lang(SourceLanguage.Cs, SourceLanguage.Ts, SourceLanguage.Js, SourceLanguage.Py, SourceLanguage.Rust, SourceLanguage.Cpp, SourceLanguage.Yaml, SourceLanguage.Json, SourceLanguage.Shell, SourceLanguage.Unknown),
            MaxMatchesPerFile: 5,
            Pattern: Rx("""(?i)\b(?:password|passwd|secret|api_key|apikey|token)\b"?\s*[:=]\s*"?(?<secret>[^"'\s]{16,})"""),
            MatchValidator: HasSufficientSecretVariety,
            RedactMatches: true),
        new SourceRule(
            RuleId: "SRC-CRYPTO-002",
            Title: "Weak or legacy cryptographic primitive",
            WhyItMatters: "MD5/SHA1/DES provide no meaningful security against modern attackers.",
            Remediation: new RemediationGuidance("Use SHA-256+ / AES-GCM (or platform-recommended primitives) for all security purposes.", [], []),
            FindingClass: "WeakCryptoSink",
            Severity: Severity.Medium,
            Confidence: ConfidenceLevel.Medium,
            ExploitabilityIndicator: false,
            Languages: Lang(SourceLanguage.Cs, SourceLanguage.Py, SourceLanguage.Rust),
            MaxMatchesPerFile: 5,
            Pattern: Rx("""(?i)\bDESCryptoServiceProvider|TripleDES\.Create|MD5\.Create|SHA1\.Create\b""", """(?i)hashlib\.(md5|sha1)\b""")),
        new SourceRule(
            RuleId: "SRC-INJECT-SQL-003",
            Title: "SQL query assembled through concatenation or interpolation",
            WhyItMatters: "Queries built from untrusted text allow attackers to change query semantics or read arbitrary data.",
            Remediation: new RemediationGuidance("Use parameterized queries exclusively; pass user input as bound parameters, never as query text.", [], []),
            FindingClass: "SqlInjectionSink",
            Severity: Severity.High,
            Confidence: ConfidenceLevel.High,
            ExploitabilityIndicator: true,
            Languages: Lang(SourceLanguage.Cs, SourceLanguage.Js, SourceLanguage.Py),
            MaxMatchesPerFile: 5,
            Pattern: Rx("""(?i)\bExecute(Reader|NonQuery|Scalar)\s*\(\s*(new|string\.Format|\$)""", """(?i)\bFromSqlRaw\s*\(\s*(\$|string\.Format)""", """(?i)\.execute\s*\(\s*f['\"]""", """(?i)\.execute\s*\(\s*['\"][^'\n]*['\"]\s*[%+]""")),
        new SourceRule(
            RuleId: "SRC-INJECT-CMD-004",
            Title: "Operating-system command built from interpolated input",
            WhyItMatters: "Commands assembled from request-controlled text let an attacker run arbitrary statements on the host.",
            Remediation: new RemediationGuidance("Invoke fixed executables with argument arrays; never route untrusted text through a shell.", [], []),
            FindingClass: "CommandInjectionSink",
            Severity: Severity.Critical,
            Confidence: ConfidenceLevel.Medium,
            ExploitabilityIndicator: true,
            Languages: Lang(SourceLanguage.Cs, SourceLanguage.Py, SourceLanguage.Js, SourceLanguage.Rust),
            MaxMatchesPerFile: 5,
            Pattern: Rx("""(?i)\bProcess\.Start\s*\(\s*(\$|string\.Format)""", """(?i)\bos\.system\s*\(""", """(?i)\bsubprocess\.[a-z]+\s*\([^()\n]*shell\s*=\s*True""", """(?i)\bexec(Sync)?\s*\(\s*[`][^`\n]*[$]{""")),
        new SourceRule(
            RuleId: "SRC-PATH-TRAV-005",
            Title: "File path composed from request-derived values without containment check",
            WhyItMatters: "Unvalidated path composition lets relative-path tricks escape the intended root directory.",
            Remediation: new RemediationGuidance("Resolve the final path and verify containment inside an allowlisted root before file operations.", [], []),
            FindingClass: "PathTraversalSink",
            Severity: Severity.Medium,
            Confidence: ConfidenceLevel.Medium,
            ExploitabilityIndicator: true,
            Languages: Lang(SourceLanguage.Cs, SourceLanguage.Js, SourceLanguage.Py),
            MaxMatchesPerFile: 5,
            Pattern: Rx("""(?i)Path\.Combine\s*\([^)]*request""", """(?i)open\s*\(\s*os\.path\.join\s*\([^)]*request""")),
        new SourceRule(
            RuleId: "SRC-SSRF-006",
            Title: "Outbound HTTP request built from a request-controlled URL",
            WhyItMatters: "Attackers can pivot the server into internal networks by steering request targets.",
            Remediation: new RemediationGuidance("Validate destinations against an explicit host/scheme allowlist before fetching.", [], []),
            FindingClass: "SsrfSink",
            Severity: Severity.Medium,
            Confidence: ConfidenceLevel.Medium,
            ExploitabilityIndicator: true,
            Languages: Lang(SourceLanguage.Cs, SourceLanguage.Js, SourceLanguage.Py),
            MaxMatchesPerFile: 5,
            Pattern: Rx("""(?i)GetAsync?\s*\([^)]*request""", """(?i)requests\.get\s*\(\s*f['\"]http""")),
        new SourceRule(
            RuleId: "SRC-TLS-008",
            Title: "TLS certificate validation disabled",
            WhyItMatters: "Accepting any certificate silently enables interception of supposedly protected traffic.",
            Remediation: new RemediationGuidance("Keep validation enabled; pin certificates explicitly when required.", [], []),
            FindingClass: "TlsValidationSink",
            Severity: Severity.Medium,
            Confidence: ConfidenceLevel.High,
            ExploitabilityIndicator: false,
            Languages: Lang(SourceLanguage.Cs, SourceLanguage.Js, SourceLanguage.Py, SourceLanguage.Ts),
            MaxMatchesPerFile: 5,
            Pattern: Rx("""(?i)ServerCertificateValidationCallback[^\n]*true""", """(?i)DangerousAcceptAnyServerCertificateValidator""", """(?i)verify\s*=\s*False""", """(?i)NODE_TLS_REJECT_UNAUTHORIZED[^\n]*0""", """(?i)rejectUnauthorized\s*:\s*false""")),
        new SourceRule(
            RuleId: "SRC-CORS-009",
            Title: "Permissive CORS policy in code or configuration",
            WhyItMatters: "Wildcard cross-origin policies expose authenticated responses to hostile origins.",
            Remediation: new RemediationGuidance("Restrict allowed origins to an explicit list; never combine wildcard with credentials.", [], []),
            FindingClass: "CorsPolicySink",
            Severity: Severity.Medium,
            Confidence: ConfidenceLevel.Medium,
            ExploitabilityIndicator: false,
            Languages: Lang(SourceLanguage.Cs, SourceLanguage.Ts, SourceLanguage.Js, SourceLanguage.Yaml),
            MaxMatchesPerFile: 5,
            Pattern: Rx("""(?i)AllowAnyOrigin\b""", """(?i)Access-Control-Allow-Origin['\" ]*[:=]['\" ]*\*""")),
        new SourceRule(
            RuleId: "SRC-COOKIE-010",
            Title: "Insecure cookie attribute configuration",
            WhyItMatters: "Cookies without Secure/HttpOnly/SameSite protections are exposed to interception or CSRF abuse.",
            Remediation: new RemediationGuidance("Set Secure, HttpOnly, and an explicit SameSite policy on every cookie.", [], []),
            FindingClass: "CookieConfigSink",
            Severity: Severity.Medium,
            Confidence: ConfidenceLevel.Medium,
            ExploitabilityIndicator: false,
            Languages: Lang(SourceLanguage.Cs, SourceLanguage.Ts, SourceLanguage.Js, SourceLanguage.Yaml),
            MaxMatchesPerFile: 5,
            Pattern: Rx("""(?i)Secure\s*=\s*false""", """(?i)HttpOnly\s*=\s*false""", """(?i)SameSite=None(?![^;\n]*Secure)""")),
        new SourceRule(
            RuleId: "SRC-DESERS-011",
            Title: "Dangerous deserializer invoked",
            WhyItMatters: "Polymorphic deserializers reconstruct attacker-chosen types and historically enable remote code execution.",
            Remediation: new RemediationGuidance("Prefer type-safe serializers; never deserialize untrusted polymorphic payloads.", [], []),
            FindingClass: "DeserializationSink",
            Severity: Severity.High,
            Confidence: ConfidenceLevel.High,
            ExploitabilityIndicator: true,
            Languages: Lang(SourceLanguage.Cs, SourceLanguage.Js, SourceLanguage.Py),
            MaxMatchesPerFile: 5,
            Pattern: Rx("""\bbinaryFormatter\.Deserialize\b""", """(?i)TypeNameHandling\s*[=.]\s*(Auto|All)""", """(?i)pickle\.loads\s*\(""", """(?i)yaml\.load\s*\((?![^)\n]*Loader)""")),
        new SourceRule(
            RuleId: "SRC-UNSAFE-012",
            Title: "Buffer-unsafe C/C++ string or I/O function",
            WhyItMatters: "Unbounded string and I/O functions are the classic vector for stack/heap buffer overflows in native code.",
            Remediation: new RemediationGuidance("Use bounded alternatives (strncpy, snprintf, fgets) or safe container types; validate sizes.", [], []),
            FindingClass: "UnsafeNativeFunction",
            Severity: Severity.High,
            Confidence: ConfidenceLevel.High,
            ExploitabilityIndicator: true,
            Languages: Lang(SourceLanguage.Cpp),
            MaxMatchesPerFile: 8,
            Pattern: Rx("""\bstrcpy\s*\(""", """\bstrcat\s*\(""", """\bsprintf\s*\(""")),
        new SourceRule(
            RuleId: "SRC-CRYPTO-013",
            Title: "Weak or legacy cryptographic primitive in native code",
            WhyItMatters: "MD5/SHA1/DES provide no meaningful security against modern attackers.",
            Remediation: new RemediationGuidance("Use SHA-256+ / AES (or platform-recommended primitives) for all security purposes.", [], []),
            FindingClass: "WeakCryptoSink",
            Severity: Severity.Medium,
            Confidence: ConfidenceLevel.Medium,
            ExploitabilityIndicator: false,
            Languages: Lang(SourceLanguage.Cpp),
            MaxMatchesPerFile: 5,
            Pattern: Rx("""(?i)\bMD5_Init\s*\(""", """(?i)\bSHA1_Init\s*\(""", """(?i)\bDES_set_key\s*\(""", """(?i)\bMD5\s*\(\s*[^)]*data""")),
    ];

    /// <summary>Secret candidates must mix at least three character classes to cut false positives.</summary>
    private static bool HasSufficientSecretVariety(string candidate)
    {
        var classes = 0;
        if (candidate.Any(char.IsUpper)) classes++;
        if (candidate.Any(char.IsLower)) classes++;
        if (candidate.Any(char.IsDigit)) classes++;
        if (candidate.Any(c => !char.IsLetterOrDigit(c))) classes++;
        if (classes < 3) return false;
        var lowered = candidate.ToLowerInvariant();
        string[] placeholders = ["changeme", "example", "sample", "dummy", "placeholder", "tbd"];
        foreach (var marker in placeholders)
        {
            if (lowered.Contains(marker)) return false;
        }
        return true;
    }

    private static Regex Rx(params string[] alternatives)
    {
        var pattern = string.Join("|", alternatives);
        // The per-match budget is ReDoS defense-in-depth, not a performance bound: every shipped
        // rule is linear and evaluates in microseconds. The budget stays at one full second so a
        // JIT warm-up, GC pause, or scheduler stall on a loaded host cannot spuriously disable an
        // honest rule (a genuinely catastrophic pattern still trips it long before any budget in
        // RepositoryAnalysisLimits could be consumed).
        return new Regex(pattern,
            RegexOptions.Compiled | RegexOptions.CultureInvariant,
            matchTimeout: TimeSpan.FromSeconds(1));
    }

    private static IReadOnlyList<SourceLanguage> Lang(params SourceLanguage[] languages) => languages;
}
