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
            Remediation: new RemediationGuidance(
                "Remove from source, purge history, rotate the credential.",
                ["Immediately revoke and rotate the exposed credential.",
                 "Remove the secret from the source code and any configuration.",
                 "Purge it from version-control history (git filter-repo or BFG).",
                 "Add a pre-commit and CI secret scanner (gitleaks, trufflehog).",
                 "Move the value to a secret manager or environment configuration."],
                ["OWASP Secrets Management Cheat Sheet", "CWE-798", "https://gitleaks.io"]),
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
            Remediation: new RemediationGuidance(
                "Replace with configuration or a secret store; verify the value was never deployed.",
                ["Confirm whether the value is a live credential; if so, rotate it.",
                 "Replace the literal with a reference to configuration or a secret store.",
                 "Verify the value was never deployed or committed to a public repository.",
                 "Add secret-scanning to CI to prevent recurrence."],
                ["OWASP Secrets Management Cheat Sheet", "CWE-798"]),
            FindingClass: "GenericSecretSink",
            Severity: Severity.Medium,
            Confidence: ConfidenceLevel.Medium,
            ExploitabilityIndicator: false,
            Languages: Lang(SourceLanguage.Cs, SourceLanguage.Ts, SourceLanguage.Js, SourceLanguage.Py, SourceLanguage.Rust, SourceLanguage.Cpp, SourceLanguage.Yaml, SourceLanguage.Json, SourceLanguage.Shell, SourceLanguage.Unknown),
            MaxMatchesPerFile: 5,
            Pattern: Rx("""(?i)\b(?:password|passwd|secret|api_key|apikey|token)\b"?\s*[:=]\s*"?(?<secret>[^"'\s]{16,})"""),
            MatchValidator: HasSufficientSecretVariety,
            RedactMatches: true,
            // Generic credential-assignment is the noisiest secret rule: test fixtures and
            // throwaway values in *_test / *.spec files flood reports. Recognized-format secrets
            // (SRC-SECRET-001) still scan test files where real keys are sometimes committed.
            SkipTestFiles: true),
        new SourceRule(
            RuleId: "SRC-CRYPTO-002",
            Title: "Weak or legacy cryptographic primitive",
            WhyItMatters: "MD5/SHA1/DES provide no meaningful security against modern attackers.",
            Remediation: new RemediationGuidance(
                "Use SHA-256+ / AES-GCM (or platform-recommended primitives) for all security purposes.",
                ["Replace MD5/SHA1/DES with SHA-256+ or an authenticated cipher (AES-GCM).",
                 "Audit and re-key any stored hashes or ciphertexts produced by the weak primitive.",
                 "Use a vetted crypto library instead of hand-rolled cryptography."],
                ["NIST SP 800-131A", "RFC 6234", "CWE-327"]),
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
            Remediation: new RemediationGuidance(
                "Use parameterized queries exclusively; pass user input as bound parameters, never as query text.",
                ["Use parameterized queries with bound parameters for all user input.",
                 "Remove string concatenation/interpolation from query construction.",
                 "Apply least-privilege database accounts.",
                 "Adopt an ORM or query builder where appropriate."],
                ["OWASP SQL Injection", "CWE-89"]),
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
            Remediation: new RemediationGuidance(
                "Invoke fixed executables with argument arrays; never route untrusted text through a shell.",
                ["Invoke fixed executables with argument arrays instead of a shell.",
                 "Validate and allowlist any dynamic input before use.",
                 "Avoid shell interpretation (shell=False; no /bin/sh -c)."],
                ["OWASP Command Injection", "CWE-78"]),
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
            Remediation: new RemediationGuidance(
                "Resolve the final path and verify containment inside an allowlisted root before file operations.",
                ["Resolve the final path and verify it stays inside an allowlisted root.",
                 "Reject or sanitize inputs containing traversal sequences (../).",
                 "Use safe file APIs that prevent directory escape."],
                ["OWASP Path Traversal", "CWE-22"]),
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
            Remediation: new RemediationGuidance(
                "Validate destinations against an explicit host/scheme allowlist before fetching.",
                ["Validate outbound destinations against an explicit host/scheme allowlist.",
                 "Block requests to internal/private IP ranges and metadata endpoints.",
                 "Resolve and re-check the target IP before connecting."],
                ["OWASP SSRF Prevention Cheat Sheet", "CWE-918"]),
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
            Remediation: new RemediationGuidance(
                "Keep validation enabled; pin certificates explicitly when required.",
                ["Re-enable certificate validation.",
                 "Use the system trust store or explicitly pinned certificates.",
                 "Remove any callback that unconditionally returns true."],
                ["CWE-295", "RFC 8446"]),
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
            Remediation: new RemediationGuidance(
                "Restrict allowed origins to an explicit list; never combine wildcard with credentials.",
                ["Restrict allowed origins to an explicit list.",
                 "Never combine a wildcard origin with credentials.",
                 "Validate the Origin header on credentialed endpoints."],
                ["OWASP CORS Misconfiguration", "CWE-942"]),
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
            Remediation: new RemediationGuidance(
                "Set Secure, HttpOnly, and an explicit SameSite policy on every cookie.",
                ["Set the Secure flag on all cookies served over HTTPS.",
                 "Set HttpOnly to prevent script access.",
                 "Set an explicit SameSite policy (Lax or Strict)."],
                ["OWASP Secure Cookie Flag", "CWE-614"]),
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
            Remediation: new RemediationGuidance(
                "Prefer type-safe serializers; never deserialize untrusted polymorphic payloads.",
                ["Use type-safe serializers with an explicit allowlist of types.",
                 "Never deserialize untrusted polymorphic payloads.",
                 "Replace BinaryFormatter/pickle with safe alternatives (System.Text.Json, etc.)."],
                ["CWE-502", ".NET BinaryFormatter deprecation guidance"]),
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
            Remediation: new RemediationGuidance(
                "Use bounded alternatives (strncpy, snprintf, fgets) or safe container types; validate sizes.",
                ["Replace strcpy/strcat/sprintf with bounded alternatives (strncpy, snprintf).",
                 "Validate buffer sizes before copying.",
                 "Prefer safe container types (std::string, std::vector)."],
                ["CWE-120", "CWE-121", "CWE-134", "CERT C Coding Standard"]),
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
            Remediation: new RemediationGuidance(
                "Use SHA-256+ / AES (or platform-recommended primitives) for all security purposes.",
                ["Replace MD5/SHA1/DES with SHA-256+ or AES.",
                 "Use the platform crypto library (OpenSSL, CommonCrypto).",
                 "Re-key any data protected by the weak primitive."],
                ["NIST SP 800-131A", "RFC 6234", "CWE-327"]),
            FindingClass: "WeakCryptoSink",
            Severity: Severity.Medium,
            Confidence: ConfidenceLevel.Medium,
            ExploitabilityIndicator: false,
            Languages: Lang(SourceLanguage.Cpp),
            MaxMatchesPerFile: 5,
            Pattern: Rx("""(?i)\bMD5_Init\s*\(""", """(?i)\bSHA1_Init\s*\(""", """(?i)\bDES_set_key\s*\(""", """(?i)\bMD5\s*\(\s*[^)]*data""")),
        new SourceRule(
            RuleId: "SRC-INJECT-CMD-014",
            Title: "Shell command execution from untrusted input",
            WhyItMatters: "Passing untrusted data to system() or popen() allows command injection and remote code execution.",
            Remediation: new RemediationGuidance(
                "Avoid shell execution; if unavoidable, use parameterized APIs and validate/escape all input.",
                ["Avoid system()/popen() with untrusted input.",
                 "Use execve-style APIs with explicit argument vectors.",
                 "Validate and allowlist any dynamic input."],
                ["CWE-78", "CERT C Coding Standard"]),
            FindingClass: "CommandInjectionSink",
            Severity: Severity.High,
            Confidence: ConfidenceLevel.Medium,
            ExploitabilityIndicator: true,
            Languages: Lang(SourceLanguage.Cpp),
            MaxMatchesPerFile: 5,
            // No whitespace before "(" : "system (" is common in English prose/comments and
            // would otherwise false-positive. exec[lv][ep]? covers the full exec family
            // (execl, execlp, execle, execv, execve, execvp) without matching "execute"/"execution".
            Pattern: Rx("""\bsystem\(""", """\bpopen\(""", """\bexec[lv][ep]?\(""")),
        new SourceRule(
            RuleId: "SRC-TLS-015",
            Title: "TLS certificate verification disabled",
            WhyItMatters: "Disabling certificate verification allows man-in-the-middle attacks on encrypted traffic.",
            Remediation: new RemediationGuidance(
                "Always verify TLS certificates; use system trust stores or pinned certificates.",
                ["Always verify TLS certificates.",
                 "Use the system trust store or pinned certificates.",
                 "Remove SSL_VERIFY_NONE / CURLOPT_SSL_VERIFYPEER=0."],
                ["CWE-295", "RFC 8446"]),
            FindingClass: "TlsConfigSink",
            Severity: Severity.High,
            Confidence: ConfidenceLevel.High,
            ExploitabilityIndicator: true,
            Languages: Lang(SourceLanguage.Cpp),
            MaxMatchesPerFile: 5,
            Pattern: Rx("""(?i)SSL_set_verify\s*\([^)]*SSL_VERIFY_NONE""", """(?i)CURLOPT_SSL_VERIFYPEER\s*[)]*\s*=\s*0""", """(?i)CURLOPT_SSL_VERIFYHOST\s*[)]*\s*=\s*0""", """(?i)SSL_CTX_set_verify\s*\([^)]*SSL_VERIFY_NONE""")),
    ];

    /// <summary>
    /// Matches a pure dotted identifier (e.g. pass.stringValue) whose segments contain only
    /// letters and underscores. Such values are property/method accesses in code, never literal
    /// secrets; real secrets and tokens carry digits or base64 characters in their segments.
    /// </summary>
    private static readonly System.Text.RegularExpressions.Regex CodeIdentifierPattern =
        new("^[A-Za-z_][A-Za-z_]*(\\.[A-Za-z_][A-Za-z_]*)+$",
            System.Text.RegularExpressions.RegexOptions.Compiled | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>Secret candidates must mix at least three character classes to cut false positives.</summary>
    private static bool HasSufficientSecretVariety(string candidate)
    {
        // Template-literal interpolations and env references are code that resolves to a value,
        // not a literal secret: token=${...}, SECRET=${ENV_VAR}, etc. Reject them outright.
        if (candidate.Contains("${") || candidate.Contains("#{") ||
            candidate.StartsWith("$", StringComparison.Ordinal) ||
            candidate.Contains(".env."))
        {
            return false;
        }

        // Function calls / expressions are code, not secrets: trimCopy(...), substr(pos, ...).
        // A genuine secret never contains call parentheses.
        if (candidate.Contains('(') || candidate.Contains(')'))
        {
            return false;
        }

        // Dotted identifiers made of pure identifiers (pass.stringValue, foo.bar) are property or
        // method accesses, not literal secrets. Real secrets and JWTs contain digits or base64
        // characters, so this conservative shape never shadows them.
        if (CodeIdentifierPattern.IsMatch(candidate))
        {
            return false;
        }

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
