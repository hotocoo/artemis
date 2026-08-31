using ACT.Contracts;

namespace ACT.Web.Checks;

/// <summary>
/// ACT-WEB-CONFIG-001: Audits web server configuration for security best practices.
/// </summary>
public sealed class ConfigurationAuditCheck : ISecurityCheck
{
    public const string CheckIdValue = "ACT-WEB-CONFIG-001";

    public ConfigurationAuditCheck()
    {
        Metadata = new SecurityCheckMetadata(
            Id: CheckId.From(CheckIdValue),
            Name: "Configuration Security Audit",
            Version: "1.0.0",
            Category: CheckCategory.Configuration,
            MaxEmittingSeverity: Severity.High,
            SafetyLevel: SafetyLevel.LocalOnly,
            RequiredPermissions: PermissionRequirement.ReadRepositoryFiles,
            RequiredProtocols: new HashSet<ProtocolKind>(),
            SupportedTargetTypes: new HashSet<TargetTypeKind> { TargetTypeKind.LocalSourceRepository },
            NetworkBehavior: new NetworkBehaviorProfile(0, 0, false, false, false),
            EvidenceTypesProduced: [EvidenceKind.SourceLocation],
            SupportsRemediation: true,
            SupportsRegressionTest: true,
            Description: "Audits web server and application configuration files for security best practices.");
        Metadata.Validate();
    }

    public SecurityCheckMetadata Metadata { get; }

    public Task<SecurityCheckResult> ExecuteAsync(SecurityCheckContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var startedUtc = DateTimeOffset.UtcNow;

        if (context.Asset.Kind is not AssetKind.Repository)
        {
            return Task.FromResult(SecurityCheckResult.Empty(
                Metadata, startedUtc, CheckExecutionStatus.Skipped_NotApplicable,
                "The asset is not a local source repository."));
        }

        try
        {
            var findings = new List<Finding>();
            var evidence = new List<EvidenceItem>();
            var repoPath = context.Asset.CanonicalTarget;

            findings.AddRange(CheckForDebugMode(repoPath, context));
            findings.AddRange(CheckForHardcodedCredentials(repoPath, context));

            return Task.FromResult(new SecurityCheckResult(
                Metadata.Id,
                CheckExecutionStatus.Completed,
                startedUtc,
                DateTimeOffset.UtcNow,
                findings,
                evidence,
                findings.Count > 0 ? $"Found {findings.Count} configuration issues" : null,
                RequestCount: 0,
                TargetsExamined: 1));
        }
        catch (Exception ex)
        {
            return Task.FromResult(SecurityCheckResult.Empty(
                Metadata, startedUtc, CheckExecutionStatus.Failed_FailedClosed,
                $"Configuration audit failed: {ex.Message}"));
        }
    }

    private IEnumerable<Finding> CheckForDebugMode(string repoPath, SecurityCheckContext context)
    {
        var findings = new List<Finding>();
        var debugPatterns = new[] { "DEBUG=true", "DEBUG=True", "debug=true", "debug=True" };
        
        var configFiles = RepositoryFileScanner.FindFiles(repoPath, "*.env*");
        
        foreach (var file in configFiles)
        {
            try
            {
                var content = File.ReadAllText(file);
                foreach (var pattern in debugPatterns)
                {
                    if (content.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                    {
                        findings.Add(CreateFinding(context, file, "Debug Mode Enabled", 
                            "Debug mode is enabled in configuration.", Severity.High));
                        break;
                    }
                }
            }
            catch { }
        }
        
        return findings;
    }

    private IEnumerable<Finding> CheckForHardcodedCredentials(string repoPath, SecurityCheckContext context)
    {
        var findings = new List<Finding>();
        var credentialPatterns = new[] { "password=", "passwd=", "api_key=", "secret=", "token=" };
        
        var configFiles = RepositoryFileScanner.FindFiles(repoPath, "*.env*", "*.config");
        
        foreach (var file in configFiles)
        {
            try
            {
                var lines = File.ReadAllLines(file);
                for (var i = 0; i < lines.Length; i++)
                {
                    var line = lines[i];
                    foreach (var pattern in credentialPatterns)
                    {
                        if (line.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            // Skip comments and template/secret-manager placeholders: they are
                            // documentation of WHERE a secret lives, not a leaked secret.
                            var trimmed = line.TrimStart();
                            if (trimmed.StartsWith('#') || trimmed.StartsWith("//") || trimmed.StartsWith(';'))
                            {
                                break;
                            }

                            var value = ExtractValueAfter(line, pattern);
                            if (IsPlaceholderValue(value))
                            {
                                break;
                            }

                            findings.Add(CreateFinding(context, file, "Potential Hardcoded Credential",
                                $"Line {i + 1} contains what appears to be a hardcoded credential.", Severity.High));
                            break;
                        }
                    }
                }
            }
            catch { }
        }
        
        return findings;
    }

    /// <summary>Extracts the value portion following a credential pattern on a line.</summary>
    private static string ExtractValueAfter(string line, string pattern)
    {
        var idx = line.IndexOf(pattern, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return string.Empty;
        var valueStart = idx + pattern.Length;
        while (valueStart < line.Length && char.IsWhiteSpace(line[valueStart])) valueStart++;
        return valueStart < line.Length ? line[valueStart..].Trim() : string.Empty;
    }

    /// <summary>
    /// True when a credential value is a known placeholder, template token, or environment
    /// reference rather than a literal secret. Prevents template files from flooding reports.
    /// </summary>
    private static bool IsPlaceholderValue(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return true;

        var lowered = value.ToLowerInvariant();

        // Environment/secret-manager references.
        if (lowered.StartsWith("${") || lowered.StartsWith("$(") || lowered.StartsWith("%(") ||
            lowered.StartsWith("#{") || lowered.StartsWith("${{"))
        {
            return true;
        }

        // Common placeholder tokens.
        var placeholders = new[]
        {
            "changeme", "change_me", "change-me", "changeit", "change_it",
            "placeholder", "todo", "fixme", "xxx", "xxxx", "xxxxx",
            "your_", "your-", "yourpassword", "password123", "admin123",
            "set_in_secrets_manager", "set_in_secret_manager", "from_secrets",
            "secret_manager", "vault", "redacted", "none", "null", "n/a",
            "example", "sample", "dummy", "test123", "dev123", "localdev",
            "insert_", "replace_", "your_value"
        };

        foreach (var token in placeholders)
        {
            if (lowered.Contains(token)) return true;
        }

        // Double-underscore template tokens (e.g. __release_tag__).
        if (lowered.Contains("__")) return true;

        return false;
    }
    private Finding CreateFinding(SecurityCheckContext context, string file, string title, string description, Severity severity)
    {
        return FindingFactory.Create(
            context.Assessment.AssessmentId,
            Metadata.Id,
            targetDisplay: Path.GetFileName(file),
            category: CheckCategory.Configuration,
            title: title,
            description: description,
            severity: severity,
            confidence: ConfidenceLevel.Medium,
            exploitabilityIndicator: false,
            businessImpact: severity == Severity.High ? BusinessImpactLevel.Severe : BusinessImpactLevel.Significant,
            whyItMatters: "Insecure configurations can lead to security vulnerabilities.",
            technicalExplanation: $"Configuration issue detected in {file}.",
            remediation: new RemediationGuidance(
                "Review and secure the configuration.",
                ["Review the configuration file for security best practices.",
                 "Apply recommended security settings."],
                []),
            fingerprintComponents: new FingerprintComponents(
                Metadata.Id,
                Path.GetFileName(file),
                $"{file}|{title}",
                "ConfigIssue"),
            assetReference: file);
    }
}
