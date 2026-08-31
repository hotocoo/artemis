using ACT.Contracts;

namespace ACT.Web.Checks;

/// <summary>
/// ACT-WEB-COMPLIANCE-001: Checks for compliance with security standards (CIS, SOC2, etc.)
/// </summary>
public sealed class ComplianceCheck : ISecurityCheck
{
    public const string CheckIdValue = "ACT-WEB-COMPLIANCE-001";

    private readonly IEvidenceFactory _evidenceFactory;

    public ComplianceCheck(IEvidenceFactory evidenceFactory)
    {
        _evidenceFactory = evidenceFactory;
        Metadata = new SecurityCheckMetadata(
            Id: CheckId.From(CheckIdValue),
            Name: "Compliance Checking",
            Version: "1.0.0",
            Category: CheckCategory.Configuration,
            MaxEmittingSeverity: Severity.Medium,
            SafetyLevel: SafetyLevel.LocalOnly,
            RequiredPermissions: PermissionRequirement.ReadRepositoryFiles,
            RequiredProtocols: new HashSet<ProtocolKind>(),
            SupportedTargetTypes: new HashSet<TargetTypeKind> { TargetTypeKind.LocalSourceRepository },
            NetworkBehavior: new NetworkBehaviorProfile(0, 0, false, false, false),
            EvidenceTypesProduced: [EvidenceKind.SourceLocation],
            SupportsRemediation: true,
            SupportsRegressionTest: true,
            Description: "Checks for compliance with security standards like CIS, SOC2, etc.");
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
            var repoPath = context.Asset.CanonicalTarget;

            findings.AddRange(CheckForMissingSecurityHeaders(repoPath, context));
            findings.AddRange(CheckForMissingRateLimiting(repoPath, context));
            findings.AddRange(CheckForMissingAuditLogging(repoPath, context));

            return Task.FromResult(new SecurityCheckResult(
                Metadata.Id,
                CheckExecutionStatus.Completed,
                startedUtc,
                DateTimeOffset.UtcNow,
                findings,
                Array.Empty<EvidenceItem>(),
                findings.Count > 0 ? $"Found {findings.Count} compliance issues" : null,
                RequestCount: 0,
                TargetsExamined: 1));
        }
        catch (Exception ex)
        {
            return Task.FromResult(SecurityCheckResult.Empty(
                Metadata, startedUtc, CheckExecutionStatus.Failed_FailedClosed,
                $"Compliance check failed: {ex.Message}"));
        }
    }

    private IEnumerable<Finding> CheckForMissingSecurityHeaders(string repoPath, SecurityCheckContext context)
    {
        var findings = new List<Finding>();
        var webConfigFiles = RepositoryFileScanner.FindFiles(repoPath, "web.config", "nginx.conf", "apache.conf");
        
        foreach (var file in webConfigFiles)
        {
            try
            {
                var content = File.ReadAllText(file);
                if (!content.Contains("X-Frame-Options", StringComparison.OrdinalIgnoreCase) ||
                    !content.Contains("X-Content-Type-Options", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(CreateFinding(context, file, "Missing Security Headers",
                        "Web server configuration is missing recommended security headers.",
                        Severity.Medium));
                }
            }
            catch { }
        }
        
        return findings;
    }

    private IEnumerable<Finding> CheckForMissingRateLimiting(string repoPath, SecurityCheckContext context)
    {
        var findings = new List<Finding>();
        var apiFiles = RepositoryFileScanner.FindFiles(repoPath, "*.cs", "*.js", "*.py");
        
        foreach (var file in apiFiles)
        {
            try
            {
                var content = File.ReadAllText(file);
                if ((content.Contains("ApiController", StringComparison.OrdinalIgnoreCase) ||
                     content.Contains("Flask", StringComparison.OrdinalIgnoreCase) ||
                     content.Contains("Express", StringComparison.OrdinalIgnoreCase)) &&
                    !content.Contains("RateLimit", StringComparison.OrdinalIgnoreCase) &&
                    !content.Contains("Throttle", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(CreateFinding(context, file, "Missing Rate Limiting",
                        "API endpoints may be missing rate limiting protection.",
                        Severity.Medium));
                    break; // Only report once
                }
            }
            catch { }
        }
        
        return findings;
    }

    private IEnumerable<Finding> CheckForMissingAuditLogging(string repoPath, SecurityCheckContext context)
    {
        var findings = new List<Finding>();
        var authFiles = RepositoryFileScanner.FindFiles(repoPath, "*auth*.cs", "*login*.cs", "*security*.cs");
        
        foreach (var file in authFiles)
        {
            try
            {
                var content = File.ReadAllText(file);
                if (!content.Contains("Log", StringComparison.OrdinalIgnoreCase) &&
                    !content.Contains("Audit", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(CreateFinding(context, file, "Missing Audit Logging",
                        "Authentication code may be missing audit logging.",
                        Severity.Medium));
                    break; // Only report once
                }
            }
            catch { }
        }
        
        return findings;
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
            businessImpact: BusinessImpactLevel.Significant,
            whyItMatters: "Non-compliance with security standards can lead to security vulnerabilities and audit failures.",
            technicalExplanation: $"Compliance issue detected in {file}.",
            remediation: new RemediationGuidance(
                "Implement security best practices to achieve compliance.",
                ["Review security standards documentation.",
                 "Implement recommended security controls.",
                 "Document compliance measures."],
                []),
            fingerprintComponents: new FingerprintComponents(
                Metadata.Id,
                Path.GetFileName(file),
                $"{file}|{title}",
                "ComplianceIssue"),
            assetReference: file);
    }
}
