using ACT.Contracts;

namespace ACT.Web.Checks;

/// <summary>
/// ACT-WEB-BASELINE-001: Verifies security baselines are met.
/// </summary>
public sealed class SecurityBaselineCheck : ISecurityCheck
{
    public const string CheckIdValue = "ACT-WEB-BASELINE-001";

    private readonly IEvidenceFactory _evidenceFactory;

    public SecurityBaselineCheck(IEvidenceFactory evidenceFactory)
    {
        _evidenceFactory = evidenceFactory;
        Metadata = new SecurityCheckMetadata(
            Id: CheckId.From(CheckIdValue),
            Name: "Security Baseline Checking",
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
            Description: "Verifies security baselines are met for the application.");
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

            findings.AddRange(CheckForInsecureDependencies(repoPath, context));
            findings.AddRange(CheckForMissingErrorHandling(repoPath, context));
            findings.AddRange(CheckForInsecureRandomGeneration(repoPath, context));

            return Task.FromResult(new SecurityCheckResult(
                Metadata.Id,
                CheckExecutionStatus.Completed,
                startedUtc,
                DateTimeOffset.UtcNow,
                findings,
                Array.Empty<EvidenceItem>(),
                findings.Count > 0 ? $"Found {findings.Count} baseline issues" : null,
                RequestCount: 0,
                TargetsExamined: 1));
        }
        catch (Exception ex)
        {
            return Task.FromResult(SecurityCheckResult.Empty(
                Metadata, startedUtc, CheckExecutionStatus.Failed_FailedClosed,
                $"Baseline check failed: {ex.Message}"));
        }
    }

    private IEnumerable<Finding> CheckForInsecureDependencies(string repoPath, SecurityCheckContext context)
    {
        var findings = new List<Finding>();
        var packageFiles = RepositoryFileScanner.FindFiles(repoPath, "package.json", "requirements.txt", "*.csproj");
        
        foreach (var file in packageFiles)
        {
            try
            {
                var content = File.ReadAllText(file);
                // Check for known insecure dependencies (simplified example)
                if (content.Contains("jquery@<3.5", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("lodash@<4.17", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(CreateFinding(context, file, "Insecure Dependencies",
                        "Package file contains potentially insecure dependencies.",
                        Severity.High));
                }
            }
            catch { }
        }
        
        return findings;
    }

    private IEnumerable<Finding> CheckForMissingErrorHandling(string repoPath, SecurityCheckContext context)
    {
        var findings = new List<Finding>();
        var sourceFiles = RepositoryFileScanner.FindFiles(repoPath, "*.cs", "*.js", "*.py");
        
        foreach (var file in sourceFiles)
        {
            try
            {
                var content = File.ReadAllText(file);
                if (content.Contains("catch", StringComparison.OrdinalIgnoreCase) &&
                    content.Contains("catch (Exception", StringComparison.OrdinalIgnoreCase) &&
                    !content.Contains("Log", StringComparison.OrdinalIgnoreCase) &&
                    !content.Contains("logger", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(CreateFinding(context, file, "Missing Error Logging",
                        "Exception handling may be missing proper logging.",
                        Severity.Medium));
                    break; // Only report once
                }
            }
            catch { }
        }
        
        return findings;
    }

    private IEnumerable<Finding> CheckForInsecureRandomGeneration(string repoPath, SecurityCheckContext context)
    {
        var findings = new List<Finding>();
        var sourceFiles = RepositoryFileScanner.FindFiles(repoPath, "*.cs", "*.js", "*.py");
        
        foreach (var file in sourceFiles)
        {
            try
            {
                var content = File.ReadAllText(file);
                if (content.Contains("new Random()", StringComparison.OrdinalIgnoreCase) ||
                    content.Contains("Math.random()", StringComparison.OrdinalIgnoreCase))
                {
                    findings.Add(CreateFinding(context, file, "Insecure Random Generation",
                        "Code uses insecure random number generation.",
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
            businessImpact: severity == Severity.High ? BusinessImpactLevel.Severe : BusinessImpactLevel.Significant,
            whyItMatters: "Failing to meet security baselines can lead to vulnerabilities.",
            technicalExplanation: $"Baseline issue detected in {file}.",
            remediation: new RemediationGuidance(
                "Implement security best practices to meet baselines.",
                ["Review security baseline documentation.",
                 "Implement recommended security controls."],
                []),
            fingerprintComponents: new FingerprintComponents(
                Metadata.Id,
                Path.GetFileName(file),
                $"{file}|{title}",
                "BaselineIssue"),
            assetReference: file);
    }
}
