using ACT.Contracts;

namespace ACT.Web.Checks;

/// <summary>
/// ACT-WEB-LOGANALYSIS-001: Analyzes logs for threat detection.
/// </summary>
public sealed class LogAnalysisCheck : ISecurityCheck
{
    public const string CheckIdValue = "ACT-WEB-LOGANALYSIS-001";

    private readonly IEvidenceFactory _evidenceFactory;

    private static readonly string[] ThreatPatterns =
    [
        "SQL Injection",
        "XSS Attack",
        "Command Injection",
        "Path Traversal",
        "Unauthorized Access",
        "Brute Force",
        "Malicious User Agent",
        "Suspicious Activity"
    ];

    public LogAnalysisCheck(IEvidenceFactory evidenceFactory)
    {
        _evidenceFactory = evidenceFactory;
        Metadata = new SecurityCheckMetadata(
            Id: CheckId.From(CheckIdValue),
            Name: "Log Analysis for Threat Detection",
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
            Description: "Analyzes logs for threat detection and suspicious activity.");
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

            findings.AddRange(AnalyzeLogFiles(repoPath, context));

            return Task.FromResult(new SecurityCheckResult(
                Metadata.Id,
                CheckExecutionStatus.Completed,
                startedUtc,
                DateTimeOffset.UtcNow,
                findings,
                Array.Empty<EvidenceItem>(),
                findings.Count > 0 ? $"Found {findings.Count} potential threats in logs" : null,
                RequestCount: 0,
                TargetsExamined: 1));
        }
        catch (Exception ex)
        {
            return Task.FromResult(SecurityCheckResult.Empty(
                Metadata, startedUtc, CheckExecutionStatus.Failed_FailedClosed,
                $"Log analysis failed: {ex.Message}"));
        }
    }

    private IEnumerable<Finding> AnalyzeLogFiles(string repoPath, SecurityCheckContext context)
    {
        var findings = new List<Finding>();
        var logFiles = RepositoryFileScanner.FindFiles(repoPath, "*.log", "*.txt")
            .Where(f => f.Contains("log", StringComparison.OrdinalIgnoreCase));
        
        foreach (var file in logFiles)
        {
            try
            {
                var lines = File.ReadAllLines(file);
                
                for (var i = 0; i < lines.Length; i++)
                {
                    var line = lines[i];
                    
                    foreach (var pattern in ThreatPatterns)
                    {
                        if (line.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                        {
                            findings.Add(CreateFinding(context, file, i + 1, pattern));
                            break; // Only report once per line
                        }
                    }
                }
            }
            catch { }
        }
        
        return findings;
    }

    private Finding CreateFinding(SecurityCheckContext context, string file, int lineNumber, string pattern)
    {
        return FindingFactory.Create(
            context.Assessment.AssessmentId,
            Metadata.Id,
            targetDisplay: Path.GetFileName(file),
            category: CheckCategory.Configuration,
            title: "Potential Threat Detected in Logs",
            description: $"Threat pattern '{pattern}' detected in log file at line {lineNumber}.",
            severity: Severity.High,
            confidence: ConfidenceLevel.Medium,
            exploitabilityIndicator: true,
            businessImpact: BusinessImpactLevel.Severe,
            whyItMatters: "Threats detected in logs may indicate active attacks or security incidents.",
            technicalExplanation: $"Threat pattern '{pattern}' found in {file} at line {lineNumber}.",
            remediation: new RemediationGuidance(
                "Investigate and respond to detected threats.",
                [
                    "Review the log entries for more context.",
                    "Implement threat detection and response procedures.",
                    "Consider blocking suspicious IP addresses or user agents."
                ],
                []),
            fingerprintComponents: new FingerprintComponents(
                Metadata.Id,
                Path.GetFileName(file),
                $"{file}|{lineNumber}|{pattern}",
                "ThreatDetection"),
            assetReference: file);
    }
}
