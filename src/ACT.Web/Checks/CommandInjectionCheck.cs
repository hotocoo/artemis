using ACT.Contracts;
using ACT.Network;

namespace ACT.Web.Checks;

/// <summary>
/// ACT-WEB-CMDINJ-001: Detects potential command injection vulnerabilities.
/// </summary>
public sealed class CommandInjectionCheck : ISecurityCheck
{
    public const string CheckIdValue = "ACT-WEB-CMDINJ-001";

    private readonly IEvidenceFactory _evidenceFactory;

    private static readonly string[] TestPayloads =
    [
        "; whoami",
        "| whoami",
        "`whoami`",
        "$(whoami)"
    ];

    public CommandInjectionCheck(IEvidenceFactory evidenceFactory)
    {
        _evidenceFactory = evidenceFactory;
        Metadata = new SecurityCheckMetadata(
            Id: CheckId.From(CheckIdValue),
            Name: "Command Injection Detection",
            Version: "1.0.0",
            Category: CheckCategory.Http,
            MaxEmittingSeverity: Severity.Critical,
            SafetyLevel: SafetyLevel.ActiveNonDestructive,
            RequiredPermissions: PermissionRequirement.OutboundNetworkToLocalTargets,
            RequiredProtocols: new HashSet<ProtocolKind> { ProtocolKind.Http, ProtocolKind.Https },
            SupportedTargetTypes: new HashSet<TargetTypeKind>
            {
                TargetTypeKind.Url,
                TargetTypeKind.Domain,
                TargetTypeKind.Hostname,
                TargetTypeKind.Localhost
            },
            NetworkBehavior: new NetworkBehaviorProfile(1, 10, true, false, false),
            EvidenceTypesProduced: [EvidenceKind.HttpResponseMetadata],
            SupportsRemediation: true,
            SupportsRegressionTest: true,
            Description: "Detects command injection vulnerabilities by analyzing responses to test payloads.");
        Metadata.Validate();
    }

    public SecurityCheckMetadata Metadata { get; }

    public async Task<SecurityCheckResult> ExecuteAsync(SecurityCheckContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var startedUtc = DateTimeOffset.UtcNow;

        if (context.Asset.Kind is not AssetKind.Url)
        {
            return SecurityCheckResult.Empty(
                Metadata, startedUtc, CheckExecutionStatus.Skipped_NotApplicable,
                "The asset is not a web target.");
        }

        try
        {
            var baseUrl = context.BaseUrl ?? new Uri(context.Asset.CanonicalTarget);
            var httpEngine = context.Assessment.Http;
            
            var findings = new List<Finding>();
            var evidence = new List<EvidenceItem>();
            var requestsMade = 0;

            var testPaths = new[] { "/", "/exec", "/run", "/command" };
            
            foreach (var path in testPaths)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var testUrl = new Uri(baseUrl, path);
                
                foreach (var param in new[] { "cmd", "command", "exec", "run" })
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    foreach (var payload in TestPayloads)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var testUri = $"{testUrl}?{param}={Uri.EscapeDataString(payload)}";
                        
                        try
                        {
                            var response = await httpEngine.SendAsync(
                                SafeHttpRequest.Get(new Uri(testUri), CorrelationId.New()),
                                cancellationToken);
                            requestsMade++;
                            
                            var responseBody = response.BodyAsText();
                            
                            if (responseBody.Contains("root", StringComparison.OrdinalIgnoreCase) ||
                                responseBody.Contains("uid=", StringComparison.OrdinalIgnoreCase))
                            {
                                findings.Add(CreateFinding(context, baseUrl, testUri, param, payload));
                                evidence.Add(CreateEvidence(context, baseUrl, testUri, response));
                                break;
                            }
                        }
                        catch (HttpRequestException) { }
                    }
                }
            }

            return new SecurityCheckResult(
                Metadata.Id,
                CheckExecutionStatus.Completed,
                startedUtc,
                DateTimeOffset.UtcNow,
                findings,
                evidence,
                findings.Count > 0 ? $"Found {findings.Count} potential command injection vulnerabilities" : null,
                RequestCount: requestsMade,
                TargetsExamined: testPaths.Length);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            return SecurityCheckResult.Empty(
                Metadata, startedUtc, CheckExecutionStatus.Failed_FailedClosed,
                $"Command injection check failed: {ex.Message}");
        }
    }

    private Finding CreateFinding(SecurityCheckContext context, Uri baseUrl, string testUrl, string param, string payload)
    {
        return FindingFactory.Create(
            context.Assessment.AssessmentId,
            Metadata.Id,
            targetDisplay: baseUrl.Host,
            category: CheckCategory.Http,
            title: "Potential Command Injection Vulnerability",
            description: $"Command execution detected when testing parameter '{param}'.",
            severity: Severity.Critical,
            confidence: ConfidenceLevel.Medium,
            exploitabilityIndicator: true,
            businessImpact: BusinessImpactLevel.Severe,
            whyItMatters: "Command injection allows attackers to execute arbitrary system commands.",
            technicalExplanation: $"Response contained command execution indicators when testing parameter '{param}'.",
            remediation: new RemediationGuidance(
                "Use parameterized commands and validate all input.",
                [
                    "Use system calls with parameter arrays instead of shell strings.",
                    "Validate and sanitize all user input.",
                    "Use least privilege accounts for command execution."
                ],
                []),
            fingerprintComponents: new FingerprintComponents(
                Metadata.Id,
                baseUrl.Host,
                $"{testUrl}|{param}",
                "CommandInjection"),
            assetReference: baseUrl.ToString());
    }

    private EvidenceItem CreateEvidence(SecurityCheckContext context, Uri baseUrl, string testUrl, SafeHttpResponse response)
    {
        var correlation = CorrelationId.New();
        
        return _evidenceFactory.Create(
            Guid.NewGuid(),
            EvidenceKind.HttpResponseMetadata,
            "http-response",
            $"Command injection test: {testUrl}",
            Metadata.Id,
            correlation,
            new Dictionary<string, string>
            {
                ["url"] = testUrl,
                ["statusCode"] = response.StatusCode.ToString()
            });
    }
}
