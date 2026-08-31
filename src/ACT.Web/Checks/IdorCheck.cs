using ACT.Contracts;
using ACT.Network;

namespace ACT.Web.Checks;

/// <summary>
/// ACT-WEB-IDOR-001: Detects Insecure Direct Object Reference vulnerabilities.
/// </summary>
public sealed class IdorCheck : ISecurityCheck
{
    public const string CheckIdValue = "ACT-WEB-IDOR-001";

    private readonly IEvidenceFactory _evidenceFactory;

    public IdorCheck(IEvidenceFactory evidenceFactory)
    {
        _evidenceFactory = evidenceFactory;
        Metadata = new SecurityCheckMetadata(
            Id: CheckId.From(CheckIdValue),
            Name: "IDOR Detection",
            Version: "1.0.0",
            Category: CheckCategory.Authorization,
            MaxEmittingSeverity: Severity.High,
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
            Description: "Detects Insecure Direct Object Reference (IDOR) vulnerabilities.");
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

            // Test common IDOR patterns
            var testPaths = new[] { "/user", "/profile", "/account", "/settings" };
            
            foreach (var path in testPaths)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var testUrl = new Uri(baseUrl, path);
                
                // Test with different object IDs
                var testUrls = new[]
                {
                    $"{testUrl}/123",
                    $"{testUrl}/456",
                    $"{testUrl}/789"
                };
                
                foreach (var testUri in testUrls)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    try
                    {
                        var response = await httpEngine.SendAsync(
                            SafeHttpRequest.Get(new Uri(testUri), CorrelationId.New()),
                            cancellationToken);
                        requestsMade++;
                        
                        // If we can access different object IDs without proper authorization, it might be vulnerable
                        if (response.StatusCode == 200)
                        {
                            findings.Add(CreateFinding(context, baseUrl, testUri));
                            evidence.Add(CreateEvidence(context, baseUrl, testUri, response));
                            break; // Only report once per path
                        }
                    }
                    catch (HttpRequestException) { }
                }
            }

            return new SecurityCheckResult(
                Metadata.Id,
                CheckExecutionStatus.Completed,
                startedUtc,
                DateTimeOffset.UtcNow,
                findings,
                evidence,
                findings.Count > 0 ? $"Found {findings.Count} potential IDOR vulnerabilities" : null,
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
                $"IDOR check failed: {ex.Message}");
        }
    }

    private Finding CreateFinding(SecurityCheckContext context, Uri baseUrl, string testUrl)
    {
        return FindingFactory.Create(
            context.Assessment.AssessmentId,
            Metadata.Id,
            targetDisplay: baseUrl.Host,
            category: CheckCategory.Authorization,
            title: "Potential Insecure Direct Object Reference (IDOR) Vulnerability",
            description: $"Object reference access detected without proper authorization at {testUrl}.",
            severity: Severity.High,
            confidence: ConfidenceLevel.Medium,
            exploitabilityIndicator: true,
            businessImpact: BusinessImpactLevel.Severe,
            whyItMatters: "IDOR allows attackers to access other users' data by manipulating object references.",
            technicalExplanation: $"Response indicated potential IDOR vulnerability at {testUrl}.",
            remediation: new RemediationGuidance(
                "Implement proper authorization checks for object access.",
                [
                    "Verify user authorization before accessing objects.",
                    "Use indirect reference maps instead of direct object IDs.",
                    "Implement proper access control lists."
                ],
                []),
            fingerprintComponents: new FingerprintComponents(
                Metadata.Id,
                baseUrl.Host,
                testUrl,
                "IdorVulnerability"),
            assetReference: baseUrl.ToString());
    }

    private EvidenceItem CreateEvidence(SecurityCheckContext context, Uri baseUrl, string testUrl, SafeHttpResponse response)
    {
        var correlation = CorrelationId.New();
        
        return _evidenceFactory.Create(
            Guid.NewGuid(),
            EvidenceKind.HttpResponseMetadata,
            "http-response",
            $"IDOR test: {testUrl}",
            Metadata.Id,
            correlation,
            new Dictionary<string, string>
            {
                ["url"] = testUrl,
                ["statusCode"] = response.StatusCode.ToString()
            });
    }
}
