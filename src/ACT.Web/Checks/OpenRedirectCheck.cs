using ACT.Contracts;
using ACT.Network;

namespace ACT.Web.Checks;

/// <summary>
/// ACT-WEB-REDIRECT-001: Detects open redirect vulnerabilities.
/// </summary>
public sealed class OpenRedirectCheck : ISecurityCheck
{
    public const string CheckIdValue = "ACT-WEB-REDIRECT-001";

    private readonly IEvidenceFactory _evidenceFactory;

    private static readonly string[] TestUrls =
    [
        "https://evil.com",
        "https://attacker.org",
        "javascript:alert('xss')"
    ];

    public OpenRedirectCheck(IEvidenceFactory evidenceFactory)
    {
        _evidenceFactory = evidenceFactory;
        Metadata = new SecurityCheckMetadata(
            Id: CheckId.From(CheckIdValue),
            Name: "Open Redirect Detection",
            Version: "1.0.0",
            Category: CheckCategory.Http,
            MaxEmittingSeverity: Severity.Medium,
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
            Description: "Detects open redirect vulnerabilities.");
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

            // Test common redirect parameters
            var testPaths = new[] { "/", "/redirect", "/go", "/return" };
            
            foreach (var path in testPaths)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var testUrl = new Uri(baseUrl, path);
                
                foreach (var param in new[] { "url", "redirect", "return", "next", "dest" })
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    
                    foreach (var testTarget in TestUrls)
                    {
                        cancellationToken.ThrowIfCancellationRequested();
                        var testUri = $"{testUrl}?{param}={Uri.EscapeDataString(testTarget)}";
                        
                        try
                        {
                            var response = await httpEngine.SendAsync(
                                SafeHttpRequest.Get(new Uri(testUri), CorrelationId.New()),
                                cancellationToken);
                            requestsMade++;
                            
                            // Check if we're redirected to the test URL
                            if (response.FinalUri.Host.Equals("evil.com", StringComparison.OrdinalIgnoreCase) ||
                                response.FinalUri.Host.Equals("attacker.org", StringComparison.OrdinalIgnoreCase))
                            {
                                findings.Add(CreateFinding(context, baseUrl, testUri, param, testTarget));
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
                findings.Count > 0 ? $"Found {findings.Count} potential open redirect vulnerabilities" : null,
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
                $"Open redirect check failed: {ex.Message}");
        }
    }

    private Finding CreateFinding(SecurityCheckContext context, Uri baseUrl, string testUrl, string param, string testTarget)
    {
        return FindingFactory.Create(
            context.Assessment.AssessmentId,
            Metadata.Id,
            targetDisplay: baseUrl.Host,
            category: CheckCategory.Http,
            title: "Potential Open Redirect Vulnerability",
            description: $"Open redirect detected in parameter '{param}' with target '{testTarget}'.",
            severity: Severity.Medium,
            confidence: ConfidenceLevel.Medium,
            exploitabilityIndicator: true,
            businessImpact: BusinessImpactLevel.Significant,
            whyItMatters: "Open redirects allow attackers to redirect users to malicious sites.",
            technicalExplanation: $"Response redirected to external URL when testing parameter '{param}'.",
            remediation: new RemediationGuidance(
                "Validate redirect URLs against an allowlist.",
                [
                    "Use an allowlist of permitted redirect URLs.",
                    "Validate that redirect URLs are relative or from trusted domains.",
                    "Encode redirect URLs to prevent manipulation."
                ],
                []),
            fingerprintComponents: new FingerprintComponents(
                Metadata.Id,
                baseUrl.Host,
                $"{testUrl}|{param}",
                "OpenRedirect"),
            assetReference: baseUrl.ToString());
    }

    private EvidenceItem CreateEvidence(SecurityCheckContext context, Uri baseUrl, string testUrl, SafeHttpResponse response)
    {
        var correlation = CorrelationId.New();
        
        return _evidenceFactory.Create(
            Guid.NewGuid(),
            EvidenceKind.HttpResponseMetadata,
            "http-response",
            $"Open redirect test: {testUrl}",
            Metadata.Id,
            correlation,
            new Dictionary<string, string>
            {
                ["url"] = testUrl,
                ["statusCode"] = response.StatusCode.ToString(),
                ["finalUrl"] = response.FinalUri.ToString()
            });
    }
}
