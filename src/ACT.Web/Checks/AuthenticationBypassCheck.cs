using ACT.Contracts;
using ACT.Network;

namespace ACT.Web.Checks;

/// <summary>
/// ACT-WEB-AUTHBYPASS-001: Tests for authentication bypass vulnerabilities.
/// </summary>
public sealed class AuthenticationBypassCheck : ISecurityCheck
{
    public const string CheckIdValue = "ACT-WEB-AUTHBYPASS-001";

    private readonly IEvidenceFactory _evidenceFactory;

    public AuthenticationBypassCheck(IEvidenceFactory evidenceFactory)
    {
        _evidenceFactory = evidenceFactory;
        Metadata = new SecurityCheckMetadata(
            Id: CheckId.From(CheckIdValue),
            Name: "Authentication Bypass Testing",
            Version: "1.0.0",
            Category: CheckCategory.Authorization,
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
            Description: "Tests for authentication bypass vulnerabilities.");
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

            // Test common authentication bypass techniques
            var testPaths = new[] { "/admin", "/dashboard", "/profile", "/settings" };
            
            foreach (var path in testPaths)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var testUrl = new Uri(baseUrl, path);
                
                // Test 1: Direct access without authentication
                try
                {
                    var response = await httpEngine.SendAsync(
                        SafeHttpRequest.Get(testUrl, CorrelationId.New()),
                        cancellationToken);
                    requestsMade++;
                    
                    // If we get 200 OK without authentication, it might be vulnerable
                    if (response.StatusCode == 200)
                    {
                        findings.Add(CreateFinding(context, baseUrl, testUrl.ToString(), "Direct Access Without Authentication"));
                        evidence.Add(CreateEvidence(context, baseUrl, testUrl.ToString(), response));
                    }
                }
                catch (HttpRequestException) { }
                
                // Test 2: Authentication header manipulation
                var testUri = $"{testUrl}?auth=bypass";
                try
                {
                    var response = await httpEngine.SendAsync(
                        SafeHttpRequest.Get(new Uri(testUri), CorrelationId.New()),
                        cancellationToken);
                    requestsMade++;
                    
                    if (response.StatusCode == 200)
                    {
                        findings.Add(CreateFinding(context, baseUrl, testUri, "Authentication Header Manipulation"));
                        evidence.Add(CreateEvidence(context, baseUrl, testUri, response));
                    }
                }
                catch (HttpRequestException) { }
            }

            return new SecurityCheckResult(
                Metadata.Id,
                CheckExecutionStatus.Completed,
                startedUtc,
                DateTimeOffset.UtcNow,
                findings,
                evidence,
                findings.Count > 0 ? $"Found {findings.Count} potential authentication bypass vulnerabilities" : null,
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
                $"Authentication bypass check failed: {ex.Message}");
        }
    }

    private Finding CreateFinding(SecurityCheckContext context, Uri baseUrl, string testUrl, string technique)
    {
        return FindingFactory.Create(
            context.Assessment.AssessmentId,
            Metadata.Id,
            targetDisplay: baseUrl.Host,
            category: CheckCategory.Authorization,
            title: "Potential Authentication Bypass Vulnerability",
            description: $"Authentication bypass detected using technique: {technique}.",
            severity: Severity.Critical,
            confidence: ConfidenceLevel.Medium,
            exploitabilityIndicator: true,
            businessImpact: BusinessImpactLevel.Severe,
            whyItMatters: "Authentication bypass allows attackers to access protected resources without proper credentials.",
            technicalExplanation: $"Response indicated potential authentication bypass at {testUrl}.",
            remediation: new RemediationGuidance(
                "Implement proper authentication and authorization checks.",
                [
                    "Verify authentication status on every request.",
                    "Use server-side session management.",
                    "Implement proper authorization checks for each resource."
                ],
                []),
            fingerprintComponents: new FingerprintComponents(
                Metadata.Id,
                baseUrl.Host,
                $"{testUrl}|{technique}",
                "AuthBypass"),
            assetReference: baseUrl.ToString());
    }

    private EvidenceItem CreateEvidence(SecurityCheckContext context, Uri baseUrl, string testUrl, SafeHttpResponse response)
    {
        var correlation = CorrelationId.New();
        
        return _evidenceFactory.Create(
            Guid.NewGuid(),
            EvidenceKind.HttpResponseMetadata,
            "http-response",
            $"Auth bypass test: {testUrl}",
            Metadata.Id,
            correlation,
            new Dictionary<string, string>
            {
                ["url"] = testUrl,
                ["statusCode"] = response.StatusCode.ToString()
            });
    }
}
