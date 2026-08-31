using ACT.Contracts;
using ACT.Network;

namespace ACT.Web.Checks;

/// <summary>
/// ACT-WEB-PATHTRAV-001: Detects potential path traversal vulnerabilities.
/// </summary>
public sealed class PathTraversalCheck : ISecurityCheck
{
    public const string CheckIdValue = "ACT-WEB-PATHTRAV-001";

    private readonly IEvidenceFactory _evidenceFactory;

    private static readonly string[] TestPayloads =
    [
        "../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%2f..%2f..%2fetc%2fpasswd"
    ];

    public PathTraversalCheck(IEvidenceFactory evidenceFactory)
    {
        _evidenceFactory = evidenceFactory;
        Metadata = new SecurityCheckMetadata(
            Id: CheckId.From(CheckIdValue),
            Name: "Path Traversal Detection",
            Version: "1.0.0",
            Category: CheckCategory.Http,
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
            Description: "Detects path traversal vulnerabilities by testing directory traversal payloads.");
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

            var testPaths = new[] { "/", "/file", "/download", "/view", "/image" };
            
            foreach (var path in testPaths)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var testUrl = new Uri(baseUrl, path);
                
                foreach (var param in new[] { "file", "path", "doc", "page", "img" })
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
                            
                            if (responseBody.Contains("root:", StringComparison.OrdinalIgnoreCase) ||
                                responseBody.Contains("daemon:", StringComparison.OrdinalIgnoreCase))
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
                findings.Count > 0 ? $"Found {findings.Count} potential path traversal vulnerabilities" : null,
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
                $"Path traversal check failed: {ex.Message}");
        }
    }

    private Finding CreateFinding(SecurityCheckContext context, Uri baseUrl, string testUrl, string param, string payload)
    {
        return FindingFactory.Create(
            context.Assessment.AssessmentId,
            Metadata.Id,
            targetDisplay: baseUrl.Host,
            category: CheckCategory.Http,
            title: "Potential Path Traversal Vulnerability",
            description: $"Sensitive file content accessed via path traversal in parameter '{param}'.",
            severity: Severity.High,
            confidence: ConfidenceLevel.Medium,
            exploitabilityIndicator: true,
            businessImpact: BusinessImpactLevel.Severe,
            whyItMatters: "Path traversal allows attackers to read arbitrary files on the server.",
            technicalExplanation: $"Response contained sensitive file content when testing parameter '{param}'.",
            remediation: new RemediationGuidance(
                "Validate and sanitize file paths, use allowlists for accessible files.",
                [
                    "Validate file paths against an allowlist of permitted files.",
                    "Normalize and canonicalize file paths before access.",
                    "Use virtual file systems or abstractions to prevent direct path access."
                ],
                []),
            fingerprintComponents: new FingerprintComponents(
                Metadata.Id,
                baseUrl.Host,
                $"{testUrl}|{param}",
                "PathTraversal"),
            assetReference: baseUrl.ToString());
    }

    private EvidenceItem CreateEvidence(SecurityCheckContext context, Uri baseUrl, string testUrl, SafeHttpResponse response)
    {
        var correlation = CorrelationId.New();
        
        return _evidenceFactory.Create(
            Guid.NewGuid(),
            EvidenceKind.HttpResponseMetadata,
            "http-response",
            $"Path traversal test: {testUrl}",
            Metadata.Id,
            correlation,
            new Dictionary<string, string>
            {
                ["url"] = testUrl,
                ["statusCode"] = response.StatusCode.ToString()
            });
    }
}
