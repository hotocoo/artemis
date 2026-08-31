using ACT.Contracts;
using ACT.Network;

namespace ACT.Web.Checks;

/// <summary>
/// ACT-WEB-XSS-001: Detects potential Cross-Site Scripting (XSS) vulnerabilities.
/// </summary>
public sealed class CrossSiteScriptingCheck : ISecurityCheck
{
    public const string CheckIdValue = "ACT-WEB-XSS-001";

    private readonly IEvidenceFactory _evidenceFactory;

    private static readonly string[] TestPayloads =
    [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "<svg onload=alert('xss')>",
        "javascript:alert('xss')",
        "<body onload=alert('xss')>"
    ];

    public CrossSiteScriptingCheck(IEvidenceFactory evidenceFactory)
    {
        _evidenceFactory = evidenceFactory;
        Metadata = new SecurityCheckMetadata(
            Id: CheckId.From(CheckIdValue),
            Name: "Cross-Site Scripting Detection",
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
            NetworkBehavior: new NetworkBehaviorProfile(1, 15, true, false, false),
            EvidenceTypesProduced: [EvidenceKind.HttpResponseMetadata],
            SupportsRemediation: true,
            SupportsRegressionTest: true,
            Description: "Detects XSS vulnerabilities by testing if payloads are reflected without encoding.");
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

            var testPaths = new[] { "/", "/search", "/q", "/query", "/s" };
            
            foreach (var path in testPaths)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var testUrl = new Uri(baseUrl, path);
                
                foreach (var param in new[] { "q", "query", "search", "s", "term" })
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
                            
                            if (IsPayloadReflected(responseBody, payload))
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
                findings.Count > 0 ? $"Found {findings.Count} potential XSS vulnerabilities" : null,
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
                $"XSS check failed: {ex.Message}");
        }
    }

    private static bool IsPayloadReflected(string responseBody, string payload)
    {
        if (!responseBody.Contains(payload, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var encodedPayload = System.Web.HttpUtility.HtmlEncode(payload);
        if (responseBody.Contains(encodedPayload, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return true;
    }

    private Finding CreateFinding(SecurityCheckContext context, Uri baseUrl, string testUrl, string param, string payload)
    {
        return FindingFactory.Create(
            context.Assessment.AssessmentId,
            Metadata.Id,
            targetDisplay: baseUrl.Host,
            category: CheckCategory.Http,
            title: "Potential Cross-Site Scripting (XSS) Vulnerability",
            description: $"XSS payload reflected in response without proper encoding for parameter '{param}'.",
            severity: Severity.High,
            confidence: ConfidenceLevel.Medium,
            exploitabilityIndicator: true,
            businessImpact: BusinessImpactLevel.Significant,
            whyItMatters: "XSS allows attackers to execute arbitrary JavaScript in victims' browsers.",
            technicalExplanation: $"The payload was reflected in the response without HTML encoding.",
            remediation: new RemediationGuidance(
                "Encode all user input before rendering it in HTML contexts.",
                [
                    "Use context-appropriate output encoding.",
                    "Implement Content Security Policy (CSP) headers.",
                    "Use modern frameworks that automatically encode output."
                ],
                []),
            fingerprintComponents: new FingerprintComponents(
                Metadata.Id,
                baseUrl.Host,
                $"{testUrl}|{param}",
                "XssReflection"),
            assetReference: baseUrl.ToString());
    }

    private EvidenceItem CreateEvidence(SecurityCheckContext context, Uri baseUrl, string testUrl, SafeHttpResponse response)
    {
        var correlation = CorrelationId.New();
        
        return _evidenceFactory.Create(
            Guid.NewGuid(),
            EvidenceKind.HttpResponseMetadata,
            "http-response",
            $"XSS test: {testUrl}",
            Metadata.Id,
            correlation,
            new Dictionary<string, string>
            {
                ["url"] = testUrl,
                ["statusCode"] = response.StatusCode.ToString(),
                ["contentType"] = response.ContentType ?? "unknown"
            });
    }
}
