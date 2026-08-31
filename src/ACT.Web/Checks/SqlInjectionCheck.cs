using ACT.Contracts;
using ACT.Network;

namespace ACT.Web.Checks;

/// <summary>
/// ACT-WEB-SQLI-001: Detects potential SQL injection vulnerabilities.
/// </summary>
public sealed class SqlInjectionCheck : ISecurityCheck
{
    public const string CheckIdValue = "ACT-WEB-SQLI-001";

    private readonly IEvidenceFactory _evidenceFactory;

    private static readonly string[] TestPayloads =
    [
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "1; WAITFOR DELAY '0:0:2'--",
        "' AND 1=CONVERT(int,(SELECT @@version))--"
    ];

    private static readonly string[] ErrorPatterns =
    [
        "SQL syntax",
        "MySQL syntax",
        "PostgreSQL error",
        "SQLite error",
        "ORA-00933",
        "ORA-00936",
        "Unclosed quotation mark",
        "quoted string not properly terminated",
        "syntax error at or near",
        "Warning: mysql_",
        "Warning: pg_",
        "System.Data.SqlClient",
        "Microsoft.Data.SqlClient",
        "Npgsql"
    ];

    public SqlInjectionCheck(IEvidenceFactory evidenceFactory)
    {
        _evidenceFactory = evidenceFactory;
        Metadata = new SecurityCheckMetadata(
            Id: CheckId.From(CheckIdValue),
            Name: "SQL Injection Detection",
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
            NetworkBehavior: new NetworkBehaviorProfile(1, 20, true, false, false),
            EvidenceTypesProduced: [EvidenceKind.HttpResponseMetadata],
            SupportsRemediation: true,
            SupportsRegressionTest: true,
            Description: "Detects SQL injection vulnerabilities by analyzing error responses to test payloads.");
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

            var testPaths = new[] { "/", "/search", "/login", "/api", "/product", "/user" };
            
            foreach (var path in testPaths)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var testUrl = new Uri(baseUrl, path);
                
                foreach (var param in new[] { "q", "query", "id", "user", "search" })
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
                            
                            foreach (var pattern in ErrorPatterns)
                            {
                                if (responseBody.Contains(pattern, StringComparison.OrdinalIgnoreCase))
                                {
                                    findings.Add(CreateFinding(context, baseUrl, testUri, param, payload, pattern));
                                    evidence.Add(CreateEvidence(context, baseUrl, testUri, response));
                                    break;
                                }
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
                findings.Count > 0 ? $"Found {findings.Count} potential SQL injection vulnerabilities" : null,
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
                $"SQL injection check failed: {ex.Message}");
        }
    }

    private Finding CreateFinding(SecurityCheckContext context, Uri baseUrl, string testUrl, string param, string payload, string errorPattern)
    {
        return FindingFactory.Create(
            context.Assessment.AssessmentId,
            Metadata.Id,
            targetDisplay: baseUrl.Host,
            category: CheckCategory.Http,
            title: "Potential SQL Injection Vulnerability",
            description: $"SQL error detected when testing parameter '{param}' with injection payload.",
            severity: Severity.Critical,
            confidence: ConfidenceLevel.Medium,
            exploitabilityIndicator: true,
            businessImpact: BusinessImpactLevel.Severe,
            whyItMatters: "SQL injection allows attackers to read, modify, or delete database contents.",
            technicalExplanation: $"Response contained SQL error pattern '{errorPattern}' when testing parameter '{param}'.",
            remediation: new RemediationGuidance(
                "Use parameterized queries or prepared statements for all database operations.",
                [
                    "Implement parameterized queries using your ORM or database library's prepared statement API.",
                    "Validate and sanitize all user input before using it in database queries.",
                    "Use least privilege database accounts."
                ],
                []),
            fingerprintComponents: new FingerprintComponents(
                Metadata.Id,
                baseUrl.Host,
                $"{testUrl}|{param}|{errorPattern}",
                "SqlInjection"),
            assetReference: baseUrl.ToString());
    }

    private EvidenceItem CreateEvidence(SecurityCheckContext context, Uri baseUrl, string testUrl, SafeHttpResponse response)
    {
        var correlation = CorrelationId.New();
        
        return _evidenceFactory.Create(
            Guid.NewGuid(),
            EvidenceKind.HttpResponseMetadata,
            "http-response",
            $"SQL injection test: {testUrl}",
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
