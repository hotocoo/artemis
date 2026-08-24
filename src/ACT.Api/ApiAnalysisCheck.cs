
using System.Net.Http;
using ACT.Contracts;

namespace ACT.Api;

/// <summary>
/// Static analysis of an operator-provided OpenAPI/Swagger document. Produces findings about
/// authentication declarations, error documentation, schema hygiene, and object-identifier
/// surfaces worth verifying with EXPLICIT fixtures. Never brute-forces anything.
/// </summary>
public sealed class ApiSurfaceAnalysisCheck : ISecurityCheck
{
    public const string CheckIdValue = "ACT-API-SURFACE-001";

    private readonly Func<string> _documentLoader;
    private readonly Uri _baseUrl;

    /// <summary>documentLoader returns the raw JSON; baseUrl is the API origin under scope.</summary>
    public ApiSurfaceAnalysisCheck(Func<string> documentLoader, Uri baseUrl)
    {
        _documentLoader = documentLoader ?? throw ActException.FailClosed(
            ErrorCategory.Configuration, "An OpenAPI document loader is required.",
            "ApiSurfaceAnalysisCheck constructed without a loader.");
        _baseUrl = baseUrl;
    }

    public SecurityCheckMetadata Metadata { get; } = new(
        CheckId.From(CheckIdValue),
        "API surface security analysis",
        "1.0.0",
        CheckCategory.Api,
        Severity.Medium,
        SafetyLevel.LocalOnly,
        PermissionRequirement.None,
        new HashSet<ProtocolKind>(),
        new HashSet<TargetTypeKind> { TargetTypeKind.Url, TargetTypeKind.TestEnvironment },
        new NetworkBehaviorProfile(0, 0, false, false, false),
        [EvidenceKind.ConfigurationLocation],
        SupportsRemediation: true,
        SupportsRegressionTest: true,
        "Analyzes the documented API surface for missing authentication declarations, weak schemas, and undocumented behavior.");

    public Task<SecurityCheckResult> ExecuteAsync(SecurityCheckContext context, CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var surface = ApiSurfaceParser.Parse(_documentLoader());
        var findings = new List<Finding>();
        var evidence = new List<EvidenceItem>();

        void Add(string findingClass, string resource, string title, string description, Severity severity,
            ConfidenceLevel confidence, string why, string how, RemediationGuidance remediation)
        {
            findings.Add(FindingFactory.Create(
                context.Assessment.AssessmentId, Metadata.Id, _baseUrl.ToString(), CheckCategory.Api,
                title, description, severity, confidence, exploitabilityIndicator: false,
                BusinessImpactLevel.Limited, why, how, remediation,
                new FingerprintComponents(Metadata.Id, _baseUrl.ToString(), resource, findingClass)));
        }

        // 1. Authentication declaration coverage.
        var unauthenticated = surface.Operations
            .Where(op => op.Method is not ("get" or "head" or "options"))
            .Where(op => op.HasSecurityOverride ? !op.SecurityRequiresAuth : !surface.HasGlobalSecurity)
            .ToList();
        if (surface.DeclaredSecuritySchemeCount == 0)
        {
            Add("no-security-schemes", "/",
                "API specification declares no security schemes",
                "The document defines no security schemes at all, so every endpoint is documented as anonymous.",
                Severity.Medium, ConfidenceLevel.High,
                "Undocumented authentication requirements make access-control review impossible and invite accidental exposure.",
                "The components.securitySchemes (or securityDefinitions) section was absent or empty.",
                new RemediationGuidance("Declare security schemes and apply them per operation.",
                    ["Define schemes (e.g. bearerAuth) under components/securitySchemes.",
                     "Apply global security and per-operation overrides where anonymous access is intended."],
                    ["https://spec.openapis.org/oas/v3.1.0#security-scheme-object"]));
        }
        if (unauthenticated.Count > 0)
        {
            Add("unauthenticated-mutations", string.Join(",", unauthenticated.Select(o => o.Path).Distinct().OrderBy(p => p, StringComparer.Ordinal)),
                $"{unauthenticated.Count} mutating operation(s) lack authentication declarations",
                "Write operations are documented without any security requirement.",
                Severity.Medium, ConfidenceLevel.Medium,
                "Mutating endpoints without declared authentication may be exposed anonymously in practice.",
                "Operations with methods POST/PUT/PATCH/DELETE resolved to no effective security requirement.",
                new RemediationGuidance("Require authentication for all mutating operations unless deliberately public.",
                    ["Add security requirements to each mutating operation.", "Document intentionally-public endpoints explicitly with security: []"]),
                    ["https://owasp.org/www-project-api-security/"]));
        }

        // 2. Object-identifier surfaces: candidates for FIXTURE-driven authz verification.
        var idPaths = surface.Operations
            .Where(op => op.ParameterNames.Any(p =>
                p.Equals("id", StringComparison.OrdinalIgnoreCase) ||
                p.EndsWith("Id", StringComparison.OrdinalIgnoreCase)))
            .Select(op => op.Method.ToUpperInvariant() + " " + op.Path)
            .Distinct()
            .OrderBy(s => s, StringComparer.Ordinal)
            .ToList();
        if (idPaths.Count > 0)
        {
            var finding = FindingFactory.Create(
                context.Assessment.AssessmentId, Metadata.Id, _baseUrl.ToString(), CheckCategory.Api,
                $"{idPaths.Count} operation(s) address objects by identifier",
                "Object-addressing endpoints detected: " + string.Join("; ", idPaths.Take(12)) +
                ". These are candidate surfaces for broken object-level authorization.",
                Severity.Informational, ConfidenceLevel.High, exploitabilityIndicator: false,
                BusinessImpactLevel.Limited,
                "BOLA/IDOR remains the top API risk class; identifiers alone must not grant access.",
                "Path or query parameters named id/*Id indicate direct object references.",
                new RemediationGuidance(
                    "Verify authorization on these operations using explicit test fixtures only.",
                    ["Provide principals from at least two tenants as fixtures.", "Run Artemis authorization checks; never probe with guessed identifiers."],
                    ["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"]));
            findings.Add(finding);
        }

        // 3. Sensitive field exposure in response schemas.
        var sensitiveTokens = new[] { "password", "secret", "token", "ssn", "apikey", "api_key", "privatekey" };
        var exposedFields = surface.Operations
            .SelectMany(op => op.ResponseSchemaFieldNames
                .Where(f => sensitiveTokens.Any(t => f.Contains(t, StringComparison.OrdinalIgnoreCase)))
                .Select(f => f))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        if (exposedFields.Count > 0)
        {
            Add("sensitive-response-fields", string.Join(",", exposedFields.OrderBy(f => f, StringComparer.Ordinal)),
                "Response schemas expose sensitive-named fields",
                "Fields such as " + string.Join(", ", exposedFields.Take(8)) +
                " appear in response payloads without writeOnly markers.",
                Severity.Medium, ConfidenceLevel.Medium,
                "Secret-shaped fields in responses frequently leak credentials or personal data.",
                "Response schema property names matched sensitive token list.",
                new RemediationGuidance("Remove secrets from responses or mark fields writeOnly/readOnly appropriately.",
                    ["Return derived views instead of domain entities.", "Add explicit DTOs for responses."],
                    ["https://owasp.org/www-project-api-security/"]));
        }

        // 4. Undocumented failure modes on mutations.
        var undocumentedFailures = surface.Operations
            .Where(op => op.Method is "post" or "put" or "patch" or "delete")
            .Where(op => !op.DocumentsErrorResponses)
            .Count();
        if (undocumentedFailures > 0)
        {
            Add("undocumented-error-responses", "operations:" + undocumentedFailures,
                $"{undocumentedFailures} mutating operation(s) document no 4xx/5xx responses",
                "Error behavior is unspecified, hiding authorization failures from contract tests.",
                Severity.Low, ConfidenceLevel.High,
                "Authorization regressions hide behind undocumented status codes.",
                "No responses entries starting with 4 or 5 were declared.",
                new RemediationGuidance("Document expected 400/401/403/404 responses for every mutation.",
                    ["Enumerate realistic failure codes per operation.", "Generate regression tests from them."],
                    []));
        }

        evidence.Add(context.Assessment.Evidence.Create(
            Guid.Empty, EvidenceKind.ConfigurationLocation, "openapi.operations", 
            surface.Operations.Count.ToString(), Metadata.Id, context.Correlation ?? CorrelationId.New(),
            new Dictionary<string, string>
            {
                ["title"] = surface.Title,
                ["version"] = surface.Version,
                ["swagger2"] = surface.IsSwagger2 ? "true" : "false"
            }));

        return Task.FromResult(new SecurityCheckResult(
            Metadata.Id, CheckExecutionStatus.Completed, started, DateTimeOffset.UtcNow,
            findings, evidence, null, RequestCount: 0, TargetsExamined: 1));
    }
}

/// <summary>
/// Executes ONLY operator-supplied access expectations against the live API through the safe
/// HTTP engine. Without fixtures this check reports Skipped_NotApplicable — it never guesses.
/// </summary>
public sealed class ApiBehavioralCheck : ISecurityCheck
{
    public const string CheckIdValue = "ACT-API-BEHAVIOR-001";

    public SecurityCheckMetadata Metadata { get; } = new(
        CheckId.From(CheckIdValue),
        "Fixture-driven API authorization verification",
        "1.0.0",
        CheckCategory.Authorization,
        Severity.Critical,
        SafetyLevel.ActiveNonDestructive,
        PermissionRequirement.UseProvidedTestCredentials | PermissionRequirement.OutboundNetworkToLocalTargets,
        new HashSet<ProtocolKind> { ProtocolKind.Http, ProtocolKind.Https },
        new HashSet<TargetTypeKind> { TargetTypeKind.Url, TargetTypeKind.TestEnvironment },
        new NetworkBehaviorProfile(1, 64, true, true, false),
        [EvidenceKind.HttpRequestMetadata, EvidenceKind.StatusCode],
        SupportsRemediation: true,
        SupportsRegressionTest: true,
        "Verifies explicitly configured access expectations against the live API.");

    public async Task<SecurityCheckResult> ExecuteAsync(SecurityCheckContext context, CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var fixtures = context.Assessment.Fixtures;
        if (fixtures.Expectations.Count == 0 || context.BaseUrl is null)
        {
            return SecurityCheckResult.Empty(Metadata, started, CheckExecutionStatus.Skipped_NotApplicable,
                "No access expectations configured.");
        }

        var principalById = fixtures.Principals.ToDictionary(p => p.PrincipalId, StringComparer.Ordinal);
        var objectById = fixtures.Objects.ToDictionary(o => o.ObjectId, StringComparer.Ordinal);
        var findings = new List<Finding>();

        foreach (var expectation in fixtures.Expectations)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var principal = principalById[expectation.PrincipalId];
            var obj = objectById[expectation.ObjectId];
            var path = obj.RelativePathTemplate.Replace("{id}", Uri.EscapeDataString(obj.ObjectId));
            var url = new Uri(context.BaseUrl, path);
            var method = expectation.HttpMethod.ToUpperInvariant() switch
            {
                "POST" => HttpMethod.Post,
                "PUT" => HttpMethod.Put,
                "DELETE" => HttpMethod.Delete,
                _ => HttpMethod.Get
            };

            SafeHttpResponse response;
            try
            {
                response = await context.Assessment.Http.SendAsync(new SafeHttpRequest(
                    method, url, principal.AuthenticationHeaders, null, context.Correlation), cancellationToken);
            }
            catch (ActException ex) when (ex.Category == ErrorCategory.Scope)
            {
                return SecurityCheckResult.Empty(Metadata, started, CheckExecutionStatus.Skipped_OutOfScope,
                    ex.SafeMessage);
            }

            var matched = response.StatusCode == expectation.ExpectedStatusCode;
            if (!matched)
            {
                var violated = IsDenial(expectation.ExpectedStatusCode) && IsSuccess(response.StatusCode);
                findings.Add(FindingFactory.Create(
                    context.Assessment.AssessmentId, Metadata.Id,
                    url.ToString(), CheckCategory.Authorization,
                    $"Access invariant '{expectation.InvariantName}' violated",
                    $"Expected {expectation.ExpectedStatusCode} but observed {response.StatusCode} for {method} {path} " +
                    $"as principal '{principal.PrincipalId}'.",
                    violated ? Severity.Critical : Severity.Medium,
                    ConfidenceLevel.High,
                    exploitabilityIndicator: violated,
                    BusinessImpactLevel.Significant,
                    "Broken access control exposes data across tenants and roles.",
                    $"Invariant '{expectation.InvariantName}' expected {expectation.ExpectedStatusCode}; observed {response.StatusCode}.",
                    new RemediationGuidance(
                        "Enforce authorization at the object boundary for every request.",
                        ["Resolve the owning tenant/role server-side from the authenticated principal.",
                         "Reject cross-tenant access with 403 or 404 consistently.",
                         "Add automated regression coverage from this fixture."],
                        ["https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"]),
                    new FingerprintComponents(Metadata.Id, url.ToString(), path, expectation.InvariantName),
                    assetReference: context.Asset.AssetId.ToString()));
            }
        }

        return new SecurityCheckResult(
            Metadata.Id,
            findings.Count > 0 ? CheckExecutionStatus.CompletedWithWarnings : CheckExecutionStatus.Completed,
            started, DateTimeOffset.UtcNow, findings, [], null,
            RequestCount: fixtures.Expectations.Count, TargetsExamined: 1);
    }

    private static bool IsDenial(int status) => status is >= 400 and < 500;

    private static bool IsSuccess(int status) => status is >= 200 and < 300;
}
