using System.Text.Json;

namespace ACT.Lab;

/// <summary>Machine-readable API descriptions served by the lab.</summary>
public static class LabApiDocuments
{
    /// <summary>
    /// Valid OpenAPI 3.0.3 document describing ONLY the declared safe surface: the enforced
    /// authorization variant plus an unauthenticated job-submission endpoint that deliberately
    /// omits all security declarations. The dangerous fixtures and the administrative reset
    /// endpoint are intentionally undocumented.
    /// </summary>
    public static string OpenApiJson { get; } = BuildOpenApiJson();

    private static string BuildOpenApiJson()
    {
        var document = new Dictionary<string, object?>
        {
            ["openapi"] = "3.0.3",
            ["info"] = new Dictionary<string, object?>
            {
                ["title"] = "Artemis Test Lab — declared safe surface",
                ["version"] = "1.0.0",
                ["description"] =
                    "Fixture surface for defensive scanner verification. Dangerous fixtures are intentionally undocumented.",
            },
            ["paths"] = new Dictionary<string, object?>
            {
                ["/authz-safe/items/{id}"] = new Dictionary<string, object?>
                {
                    ["get"] = new Dictionary<string, object?>
                    {
                        ["operationId"] = "getSafeItem",
                        ["summary"] = "Returns a synthetic item when the caller tenant owns it.",
                        ["security"] = new object[] { new Dictionary<string, string[]> { ["XTenantHeader"] = [] } },
                        ["parameters"] = new object[]
                        {
                            new Dictionary<string, object?>
                            {
                                ["name"] = "id",
                                ["in"] = "path",
                                ["required"] = true,
                                ["schema"] = new Dictionary<string, string> { ["type"] = "string" },
                            },
                            new Dictionary<string, object?>
                            {
                                ["name"] = "X-Tenant",
                                ["in"] = "header",
                                ["required"] = true,
                                ["schema"] = new Dictionary<string, string> { ["type"] = "string" },
                            },
                        },
                        ["responses"] = new Dictionary<string, object?>
                        {
                            ["200"] = ResponseDescription("The synthetic item owned by the caller tenant."),
                            ["404"] = ResponseDescription("Unknown id or the caller tenant does not own the item."),
                        },
                    },
                },
                ["/api/jobs"] = new Dictionary<string, object?>
                {
                    ["post"] = new Dictionary<string, object?>
                    {
                        // Fixture: this endpoint intentionally OMITS every security declaration.
                        ["operationId"] = "submitSyntheticJob",
                        ["summary"] = "Queues a synthetic job without any authentication requirements.",
                        ["responses"] = new Dictionary<string, object?>
                        {
                            ["202"] = ResponseDescription("Synthetic job accepted."),
                        },
                    },
                },
            },
            ["components"] = new Dictionary<string, object?>
            {
                ["securitySchemes"] = new Dictionary<string, object?>
                {
                    ["XTenantHeader"] = new Dictionary<string, object?>
                    {
                        ["type"] = "apiKey",
                        ["in"] = "header",
                        ["name"] = "X-Tenant",
                    },
                },
            },
        };

        return JsonSerializer.Serialize(document);
    }

    private static Dictionary<string, object?> ResponseDescription(string description) => new() { ["description"] = description };
}
