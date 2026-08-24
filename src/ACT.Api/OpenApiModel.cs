
using System.Text.Json;
using ACT.Contracts;

namespace ACT.Api;

/// <summary>Lightweight parsed API surface extracted from OpenAPI 3.x / Swagger 2.x documents.</summary>
public sealed record ApiSurface(
    string Title,
    string Version,
    bool IsSwagger2,
    IReadOnlyList<ApiOperation> Operations,
    bool HasGlobalSecurity,
    int DeclaredSecuritySchemeCount);

/// <summary>One documented operation.</summary>
public sealed record ApiOperation(
    string Path,
    string Method,
    bool HasSecurityOverride,
    bool SecurityRequiresAuth,
    bool HasResponses,
    bool DocumentsErrorResponses,
    IReadOnlyList<string> ParameterNames,
    IReadOnlyList<string> ResponseSchemaFieldNames);

/// <summary>
/// Tolerant parser for machine-authored documents, hostile to garbage: structural problems
/// become Parser failures instead of silently half-read models.
/// </summary>
public static class ApiSurfaceParser
{
    public static ApiSurface Parse(string json)
    {
        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException ex)
        {
            throw ActException.FailClosed(ErrorCategory.Parser,
                "The API description is not valid JSON.",
                $"OpenAPI JSON parse failure: {ex.Message}", ex);
        }

        using var _ = document;
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
        {
            throw ActException.FailClosed(ErrorCategory.Parser,
                "The API description root must be a JSON object.", "Root element was not an object.");
        }

        var isSwagger2 = root.TryGetProperty("swagger", out var swaggerProp) &&
                         swaggerProp.GetString()?.StartsWith("2", StringComparison.Ordinal) == true;
        var isOpenApi3 = root.TryGetProperty("openapi", out _) ;
        if (!isSwagger2 && !isOpenApi3)
        {
            throw ActException.FailClosed(ErrorCategory.Parser,
                "The API description is neither OpenAPI 3.x nor Swagger 2.x.",
                "Neither 'openapi' nor 'swagger' version field found.");
        }

        var title = root.TryGetProperty("info", out var info) && info.TryGetProperty("title", out var t)
            ? t.GetString() ?? ""
            : "";
        var version = root.TryGetProperty("info", out var info2) && info2.TryGetProperty("version", out var v)
            ? v.GetString() ?? ""
            : "";

        var schemeCount = CountSecuritySchemes(root, isSwagger2);
        var hasGlobalSecurity = root.TryGetProperty("security", out var globalSec) &&
                                globalSec.ValueKind == JsonValueKind.Array && globalSec.GetArrayLength() > 0;

        if (!root.TryGetProperty("paths", out var pathsElement) || pathsElement.ValueKind != JsonValueKind.Object)
        {
            return new ApiSurface(title, version, isSwagger2, [], hasGlobalSecurity, schemeCount);
        }

        var operations = new List<ApiOperation>();
        foreach (var pathProperty in pathsElement.EnumerateObject())
        {
            if (pathProperty.Value.ValueKind != JsonValueKind.Object) continue;
            foreach (var op in pathProperty.Value.EnumerateObject())
            {
                var method = op.Name.ToLowerInvariant();
                if (!IsHttpMethod(method)) continue;
                operations.Add(ParseOperation(pathProperty.Name, method, op.Value));
            }
        }

        return new ApiSurface(title, version, isSwagger2, operations, hasGlobalSecurity, schemeCount);
    }

    private static ApiOperation ParseOperation(string path, string method, JsonElement operation)
    {
        var hasSecurity = operation.TryGetProperty("security", out var sec);
        var securityRequiresAuth = hasSecurity && sec.ValueKind == JsonValueKind.Array && sec.GetArrayLength() > 0;

        var hasResponses = operation.TryGetProperty("responses", out var responses) &&
                           responses.ValueKind == JsonValueKind.Object && responses.EnumerateObject().Any();
        var documentsErrors = hasResponses && responses.EnumerateObject().Any(r =>
            r.Name.StartsWith('4') || r.Name.StartsWith('5'));

        var parameterNames = new List<string>();
        if (operation.TryGetProperty("parameters", out var parameters) && parameters.ValueKind == JsonValueKind.Array)
        {
            foreach (var p in parameters.EnumerateArray())
            {
                if (p.TryGetProperty("name", out var n) && n.ValueKind == JsonValueKind.String)
                {
                    parameterNames.Add(n.GetString()!);
                }
            }
        }

        var fieldNames = new List<string>();
        if (hasResponses)
        {
            foreach (var response in responses.EnumerateObject())
            {
                if (response.Value.ValueKind != JsonValueKind.Object) continue;
                if (!response.Value.TryGetProperty("content", out var content)) continue;
                foreach (var mediaType in content.EnumerateObject())
                {
                    if (!mediaType.Value.TryGetProperty("schema", out var schema)) continue;
                    CollectSchemaFields(schema, fieldNames, depth: 0);
                }
            }
        }

        return new ApiOperation(path, method, hasSecurity, securityRequiresAuth,
            hasResponses, documentsErrors, parameterNames, fieldNames.Distinct(StringComparer.OrdinalIgnoreCase).ToList());
    }

    private static void CollectSchemaFields(JsonElement schema, List<string> into, int depth)
    {
        if (depth > 6 || schema.ValueKind != JsonValueKind.Object) return;
        if (schema.TryGetProperty("properties", out var properties) && properties.ValueKind == JsonValueKind.Object)
        {
            foreach (var property in properties.EnumerateObject())
            {
                into.Add(property.Name);
            }
        }
        if (schema.TryGetProperty("items", out var items))
        {
            CollectSchemaFields(items, into, depth + 1);
        }
    }

    private static int CountSecuritySchemes(JsonElement root, bool swagger2)
    {
        var container = swagger2 ? "securityDefinitions" : "components";
        if (!root.TryGetProperty(container, out var section)) return 0;
        if (swagger2)
        {
            return section.ValueKind == JsonValueKind.Object ? section.EnumerateObject().Count() : 0;
        }
        return section.ValueKind == JsonValueKind.Object &&
               section.TryGetProperty("securitySchemes", out var schemes) &&
               schemes.ValueKind == JsonValueKind.Object
            ? schemes.EnumerateObject().Count()
            : 0;
    }

    private static bool IsHttpMethod(string name) => name is
        "get" or "put" or "post" or "delete" or "options" or "head" or "patch" or "trace";
}
