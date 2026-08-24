
using System.Text.Json;
using ACT.Contracts;

namespace ACT.Cli;

/// <summary>Loads operator-authored authorization fixtures. Synthetic example lives in samples/.</summary>
public static class FixturesFile
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        ReadCommentHandling = JsonCommentHandling.Disallow
    };

    public static AuthorizationFixtureSet Load(string path)
    {
        string json;
        try
        {
            json = File.ReadAllText(path);
        }
        catch (Exception ex)
        {
            throw ActException.FailClosed(ErrorCategory.Parser,
                "The fixtures file could not be read.",
                $"Read failure on '{path}': {ex.Message}", ex);
        }

        try
        {
            var dto = JsonSerializer.Deserialize<FixturesDto>(json, JsonOptions)
                      ?? throw new JsonException("Fixtures document is empty.");

            var principals = (dto.Principals ?? []).Select(p => new TestPrincipal(
                Require(p.PrincipalId, "principals[].principalId"),
                Require(p.TenantId, "principals[].tenantId"),
                Require(p.Role, "principals[].role"),
                p.AuthenticationHeaders ?? new Dictionary<string, string>())).ToList();

            var objects = (dto.Objects ?? []).Select(o => new ObjectFixture(
                Require(o.ObjectId, "objects[].objectId"),
                Require(o.OwnerTenantId, "objects[].ownerTenantId"),
                Require(o.RelativePathTemplate, "objects[].relativePathTemplate"))).ToList();

            var expectations = (dto.Expectations ?? []).Select(e => new AccessExpectation(
                Require(e.ExpectationId, "expectations[].expectationId"),
                Require(e.PrincipalId, "expectations[].principalId"),
                Require(e.ObjectId, "expectations[].objectId"),
                Require(e.HttpMethod, "expectations[].httpMethod").ToUpperInvariant(),
                e.ExpectedStatusCode ?? throw Fail("expectations[].expectedStatusCode is required."),
                Require(e.InvariantName, "expectations[].invariantName"))).ToList();

            return new AuthorizationFixtureSet(principals, objects, expectations);
        }
        catch (JsonException ex)
        {
            throw ActException.FailClosed(ErrorCategory.Parser,
                "The fixtures file is not valid JSON for Artemis fixtures.",
                $"JSON parse error in '{path}': {ex.Message}", ex);
        }
    }

    private static string Require(string? value, string field) =>
        string.IsNullOrWhiteSpace(value) ? throw Fail($"Field '{field}' is required.") : value.Trim();

    private static ActException Fail(string detail) =>
        ActException.FailClosed(ErrorCategory.Parser, "The fixtures file contains invalid values.", detail);

    private sealed record FixturesDto(
        IReadOnlyList<PrincipalDto>? Principals,
        IReadOnlyList<ObjectDto>? Objects,
        IReadOnlyList<ExpectationDto>? Expectations);

    private sealed record PrincipalDto(
        string? PrincipalId, string? TenantId, string? Role,
        Dictionary<string, string>? AuthenticationHeaders);

    private sealed record ObjectDto(
        string? ObjectId, string? OwnerTenantId, string? RelativePathTemplate);

    private sealed record ExpectationDto(
        string? ExpectationId, string? PrincipalId, string? ObjectId,
        string? HttpMethod, int? ExpectedStatusCode, string? InvariantName);
}
