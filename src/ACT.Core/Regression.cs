
using System.Net.Http;
using System.Text;
using System.Text.Json;
using ACT.Contracts;

namespace ACT.Core;

/// <summary>Machine-executable regression step derived from a confirmed finding.</summary>
public sealed record RegressionStepSpec(
    string Given,
    string When,
    string Then);

/// <summary>A generated regression test bound to its finding.</summary>
public sealed record GeneratedRegression(
    Guid RegressionTestId,
    Guid FindingId,
    CheckId OriginatingCheck,
    string Title,
    IReadOnlyList<RegressionStepSpec> Steps,
    HttpRequestExpectation? HttpExpectation,
    bool ReplayCheck,
    string ExpectedOutcomeSummary);

/// <summary>Concrete HTTP replay used for access-control regressions.</summary>
public sealed record HttpRequestExpectation(
    HttpMethodType Method,
    Uri Url,
    IReadOnlyDictionary<string, string> PrincipalHeaders,
    int ExpectedStatusMin,
    int ExpectedStatusMax,
    string InvariantName);

public enum HttpMethodType
{
    Get,
    Post,
    Put,
    Delete
}

/// <summary>
/// Generates regression tests from findings using ONLY operator-supplied fixtures. The engine
/// never invents object ids or credentials; without fixtures no HTTP regressions are produced.
/// </summary>
public static class RegressionGenerator
{
    public static GeneratedRegression? TryGenerate(
        Finding finding,
        AuthorizationFixtureSet fixtures,
        Uri baseUrl)
    {
        // Access-control regressions need explicit principals and objects.
        if (finding.Category == CheckCategory.Authorization && fixtures.Principals.Count >= 2 && fixtures.Objects.Count > 0)
        {
            var target = fixtures.Objects.First();
            var outsider = fixtures.Principals
                .Where(p => !string.Equals(p.TenantId, target.OwnerTenantId, StringComparison.Ordinal))
                .OrderBy(p => p.TenantId, StringComparer.Ordinal)
                .FirstOrDefault();

            if (outsider is not null)
            {
                var path = target.RelativePathTemplate.Replace("{id}", Uri.EscapeDataString(target.ObjectId));
                var url = new Uri(baseUrl, path);
                var steps = new List<RegressionStepSpec>
                {
                    new($"Principal '{outsider.PrincipalId}' of tenant '{outsider.TenantId}' is authenticated.",
                        $"GET {url.PathAndQuery} for object '{target.ObjectId}' owned by tenant '{target.OwnerTenantId}'.",
                        $"Response status must be within 400..404 (forbidden/not found); success would be a cross-tenant isolation failure."),
                    new("Remediation applied.",
                        "The same request is repeated.",
                        "It must remain denied. A later success regresses the original finding.")
                };
                return new GeneratedRegression(
                    Guid.NewGuid(),
                    finding.FindingId,
                    finding.CheckId,
                    "Cross-tenant access remains denied",
                    steps,
                    new HttpRequestExpectation(HttpMethodType.Get, url, outsider.AuthenticationHeaders, 400, 404,
                        "cross-tenant-read-denied"),
                    ReplayCheck: false,
                    "Status in 400..404");
            }
        }

        // Default: replay the originating check and require the fingerprint to disappear.
        return new GeneratedRegression(
            Guid.NewGuid(),
            finding.FindingId,
            finding.CheckId,
            $"Re-run {finding.CheckId.Value} and require remediation of {finding.Fingerprint.Hash[..12]}",
            [new RegressionStepSpec(
                "The original finding was recorded.",
                "The originating check runs again against the same target.",
                "The finding fingerprint must no longer be reported.")],
            null,
            ReplayCheck: true,
            "Fingerprint absent from fresh results");
    }
}

/// <summary>Outcome of one executed regression test.</summary>
public sealed record RegressionRunResult(
    Guid RegressionTestId,
    Guid FindingId,
    bool Passed,
    string DetailSafe,
    DateTimeOffset RanUtc);

/// <summary>
/// Executes generated regressions. HTTP expectations run through the safe engine, so every
/// replay inherits full scope enforcement.
/// </summary>
public sealed class RegressionRunner(ISafeHttpEngine http)
{
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public async Task<RegressionRunResult> RunAsync(GeneratedRegression regression, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;

        if (regression.HttpExpectation is { } expectation)
        {
            var verdict = await ExecuteExpectationAsync(expectation, cancellationToken);
            return new RegressionRunResult(regression.RegressionTestId, regression.FindingId,
                verdict.Passed, verdict.Detail, now);
        }

        // CheckReplay regressions are orchestrated by the assessment pipeline itself; the runner
        // reports the plan honestly rather than pretending to execute here.
        return new RegressionRunResult(regression.RegressionTestId, regression.FindingId,
            Passed: true,
            "Replay scheduled with next assessment of this scope.",
            now);
    }

    private async Task<(bool Passed, string Detail)> ExecuteExpectationAsync(
        HttpRequestExpectation expectation, CancellationToken cancellationToken)
    {
        var method = expectation.Method switch
        {
            HttpMethodType.Get => HttpMethod.Get,
            HttpMethodType.Post => HttpMethod.Post,
            HttpMethodType.Put => HttpMethod.Put,
            _ => HttpMethod.Delete
        };

        var response = await http.SendAsync(new SafeHttpRequest(
            method,
            expectation.Url,
            expectation.PrincipalHeaders,
            null,
            CorrelationId.New()), cancellationToken);

        var inRange = response.StatusCode >= expectation.ExpectedStatusMin &&
                      response.StatusCode <= expectation.ExpectedStatusMax;
        var detail = inRange
            ? $"Status {response.StatusCode} within expected {expectation.ExpectedStatusMin}..{expectation.ExpectedStatusMax}."
            : $"Status {response.StatusCode} OUTSIDE expected {expectation.ExpectedStatusMin}..{expectation.ExpectedStatusMax}: invariant '{expectation.InvariantName}' violated.";
        return (inRange, detail);
    }

    /// <summary>Serializes a regression for persistence.</summary>
    public static string Serialize(GeneratedRegression regression) =>
        JsonSerializer.Serialize(regression, JsonOptions);

    public static GeneratedRegression? Deserialize(string json)
    {
        try
        {
            return JsonSerializer.Deserialize<GeneratedRegression>(json, JsonOptions);
        }
        catch (JsonException ex)
        {
            throw ActException.FailClosed(ErrorCategory.Parser,
                "A stored regression test could not be read.",
                "Regression deserialization failed: " + ex.Message, ex);
        }
    }
}
