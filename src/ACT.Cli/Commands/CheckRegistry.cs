
using ACT.Api;
using ACT.Contracts;
using ACT.Tls.Checks;
using ACT.Web.Checks;

namespace ACT.Cli;

/// <summary>
/// The explicit built-in check registry. Nothing is discovered reflectively at runtime:
/// every executable check is listed here by construction.
/// </summary>
public static class CheckRegistry
{
    public interface IBuiltInCheck : ISecurityCheck
    {
        string Id { get; }
        CheckCategory Category { get; }
        SafetyLevel Safety { get; }
    }

    private sealed class Adapter(ISecurityCheck inner) : IBuiltInCheck
    {
        public string Id => inner.Metadata.Id.Value;
        public CheckCategory Category => inner.Metadata.Category;
        public SafetyLevel Safety => inner.Metadata.SafetyLevel;
        public SecurityCheckMetadata Metadata => inner.Metadata;
        public Task<SecurityCheckResult> ExecuteAsync(SecurityCheckContext context, CancellationToken cancellationToken) =>
            inner.ExecuteAsync(context, cancellationToken);
    }

    /// <summary>Network/web-facing checks bound to a specific base URL.</summary>
    public static IReadOnlyList<ISecurityCheck> CreateTargetedChecks(Uri baseUrl)
    {
        var list = new List<ISecurityCheck>();
        list.AddRange(BuildWebChecks());

        var openApiUrl = new Uri(baseUrl, "/api/openapi.json");
        using var probe = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        string? document = null;
        try
        {
            document = probe.GetStringAsync(openApiUrl).GetAwaiter().GetResult();
        }
        catch (Exception)
        {
            // No OpenAPI document published at the conventional location: surface check skips.
        }
        if (document is not null)
        {
            list.Add(new ApiSurfaceAnalysisCheck(() => document, baseUrl));
        }
        return list;
    }

    /// <summary>Catalog listing used by 'artemis check list'.</summary>
    public static IReadOnlyList<SecurityCheckMetadata> Catalog()
    {
        var samples = new List<ISecurityCheck>();
        samples.AddRange(BuildWebChecks());
        return [.. samples.Select(c => c.Metadata)];
    }

    private static List<ISecurityCheck> BuildWebChecks() =>
    [
        new HstsCheck(),
        new CspCheck(),
        new SecurityHeadersCheck(),
        new CookieFlagCheck(),
        new CorsCheck(),
        new TlsRedirectCheck(),
        new MixedContentCheck(),
        new InfoDisclosureCheck(),
        new CacheControlCheck()
    ];
}
