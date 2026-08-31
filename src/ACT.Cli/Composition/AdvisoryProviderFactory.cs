using ACT.Contracts;
using ACT.DependencyAnalysis;
using Microsoft.Extensions.Configuration;

namespace ACT.Cli.Composition;

/// <summary>
/// Builds the advisory provider the dependency audit should use from operator configuration.
/// The assessment path previously hard-wired the disabled provider, so a configured feed was
/// never consulted even when enabled. This factory closes that gap: the first enabled source
/// wins; with none enabled the honest disabled provider is returned so results stay inconclusive
/// rather than a false clean bill of health.
/// </summary>
public static class AdvisoryProviderFactory
{
    public static ISecurityAdvisoryProvider Create(IConfiguration configuration)
    {
        var sources = configuration.GetSection("Act:Feeds:Sources").GetChildren().ToList();
        var cachePath = configuration.GetValue<string>("Act:Feeds:CachePath") ?? "feeds-cache";
        var defaultStale = configuration.GetValue<int>("Act:Feeds:StaleAfterDays") is int d and > 0
            ? d
            : FeedDefaults.StaleAfterDays;

        foreach (var source in sources)
        {
            if (!source.GetValue<bool>("Enabled")) continue;

            var name = source.GetValue<string>("Name") ?? "feed";
            var kindText = source.GetValue<string>("Kind") ?? "";
            var endpointOrPath = source.GetValue<string>("EndpointOrPath") ?? "";
            var stale = source.GetValue<int>("StaleAfterDays") is int s and > 0 ? s : defaultStale;

            try
            {
                if (kindText.Equals("OfflineFile", StringComparison.OrdinalIgnoreCase))
                {
                    var sha = source.GetValue<string?>("Sha256");
                    return new CachingFeedProvider(
                        new OfflineFileAdvisoryProvider(endpointOrPath, sha, stale),
                        cachePath, stale);
                }

                if (kindText.Equals("Osv", StringComparison.OrdinalIgnoreCase))
                {
                    if (!Uri.TryCreate(endpointOrPath, UriKind.Absolute, out var endpoint)
                        || endpoint.Scheme is not ("http" or "https"))
                    {
                        // Malformed endpoint: fall through to the disabled provider rather than
                        // failing the whole assessment; the feed command reports the problem.
                        continue;
                    }
                    return new CachingFeedProvider(
                        new OsvAdvisoryProvider(endpoint, stale),
                        cachePath, stale);
                }
            }
            catch (ActException)
            {
                // Integrity/configuration failure for one source: skip it and try the next;
                // the dedicated 'artemis feed update' command surfaces these loudly.
            }
        }

        return DisabledAdvisoryProvider.Instance;
    }
}
