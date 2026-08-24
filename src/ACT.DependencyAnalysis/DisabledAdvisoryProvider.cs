
using ACT.Contracts;

namespace ACT.DependencyAnalysis;

/// <summary>
/// The honest absence of advisory data. When no feed is configured (the shipping default), this
/// provider answers every lookup with zero advisories AND a not-current freshness mark, so
/// downstream reporting treats dependency severities as inconclusive instead of mistaking
/// "nothing retrieved" for "nothing vulnerable".
/// </summary>
public sealed class DisabledAdvisoryProvider : ISecurityAdvisoryProvider
{
    /// <summary>Shared stateless instance.</summary>
    public static DisabledAdvisoryProvider Instance { get; } = new();

    private static readonly FeedFreshness NoFeedFreshness =
        new(IsCurrent: false, LastUpdatedUtc: null,
            Note: "No advisory feed is configured; results are inconclusive until a feed is enabled.");

    private DisabledAdvisoryProvider()
    {
    }

    /// <summary>The feed name recorded alongside any consumer output.</summary>
    public string Name => "disabled";

    /// <summary>Returns an empty lookup explicitly marked not-current.</summary>
    public Task<AdvisoryLookupResult> QueryAsync(string ecosystem, string packageName, string version,
        CancellationToken cancellationToken) =>
        Task.FromResult(new AdvisoryLookupResult(ecosystem, packageName, version, [], NoFeedFreshness));

    /// <summary>Returns the standing not-current freshness verdict.</summary>
    public Task<FeedFreshness> GetFreshnessAsync(CancellationToken cancellationToken) =>
        Task.FromResult(NoFeedFreshness);
}
