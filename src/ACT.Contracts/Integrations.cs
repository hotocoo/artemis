
namespace ACT.Contracts;

/// <summary>One vulnerability-advisory observation from any configured feed.</summary>
public sealed record AdvisoryRecord(
    string AdvisoryId,
    string Ecosystem,
    string Package,
    string AffectedRangeExpression,
    string? FixedVersion,
    Severity? Severity,
    string SourceFeed,
    DateTimeOffset RetrievedUtc,
    string MetadataHash);

/// <summary>Whether a feed's data may honestly be presented as current.</summary>
public sealed record FeedFreshness(bool IsCurrent, DateTimeOffset? LastUpdatedUtc, string Note);

/// <summary>
/// Abstraction over vulnerability-metadata sources. Implementations cache locally and must
/// clearly mark stale data instead of silently presenting it as current.
/// </summary>
public interface ISecurityAdvisoryProvider
{
    string Name { get; }

    Task<AdvisoryLookupResult> QueryAsync(string ecosystem, string packageName, string version,
        CancellationToken cancellationToken);

    Task<FeedFreshness> GetFreshnessAsync(CancellationToken cancellationToken);
}

/// <summary>Advisories relevant to one package/version plus honest freshness information.</summary>
public sealed record AdvisoryLookupResult(
    string Ecosystem,
    string Package,
    string Version,
    IReadOnlyList<AdvisoryRecord> Advisories,
    FeedFreshness Freshness);

/// <summary>A block of content that originated outside the operator and must be treated as data, never instructions.</summary>
public sealed record LlmUntrustedBlock(string Label, string Content);

/// <summary>A bounded request to a language model. Untrusted blocks are always delimited.</summary>
public sealed record LlmRequest(
    string SystemPrompt,
    string Instruction,
    IReadOnlyList<LlmUntrustedBlock> UntrustedBlocks,
    int MaxOutputTokens);

/// <summary>Completion result; UsedFallback=true means no model answered and callers must degrade gracefully.</summary>
public sealed record LlmCompletion(string Text, bool UsedFallback, string ProviderName, int TokensEstimated);

/// <summary>
/// Optional language-model integration. The entire security engine functions with every
/// implementation disabled. Implementations receive target content only inside delimited
/// untrusted blocks and their output is advisory-only by construction.
/// </summary>
public interface ILanguageModelProvider
{
    string Name { get; }

    bool IsAvailable { get; }

    Task<LlmCompletion> CompleteAsync(LlmRequest request, CancellationToken cancellationToken);
}
