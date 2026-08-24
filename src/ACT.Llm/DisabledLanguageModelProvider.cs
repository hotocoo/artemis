using ACT.Contracts;

namespace ACT.Llm;

/// <summary>
/// Default provider used whenever language-model advisories are disabled. It performs no network
/// or model work and always reports an empty fallback completion so callers degrade gracefully.
/// </summary>
public sealed class DisabledLanguageModelProvider : ILanguageModelProvider
{
    /// <summary>Stable provider name reported in completions and audit badges.</summary>
    public const string ProviderName = "disabled";

    /// <inheritdoc />
    public string Name => ProviderName;

    /// <summary>Always false: the disabled provider never answers requests.</summary>
    public bool IsAvailable => false;

    /// <summary>Returns an empty fallback completion without touching any network resource.</summary>
    public Task<LlmCompletion> CompleteAsync(LlmRequest request, CancellationToken cancellationToken) =>
        Task.FromResult(new LlmCompletion(string.Empty, UsedFallback: true, ProviderName, TokensEstimated: 0));
}
