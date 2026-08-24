using ACT.Contracts;

namespace ACT.Llm;

/// <summary>
/// Shared plumbing for advisory language-model features. Every failure degrades gracefully to
/// <c>null</c>; only operator-requested cancellation propagates.
/// </summary>
internal static class AdvisorySupport
{
    /// <summary>Output budget used for advisory requests.</summary>
    internal const int AdvisoryMaxOutputTokens = 1024;

    internal static async Task<string?> TryRunAsync(
        ILanguageModelProvider provider,
        string systemPrompt,
        string instruction,
        string blockLabel,
        string blockContent,
        CancellationToken cancellationToken)
    {
        if (!provider.IsAvailable) return null;

        try
        {
            var request = new LlmRequest(
                SystemPrompt: systemPrompt,
                Instruction: instruction,
                UntrustedBlocks: [new LlmUntrustedBlock(blockLabel, blockContent)],
                MaxOutputTokens: AdvisoryMaxOutputTokens);
            var completion = await provider.CompleteAsync(request, cancellationToken);
            if (completion.UsedFallback || string.IsNullOrWhiteSpace(completion.Text)) return null;
            return completion.Text;
        }
        catch (Exception) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception)
        {
            return null;
        }
    }
}
