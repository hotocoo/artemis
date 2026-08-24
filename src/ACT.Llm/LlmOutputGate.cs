namespace ACT.Llm;

/// <summary>Advisory audit badge describing whether model output contained tool-directed directives.</summary>
public sealed record LlmOutputVerdict(bool IsClean, IReadOnlyList<string> FlaggedDirectives)
{
    /// <summary>Verdict for output with no flagged directives.</summary>
    public static LlmOutputVerdict Clean { get; } = new(true, []);
}

/// <summary>
/// Scans advisory model output for directive-like phrases aimed at the assessment tool. Purely
/// advisory by construction: verdicts feed audit badges and never change engine behavior alone.
/// </summary>
public static class LlmOutputGate
{
    private static readonly string[] DirectivePhrases =
    [
        "disable safety",
        "ignore scope",
        "expand allowlist",
        "emergency stop",
        "delete evidence",
        "run command",
        "execute command",
        "mark all as false positive"
    ];

    /// <summary>Analyzes model output and lists each directive-like phrase it contains.</summary>
    public static LlmOutputVerdict Analyze(string? output)
    {
        if (string.IsNullOrEmpty(output)) return LlmOutputVerdict.Clean;

        var flagged = new List<string>();
        foreach (var phrase in DirectivePhrases)
        {
            if (output.Contains(phrase, StringComparison.OrdinalIgnoreCase)) flagged.Add(phrase);
        }

        return flagged.Count == 0 ? LlmOutputVerdict.Clean : new LlmOutputVerdict(false, flagged);
    }
}
