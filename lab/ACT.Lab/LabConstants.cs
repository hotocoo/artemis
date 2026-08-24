namespace ACT.Lab;

/// <summary>Canonical header names used by the lab's fixtures.</summary>
public static class LabConstants
{
    /// <summary>Per-request correlation header echoed on every response.</summary>
    public const string CorrelationHeader = "X-Lab-Correlation";

    /// <summary>Administrative token header guarding undocumented maintenance endpoints.</summary>
    public const string TokenHeader = "X-Lab-Token";

    /// <summary>Response header marking a blocked path-traversal attempt.</summary>
    public const string TraversalBlockedHeader = "X-Lab-Traversal-Blocked";

    /// <summary>Response header marking rejection of a command-metacharacter probe.</summary>
    public const string CommandMetaDetectedHeader = "X-Lab-CommandMeta-Detected";
}
