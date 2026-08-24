namespace ACT.Lab;

/// <summary>Detects shell metacharacters in command-fixture probes without ever executing anything.</summary>
public static class LabShellMetaDetector
{
    private static readonly char[] Metacharacters = [';', '&', '|', '`', '$'];

    /// <summary>True when the value carries a shell metacharacter the lab treats as an injection probe.</summary>
    public static bool ContainsShellMetacharacter(string value) => value.IndexOfAny(Metacharacters) >= 0;
}
