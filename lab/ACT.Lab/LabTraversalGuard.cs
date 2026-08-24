namespace ACT.Lab;

/// <summary>Root-boundary decisions for the traversal fixture. Pure string logic; performs no I/O.</summary>
public static class LabTraversalGuard
{
    /// <summary>
    /// True when a fully-resolved candidate path stays strictly inside the data root. The root itself
    /// does not count as inside: nothing readable is ever served from the root directory itself.
    /// </summary>
    public static bool StaysInsideRoot(string rootFullPath, string candidateFullPath)
    {
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(rootFullPath));
        var candidate = Path.GetFullPath(candidateFullPath);
        var comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (string.Equals(root, candidate, comparison))
        {
            return false;
        }

        if (candidate.StartsWith(root + Path.DirectorySeparatorChar, comparison))
        {
            return true;
        }

        var alternateSeparator = Path.AltDirectorySeparatorChar;
        return alternateSeparator != Path.DirectorySeparatorChar
            && candidate.StartsWith(root + alternateSeparator, comparison);
    }
}
