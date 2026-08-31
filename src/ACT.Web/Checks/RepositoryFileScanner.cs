using ACT.SourceAnalysis;

namespace ACT.Web.Checks;

/// <summary>
/// Shared repository file enumeration for the network-free, repository-scoped checks.
/// Walks the operator-provided repository root while honoring the canonical ignored-directory
/// set (node_modules, dist, .git, build output, ...) so findings never originate from
/// dependencies or generated artifacts.
/// </summary>
public static class RepositoryFileScanner
{
    /// <summary>
    /// Enumerates files under <paramref name="repoPath"/> whose name matches any of the
    /// supplied search patterns, skipping well-known build/dependency/VCS directories.
    /// Returns an empty (never null) list when the root is missing or unreadable.
    /// </summary>
    public static IReadOnlyList<string> FindFiles(string repoPath, params string[] patterns)
    {
        if (string.IsNullOrWhiteSpace(repoPath) || !Directory.Exists(repoPath))
        {
            return [];
        }

        var results = new List<string>();
        var roots = new Stack<string>();
        roots.Push(repoPath);

        while (roots.Count > 0)
        {
            var dir = roots.Pop();
            string[] subdirs;
            try
            {
                subdirs = Directory.GetDirectories(dir);
            }
            catch
            {
                continue;
            }

            foreach (var sub in subdirs)
            {
                var name = Path.GetFileName(sub);
                if (!RepositoryWalker.IsIgnoredDirectoryName(name))
                {
                    roots.Push(sub);
                }
            }

            string[] files;
            try
            {
                files = Directory.GetFiles(dir);
            }
            catch
            {
                continue;
            }

            foreach (var file in files)
            {
                var fileName = Path.GetFileName(file);
                foreach (var pattern in patterns)
                {
                    if (MatchesPattern(fileName, pattern))
                    {
                        results.Add(file);
                        break;
                    }
                }
            }
        }

        return results;
    }

    /// <summary>
    /// Case-insensitive wildcard match supporting '*' (any run) and '?' (single char),
    /// mirroring the semantics the checks rely on for patterns like '*.env*' or 'web.config'.
    /// </summary>
    private static bool MatchesPattern(string fileName, string pattern)
    {
        var rx = "^" + System.Text.RegularExpressions.Regex.Escape(pattern)
            .Replace("\\*", ".*")
            .Replace("\\?", ".") + "$";
        return System.Text.RegularExpressions.Regex.IsMatch(fileName, rx,
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    }
}
