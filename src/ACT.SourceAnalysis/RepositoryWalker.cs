using System.Runtime.CompilerServices;
using ACT.Contracts;

namespace ACT.SourceAnalysis;

/// <summary>
/// Safely enumerates text files under one operator-provided repository root with hard caps on
/// file size, directory depth, run volume, and symlink traversal. Links resolving outside the
/// root are observed and skipped, never followed.
/// </summary>
public sealed class RepositoryWalker
{
    /// <summary>Well-known directories that never contain analyzable first-party source.</summary>
    public static readonly IReadOnlySet<string> IgnoredDirectoryNames =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            ".git", ".hg", ".svn", "node_modules", "bin", "obj",
            "dist", "build", "target", ".venv", "__pycache__", "out"
        };

    /// <summary>Creates a walker; the root must exist and the limits must be positive or the call fails closed.</summary>
    public RepositoryWalker(string rootPath, RepositoryAnalysisLimits? limits = null)
    {
        if (string.IsNullOrWhiteSpace(rootPath))
        {
            throw ActException.FailClosed(
                ErrorCategory.Configuration,
                "A repository root path is required for source analysis.",
                "RepositoryWalker received a null or empty root path.");
        }

        var fullPath = Path.GetFullPath(rootPath);
        if (!Directory.Exists(fullPath))
        {
            throw ActException.FailClosed(
                ErrorCategory.Configuration,
                "The configured repository root does not exist.",
                $"Repository root not found: '{fullPath}'.");
        }

        Limits = limits ?? RepositoryAnalysisLimits.Default;
        if (Limits.MaxFileBytes <= 0 || Limits.MaxDepth <= 0 || Limits.MaxFilesPerRun <= 0)
        {
            throw ActException.FailClosed(
                ErrorCategory.Configuration,
                "Repository analysis limits must all be positive.",
                $"Invalid RepositoryAnalysisLimits: MaxFileBytes={Limits.MaxFileBytes}, MaxDepth={Limits.MaxDepth}, MaxFilesPerRun={Limits.MaxFilesPerRun}.");
        }

        RootPath = fullPath.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    }

    /// <summary>Absolute normalized root path of this walk.</summary>
    public string RootPath { get; }

    /// <summary>Effective resource limits for this walk.</summary>
    public RepositoryAnalysisLimits Limits { get; }

    /// <summary>Counters accumulated while entries are consumed.</summary>
    public RepositoryWalkCounters Counters { get; } = new();

    /// <summary>Enumerates the repository breadth-first in deterministic (ordinal name) order.</summary>
    public async IAsyncEnumerable<RepositoryWalkEntry> WalkAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var visitedTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { RootPath };
        var pendingDirectories = new Queue<(string FullPath, string RelativePath, int Depth)>();
        pendingDirectories.Enqueue((RootPath, string.Empty, 0));
        var filesEmitted = 0;

        while (pendingDirectories.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var (directoryFullPath, directoryRelative, depth) = pendingDirectories.Dequeue();

            FileSystemInfo[] children;
            try
            {
                children = new DirectoryInfo(directoryFullPath)
                    .EnumerateFileSystemInfos()
                    .OrderBy(static candidate => candidate.Name, StringComparer.Ordinal)
                    .ToArray();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Counters.IncrementIoErrors();
                continue;
            }

            foreach (var child in children)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var childRelative = directoryRelative.Length == 0
                    ? child.Name
                    : $"{directoryRelative}/{child.Name}";

                if (child is DirectoryInfo directoryInfo)
                {
                    if (IgnoredDirectoryNames.Contains(directoryInfo.Name))
                    {
                        Counters.IncrementIgnoredDirectories();
                        continue;
                    }

                    var resolution = ResolveWithinRoot(directoryInfo, visitedTargets);
                    if (!resolution.Success)
                    {
                        Counters.IncrementSymlinkEscapes();
                        yield return new SymlinkEscapeObservation(childRelative, resolution.TargetPath);
                        continue;
                    }

                    if (depth + 1 > Limits.MaxDepth)
                    {
                        Counters.IncrementDepthLimitedDirectories();
                        continue;
                    }

                    pendingDirectories.Enqueue((resolution.TargetPath, childRelative, depth + 1));
                    continue;
                }

                var fileInfo = (FileInfo)child;
                var fileResolution = ResolveWithinRoot(fileInfo, visitedTargets);
                if (!fileResolution.Success)
                {
                    Counters.IncrementSymlinkEscapes();
                    yield return new SymlinkEscapeObservation(childRelative, fileResolution.TargetPath);
                    continue;
                }

                long length;
                try
                {
                    length = fileInfo.Length;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    Counters.IncrementIoErrors();
                    continue;
                }

                if (length > Limits.MaxFileBytes)
                {
                    Counters.IncrementOversizedFiles();
                    yield return new OversizedFileSkipped(childRelative, length);
                    continue;
                }

                if (filesEmitted >= Limits.MaxFilesPerRun)
                {
                    Counters.MarkFileLimitReached();
                    yield return new ScanLimitReached(
                        $"The per-run cap of {Limits.MaxFilesPerRun} files was reached; remaining files were not analyzed.");
                    yield break;
                }

                filesEmitted++;
                Counters.IncrementFilesDiscovered();
                yield return new DiscoveredFile(new FileContext(
                    childRelative,
                    fileInfo.FullName,
                    SourceLanguageDetector.Detect(fileInfo.Name),
                    length));
            }
        }
    }

    private LinkResolution ResolveWithinRoot(FileSystemInfo info, HashSet<string> visitedTargets)
    {
        if (info.LinkTarget is null)
        {
            return new LinkResolution(true, info.FullName);
        }

        FileSystemInfo? finalTarget;
        try
        {
            finalTarget = info.ResolveLinkTarget(returnFinalTarget: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return new LinkResolution(false, string.Empty);
        }

        if (finalTarget is null)
        {
            return new LinkResolution(false, string.Empty);
        }

        var resolvedFullPath = Path.GetFullPath(finalTarget.FullName);
        var withinRoot = resolvedFullPath.Equals(RootPath, StringComparison.OrdinalIgnoreCase)
                         || resolvedFullPath.StartsWith(
                             RootPath + Path.DirectorySeparatorChar,
                             StringComparison.OrdinalIgnoreCase);
        // A link that escapes the root, or that closes a cycle onto an already-visited target,
        // is skipped: it is never followed.
        if (!withinRoot || !visitedTargets.Add(resolvedFullPath))
        {
            return new LinkResolution(false, resolvedFullPath);
        }

        return new LinkResolution(true, resolvedFullPath);
    }

    private readonly record struct LinkResolution(bool Success, string TargetPath);
}

