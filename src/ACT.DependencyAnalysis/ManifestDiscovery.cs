
using System.Runtime.CompilerServices;

namespace ACT.DependencyAnalysis;

/// <summary>Bounded resource envelope for one manifest discovery walk.</summary>
public sealed record DiscoveryLimits
{
    /// <summary>Default per-file size cap (10 MB).</summary>
    public const long DefaultMaxFileBytes = 10 * 1024 * 1024;

    /// <summary>Creates limits; all values are validated by consumers.</summary>
    public DiscoveryLimits(long maxFileBytes = DefaultMaxFileBytes, int maxDepth = 12, int maxFilesPerRun = 20_000)
    {
        MaxFileBytes = maxFileBytes;
        MaxDepth = maxDepth;
        MaxFilesPerRun = maxFilesPerRun;
    }

    /// <summary>Files larger than this many bytes are skipped.</summary>
    public long MaxFileBytes { get; }

    /// <summary>Maximum directory depth below the root.</summary>
    public int MaxDepth { get; }

    /// <summary>Maximum number of candidate files per run.</summary>
    public int MaxFilesPerRun { get; }
}

/// <summary>
/// Discovers dependency manifest files under one repository root with the same safety posture as
/// source analysis: ignored directories, symlink-escape refusal, depth, size, and volume caps.
/// </summary>
internal sealed class ManifestDiscovery
{
    private static readonly HashSet<string> IgnoredDirectoryNames =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ".git", ".hg", ".svn", "node_modules", "bin", "obj",
            "dist", "build", "target", ".venv", "__pycache__", "out"
        };

    /// <summary>Enumerates candidate manifests breadth-first in deterministic order.</summary>
    public async IAsyncEnumerable<DiscoveredManifest> DiscoverAsync(
        string rootPath,
        DiscoveryLimits limits,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var visitedTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { rootPath };
        var pending = new Queue<(string FullPath, string RelativePath, int Depth)>();
        pending.Enqueue((rootPath, string.Empty, 0));
        var emitted = 0;

        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var (directoryFullPath, directoryRelative, depth) = pending.Dequeue();

            FileSystemInfo[] children;
            try
            {
                children = new DirectoryInfo(directoryFullPath)
                    .EnumerateFileSystemInfos()
                    .OrderBy(static c => c.Name, StringComparer.Ordinal)
                    .ToArray();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var child in children)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (child is DirectoryInfo directory)
                {
                    if (!IgnoredDirectoryNames.Contains(directory.Name) && depth < limits.MaxDepth)
                    {
                        var resolution = ResolveWithinRoot(directory, visitedTargets, rootPath);
                        if (resolution is not null)
                        {
                            pending.Enqueue((resolution, JoinRelative(directoryRelative, directory.Name), depth + 1));
                        }
                    }

                    continue;
                }

                if (!ManifestParser.IsManifestFileName(child.Name))
                {
                    continue;
                }

                long length;
                try
                {
                    length = ((FileInfo)child).Length;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    continue;
                }

                if (length > limits.MaxFileBytes || emitted >= limits.MaxFilesPerRun)
                {
                    yield break;
                }

                emitted++;
                yield return new DiscoveredManifest(
                    JoinRelative(directoryRelative, child.Name),
                    child.FullName,
                    length);
            }
        }
    }

    private static string? ResolveWithinRoot(FileSystemInfo info, HashSet<string> visitedTargets, string rootPath)
    {
        if (info.LinkTarget is null)
        {
            return info.FullName;
        }

        FileSystemInfo? finalTarget;
        try
        {
            finalTarget = info.ResolveLinkTarget(returnFinalTarget: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }

        if (finalTarget is null)
        {
            return null;
        }

        var resolvedFullPath = Path.GetFullPath(finalTarget.FullName);
        var withinRoot = resolvedFullPath.Equals(rootPath, StringComparison.OrdinalIgnoreCase)
                         || resolvedFullPath.StartsWith(rootPath + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
        return withinRoot && visitedTargets.Add(resolvedFullPath) ? resolvedFullPath : null;
    }

    private static string JoinRelative(string parent, string name) =>
        parent.Length == 0 ? name : parent + "/" + name;

    internal readonly record struct DiscoveredManifest(string RelativePath, string AbsolutePath, long SizeBytes);
}

