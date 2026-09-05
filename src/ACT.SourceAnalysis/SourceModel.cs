using System.Runtime.CompilerServices;
using System.Text;

using ACT.Contracts;

namespace ACT.SourceAnalysis;

/// <summary>Programming-language classification used to select which source rules apply to a file.</summary>
public enum SourceLanguage
{
    Cs,
    Ts,
    Js,
    Py,
    Rust,
    Cpp,
    Go,
    Sql,
    Yaml,
    Json,
    Dockerfile,
    Shell,
    Unknown
}

/// <summary>Detects a file's source language from its name so rule evaluation can be filtered.</summary>
public static class SourceLanguageDetector
{
    /// <summary>Maps a file name to its source language; unknown extensions yield <see cref="SourceLanguage.Unknown"/>.</summary>
    public static SourceLanguage Detect(string fileName)
    {
        var name = Path.GetFileName(fileName);
        if (name.Equals("Dockerfile", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("Dockerfile.", StringComparison.OrdinalIgnoreCase)
            || name.EndsWith(".dockerfile", StringComparison.OrdinalIgnoreCase))
        {
            return SourceLanguage.Dockerfile;
        }

        return Path.GetExtension(name) switch
        {
            ".cs" => SourceLanguage.Cs,
            ".ts" or ".tsx" or ".mts" or ".cts" => SourceLanguage.Ts,
            ".js" or ".jsx" or ".mjs" or ".cjs" => SourceLanguage.Js,
            ".py" => SourceLanguage.Py,
            ".rs" => SourceLanguage.Rust,
            // Go source files were intentionally not recognized before round 6; adding the .go
            // extension keeps the language classifier consistent with the dependency-analysis
            // ecosystem (Go modules are inventoried starting in 0.1.5) and clears the way for
            // Go-targeted source rules to be added on top of the detector.
            ".go" => SourceLanguage.Go,
            ".cpp" or ".cc" or ".cxx" or ".c++" or ".hpp" or ".hh" or ".hxx" or ".h" or ".c" => SourceLanguage.Cpp,
            ".sql" => SourceLanguage.Sql,
            ".yaml" or ".yml" => SourceLanguage.Yaml,
            ".json" => SourceLanguage.Json,
            ".sh" or ".bash" or ".zsh" => SourceLanguage.Shell,
            _ => SourceLanguage.Unknown
        };
    }
}

/// <summary>Bounded resource envelope for one repository analysis run.</summary>
public sealed record RepositoryAnalysisLimits
{
    /// <summary>Default per-file size cap (10 MB).</summary>
    public const long DefaultMaxFileBytes = 10 * 1024 * 1024;

    /// <summary>Default directory descent cap.</summary>
    public const int DefaultMaxDepth = 12;

    /// <summary>Default maximum number of files emitted per walk.</summary>
    public const int DefaultMaxFilesPerRun = 20_000;

    /// <summary>Files larger than this many bytes are skipped and counted.</summary>
    public long MaxFileBytes { get; init; } = DefaultMaxFileBytes;

    /// <summary>Maximum directory depth below the root; deeper directories are not descended.</summary>
    public int MaxDepth { get; init; } = DefaultMaxDepth;

    /// <summary>Maximum number of files a single walk may emit before stopping.</summary>
    public int MaxFilesPerRun { get; init; } = DefaultMaxFilesPerRun;

    /// <summary>Shared default limits instance.</summary>
    public static RepositoryAnalysisLimits Default { get; } = new();
}

/// <summary>A declarative source-analysis rule: one compiled pattern plus honest metadata.</summary>
public sealed record SourceRule(
    string RuleId,
    string Title,
    string WhyItMatters,
    RemediationGuidance Remediation,
    string FindingClass,
    Severity Severity,
    ConfidenceLevel Confidence,
    bool ExploitabilityIndicator,
    IReadOnlyList<SourceLanguage> Languages,
    int MaxMatchesPerFile,
    System.Text.RegularExpressions.Regex Pattern,
    bool RedactMatches = false,
    Func<string, bool>? MatchValidator = null,
    bool SkipTestFiles = false);

/// <summary>One numbered line produced by lazy, encoding-tolerant streaming of a source file.</summary>
public readonly record struct FileLine(int Number, string Text);

/// <summary>A discovered source file ready for rule evaluation; line content is streamed lazily on demand.</summary>
public sealed record FileContext(string RelativePath, string AbsolutePath, SourceLanguage Language, long SizeBytes)
{
    /// <summary>
    /// Streams numbered lines with invalid UTF-8 decoded to replacement characters instead of throwing.
    /// The file is opened only when enumeration starts.
    /// </summary>
    public async IAsyncEnumerable<FileLine> EnumerateLinesAsync(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var stream = new FileStream(
            AbsolutePath, FileMode.Open, FileAccess.Read, FileShare.Read,
            bufferSize: 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using (stream.ConfigureAwait(false))
        {
            // Encoding.UTF8's decoder replaces malformed byte sequences with U+FFFD; it never throws.
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            var number = 0;
            while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
            {
                yield return new FileLine(++number, line);
            }
        }
    }
}

/// <summary>Base type for entries yielded while walking a repository.</summary>
public abstract record RepositoryWalkEntry;

/// <summary>A file admitted into the analysis set.</summary>
public sealed record DiscoveredFile(FileContext File) : RepositoryWalkEntry;

/// <summary>A symlink or reparse point whose final target resolves outside the repository root; never followed.</summary>
public sealed record SymlinkEscapeObservation(string LinkPath, string ResolvedTargetPath) : RepositoryWalkEntry;

/// <summary>A file skipped because it exceeded the configured per-file size cap.</summary>
public sealed record OversizedFileSkipped(string RelativePath, long SizeBytes) : RepositoryWalkEntry;

/// <summary>A file skipped because its content is binary (never meaningfully matched by text rules).</summary>
public sealed record BinaryFileSkipped(string RelativePath) : RepositoryWalkEntry;

/// <summary>Terminal notice emitted when the per-run file cap stopped the walk early.</summary>
public sealed record ScanLimitReached(string Reason) : RepositoryWalkEntry;

/// <summary>Thread-safe counters accumulated during one walk; read after enumeration completes.</summary>
public sealed class RepositoryWalkCounters
{
    private long _filesDiscovered;
    private long _oversizedFilesSkipped;
    private long _binaryFilesSkipped;
    private long _symlinkEscapesSkipped;
    private long _ioErrorsSkipped;
    private long _depthLimitedDirectories;
    private long _ignoredDirectories;
    private long _fileLimitReached;

    /// <summary>Records one admitted file.</summary>
    public void IncrementFilesDiscovered() => Interlocked.Increment(ref _filesDiscovered);

    /// <summary>Records one oversize skip.</summary>
    public void IncrementOversizedFiles() => Interlocked.Increment(ref _oversizedFilesSkipped);

    /// <summary>Records one binary-file skip.</summary>
    public void IncrementBinaryFiles() => Interlocked.Increment(ref _binaryFilesSkipped);

    /// <summary>Records one symlink-escape skip.</summary>
    public void IncrementSymlinkEscapes() => Interlocked.Increment(ref _symlinkEscapesSkipped);

    /// <summary>Records one unreadable entry.</summary>
    public void IncrementIoErrors() => Interlocked.Increment(ref _ioErrorsSkipped);

    /// <summary>Records one directory not descended due to the depth cap.</summary>
    public void IncrementDepthLimitedDirectories() => Interlocked.Increment(ref _depthLimitedDirectories);

    /// <summary>Records one ignored well-known directory (.git, node_modules, ...).</summary>
    public void IncrementIgnoredDirectories() => Interlocked.Increment(ref _ignoredDirectories);

    /// <summary>Marks that the per-run file cap terminated the walk.</summary>
    public void MarkFileLimitReached() => Interlocked.Exchange(ref _fileLimitReached, 1);

    /// <summary>Point-in-time snapshot of all counters.</summary>
    public RepositoryWalkStatistics Snapshot() => new(
        Interlocked.Read(ref _filesDiscovered),
        Interlocked.Read(ref _oversizedFilesSkipped),
        Interlocked.Read(ref _symlinkEscapesSkipped),
        Interlocked.Read(ref _ioErrorsSkipped),
        Interlocked.Read(ref _depthLimitedDirectories),
        Interlocked.Read(ref _ignoredDirectories),
        Interlocked.Read(ref _fileLimitReached) == 1);
}

/// <summary>Immutable summary of one completed or in-progress walk.</summary>
public sealed record RepositoryWalkStatistics(
    long FilesDiscovered,
    long OversizedFilesSkipped,
    long SymlinkEscapesSkipped,
    long IoErrorsSkipped,
    long DepthLimitedDirectories,
    long IgnoredDirectories,
    bool FileLimitReached);

