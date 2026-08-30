
namespace ACT.DependencyAnalysis;

/// <summary>Package ecosystems whose manifests Artemis can inventory.</summary>
public enum DependencyEcosystem
{
    Unknown,
    NuGet,
    Npm,
    PyPi,
    Cargo,
    CMake,
    Go,
    Maven
}

/// <summary>Canonical advisory-feed names for each supported ecosystem.</summary>
public static class DependencyEcosystemNames
{
    /// <summary>Maps an ecosystem enum to its canonical feed-facing name.</summary>
    public static string ToCanonicalName(DependencyEcosystem ecosystem) => ecosystem switch
    {
        DependencyEcosystem.NuGet => "NuGet",
        DependencyEcosystem.Npm => "npm",
        DependencyEcosystem.PyPi => "PyPI",
        DependencyEcosystem.Cargo => "crates.io",
        DependencyEcosystem.CMake => "CMake",
        DependencyEcosystem.Go => "Go",
        DependencyEcosystem.Maven => "Maven",
        _ => "Unknown"
    };
}

/// <summary>One inventoried package reference from a single manifest file.</summary>
/// <param name="Name">Package name exactly as declared by its manager.</param>
/// <param name="Version">Pinned version, or null when the manifest does not pin one.</param>
/// <param name="IsDirect">True when the reference was declared directly rather than transitively.</param>
/// <param name="SourceFile">Display path of the manifest that declared the reference.</param>
/// <param name="SourceUrl">Remote fetch URL when the dependency is pulled from an external source (e.g. CMake FetchContent); null otherwise.</param>
public sealed record DependencyEntry(string Name, string? Version, bool IsDirect, string SourceFile, string? SourceUrl = null);

/// <summary>A recoverable content problem recorded during manifest parsing.</summary>
/// <param name="SourceFile">Display path of the offending manifest.</param>
/// <param name="SafeMessage">User-safe description of the problem.</param>
/// <param name="DiagnosticDetail">Log-only detail including the offending fragment class.</param>
public sealed record ParseIssue(string SourceFile, string SafeMessage, string DiagnosticDetail);

/// <summary>The complete parsed inventory of one dependency manifest file.</summary>
public sealed record DependencyManifest(
    DependencyEcosystem Ecosystem,
    IReadOnlyList<DependencyEntry> Entries,
    IReadOnlyList<ParseIssue> ParseIssues)
{
    /// <summary>An empty manifest carrying a single parse issue.</summary>
    public static DependencyManifest WithIssue(DependencyEcosystem ecosystem, string sourceFile, string safeMessage, string diagnosticDetail) =>
        new(ecosystem, [], [new ParseIssue(sourceFile, safeMessage, diagnosticDetail)]);
}

