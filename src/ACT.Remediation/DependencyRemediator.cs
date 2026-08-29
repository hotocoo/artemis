using System.Text.RegularExpressions;

namespace ACT.Remediation;

/// <summary>The outcome of one dependency manifest remediation attempt.</summary>
public sealed record DependencyRemediationResult(
    bool Updated,
    string ManifestPath,
    string PackageName,
    string? PreviousVersion,
    string? NewVersion,
    string Detail);

/// <summary>
/// Fixes vulnerable dependencies on the spot by updating the pinned version in the source
/// manifest to the advisory's fixed version. Supports NuGet, npm, PyPI, and Cargo manifests.
/// The change is a surgical, single-package edit that preserves the rest of the manifest.
/// </summary>
public static class DependencyRemediator
{
    /// <summary>
    /// Updates the pinned version of a package in a manifest to the given version.
    /// Fails closed (no partial writes) when the package cannot be located.
    /// </summary>
    public static async Task<DependencyRemediationResult> UpdateVersionAsync(
        string manifestPath, string packageName, string newVersion, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(manifestPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(packageName);
        ArgumentException.ThrowIfNullOrWhiteSpace(newVersion);

        if (!File.Exists(manifestPath))
        {
            return new DependencyRemediationResult(false, manifestPath, packageName, null, null,
                "Manifest not found: " + manifestPath);
        }

        var original = await File.ReadAllTextAsync(manifestPath, cancellationToken).ConfigureAwait(false);
        var (updated, previousVersion) = Rewrite(original, packageName, newVersion);
        if (updated is null)
        {
            return new DependencyRemediationResult(false, manifestPath, packageName, previousVersion, null,
                $"Package '{packageName}' was not found in {Path.GetFileName(manifestPath)}; nothing changed.");
        }

        await File.WriteAllTextAsync(manifestPath, updated, cancellationToken).ConfigureAwait(false);
        return new DependencyRemediationResult(true, manifestPath, packageName, previousVersion, newVersion,
            $"Updated {packageName} {FormatVersion(previousVersion)} -> {newVersion} in {Path.GetFileName(manifestPath)}.");
    }

    /// <summary>Resolves the full path of a manifest given a repository root and a reference.</summary>
    public static string ResolveManifestPath(string repoRoot, string manifestReference)
    {
        if (Path.IsPathRooted(manifestReference))
        {
            return manifestReference;
        }
        return Path.GetFullPath(Path.Combine(repoRoot, manifestReference));
    }

    private static (string? Content, string? PreviousVersion) Rewrite(string content, string packageName, string newVersion)
    {
        if (LooksLikeCsproj(content))
        {
            return RewriteCsproj(content, packageName, newVersion);
        }
        if (LooksLikeRequirementsTxt(content))
        {
            return RewriteRequirementsTxt(content, packageName, newVersion);
        }
        if (LooksLikeCargoToml(content))
        {
            return RewriteCargoToml(content, packageName, newVersion);
        }
        return RewriteJson(content, packageName, newVersion);
    }

    private static bool LooksLikeCsproj(string content) =>
        content.Contains("<Project", StringComparison.OrdinalIgnoreCase) &&
        content.Contains("PackageReference", StringComparison.OrdinalIgnoreCase);

    private static bool LooksLikeRequirementsTxt(string content) =>
        content.Split('\n').Any(l => l.Trim().Contains("==") && !l.TrimStart().StartsWith("#"));

    private static bool LooksLikeCargoToml(string content) =>
        content.Contains("[dependencies", StringComparison.OrdinalIgnoreCase);

    // NuGet .csproj: <PackageReference Include="name" Version="old" />
    private static (string?, string?) RewriteCsproj(string content, string packageName, string newVersion)
    {
        var includeMarker = "Include=\"" + packageName + "\"";
        var includeIndex = content.IndexOf(includeMarker, StringComparison.OrdinalIgnoreCase);
        if (includeIndex < 0)
        {
            return (null, null);
        }

        // Find the end of this PackageReference tag.
        var tagEnd = content.IndexOf(">", includeIndex);
        if (tagEnd < 0)
        {
            return (null, null);
        }

        var tag = content.Substring(includeIndex, tagEnd - includeIndex + 1);
        var versionMatch = Regex.Match(tag, "Version=\"([^\"]*)\"", RegexOptions.IgnoreCase);
        var previous = versionMatch.Success ? versionMatch.Groups[1].Value : null;

        string updatedTag;
        if (versionMatch.Success)
        {
            updatedTag = tag.Replace("Version=\"" + versionMatch.Groups[1].Value + "\"", "Version=\"" + newVersion + "\"");
        }
        else
        {
            updatedTag = tag.Replace(includeMarker, includeMarker + " Version=\"" + newVersion + "\"");
        }

        var newContent = content.Replace(tag, updatedTag);
        return (newContent, previous);
    }

    // requirements.txt: name==old
    private static (string?, string?) RewriteRequirementsTxt(string content, string packageName, string newVersion)
    {
        var lines = content.Split('\n');
        var found = false;
        string? previous = null;
        for (var i = 0; i < lines.Length; i++)
        {
            var trimmed = lines[i].TrimStart();
            if (trimmed.StartsWith(packageName + "==", StringComparison.OrdinalIgnoreCase))
            {
                var afterEq = trimmed.Substring(packageName.Length + 2).TrimEnd();
                previous = afterEq;
                lines[i] = lines[i].Replace(trimmed, packageName + "==" + newVersion);
                found = true;
                break;
            }
        }

        return found ? (string.Join("\n", lines), previous) : (null, previous);
    }

    // Cargo.toml: name = "old" under [dependencies]
    private static (string?, string?) RewriteCargoToml(string content, string packageName, string newVersion)
    {
        var marker = packageName + " =";
        var index = content.IndexOf(marker, StringComparison.Ordinal);
        if (index < 0)
        {
            return (null, null);
        }

        var afterMarker = index + marker.Length;
        var firstQuote = content.IndexOf('"', afterMarker);
        if (firstQuote < 0)
        {
            return (null, null);
        }

        var secondQuote = content.IndexOf('"', firstQuote + 1);
        if (secondQuote < 0)
        {
            return (null, null);
        }

        var previous = content.Substring(firstQuote + 1, secondQuote - firstQuote - 1);
        var newContent = content.Substring(0, firstQuote + 1) + newVersion + content.Substring(secondQuote);
        return (newContent, previous);
    }

    // package.json / lock files: "name": "old"
    private static (string?, string?) RewriteJson(string content, string packageName, string newVersion)
    {
        var key = "\"" + packageName + "\"";
        var keyIndex = content.IndexOf(key, StringComparison.Ordinal);
        if (keyIndex < 0)
        {
            return (null, null);
        }

        var colonIndex = content.IndexOf(':', keyIndex + key.Length);
        if (colonIndex < 0)
        {
            return (null, null);
        }

        var valueStart = content.IndexOf('"', colonIndex + 1);
        if (valueStart < 0)
        {
            return (null, null);
        }

        var valueEnd = content.IndexOf('"', valueStart + 1);
        if (valueEnd < 0)
        {
            return (null, null);
        }

        var previous = content.Substring(valueStart + 1, valueEnd - valueStart - 1);
        var newContent = content.Substring(0, valueStart + 1) + newVersion + content.Substring(valueEnd);
        return (newContent, previous);
    }

    private static string FormatVersion(string? version) =>
        string.IsNullOrWhiteSpace(version) ? "(unpinned)" : version;
}
