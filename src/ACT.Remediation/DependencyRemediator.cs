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
/// manifest to the advisory's fixed version. Supports NuGet, npm, PyPI, Cargo, and Maven
/// manifests. The change is a surgical, single-package edit that preserves the rest of the
/// manifest; formats the engine cannot confidently edit are reported as not updated rather
/// than rewritten blindly.
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
        if (LooksLikePomXml(content))
        {
            return RewritePomXml(content, packageName, newVersion);
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

    private static bool LooksLikePomXml(string content) =>
        content.Contains("<project", StringComparison.OrdinalIgnoreCase) &&
        content.Contains("<dependency>", StringComparison.OrdinalIgnoreCase);

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

    // pom.xml: <dependency><groupId>group</groupId><artifactId>artifact</artifactId><version>old</version></dependency>
    // packageName arrives as "groupId:artifactId". Find the matching dependency element and rewrite
    // its <version>OLD</version> child in place; the rest of the file is untouched. Dependencies
    // inside <dependencyManagement> are deliberately skipped so the rewriter never silently
    // changes the central pin for every transitive consumer.
    private static (string?, string?) RewritePomXml(string content, string packageName, string newVersion)
    {
        var separatorIndex = packageName.IndexOf(':');
        if (separatorIndex <= 0 || separatorIndex == packageName.Length - 1)
        {
            return (null, null);
        }

        var groupId = packageName[..separatorIndex];
        var artifactId = packageName[(separatorIndex + 1)..];

        var groupIdStart = content.IndexOf("<groupId>", StringComparison.OrdinalIgnoreCase);
        while (groupIdStart >= 0)
        {
            var groupIdOpenEnd = groupIdStart + "<groupId>".Length;
            var groupIdCloseStart = content.IndexOf("</groupId>", groupIdOpenEnd, StringComparison.OrdinalIgnoreCase);
            if (groupIdCloseStart < 0)
            {
                return (null, null);
            }

            var actualGroupId = content[groupIdOpenEnd..groupIdCloseStart];
            if (string.Equals(actualGroupId, groupId, StringComparison.Ordinal))
            {
                var depOpen = content.LastIndexOf("<dependency>", groupIdStart, StringComparison.OrdinalIgnoreCase);
                var depClose = content.IndexOf("</dependency>", groupIdCloseStart, StringComparison.OrdinalIgnoreCase);
                if (depOpen < 0 || depClose < 0)
                {
                    return (null, null);
                }

                // A dependency that lives inside <dependencyManagement> sets the central pin for
                // every consumer. Touching it would silently change versions across the project,
                // so we deliberately leave managed entries alone and prefer the first literal
                // <version> in the project's <dependencies> block.
                var depMgmtOpen = content.LastIndexOf("<dependencyManagement>", depOpen, StringComparison.OrdinalIgnoreCase);
                var depMgmtClose = content.LastIndexOf("</dependencyManagement>", depOpen, StringComparison.OrdinalIgnoreCase);
                if (depMgmtOpen > depMgmtClose)
                {
                    groupIdStart = content.IndexOf("<groupId>", groupIdCloseStart, StringComparison.OrdinalIgnoreCase);
                    continue;
                }

                var dependencyBlock = content.Substring(depOpen, depClose - depOpen + "</dependency>".Length);
                var artifactIdNeedle = "<artifactId>" + artifactId + "</artifactId>";
                if (dependencyBlock.IndexOf(artifactIdNeedle, StringComparison.OrdinalIgnoreCase) < 0)
                {
                    // Group matched a different dependency; keep scanning in case the same groupId
                    // appears for multiple artifacts.
                    groupIdStart = content.IndexOf("<groupId>", groupIdCloseStart, StringComparison.OrdinalIgnoreCase);
                    continue;
                }

                var versionMatch = Regex.Match(dependencyBlock, "<version>([^<]*)</version>", RegexOptions.IgnoreCase);
                if (!versionMatch.Success)
                {
                    // This dependency has no literal <version> child to rewrite; it relies on
                    // <dependencyManagement> or a property reference. Continue scanning for a
                    // literal to upgrade; if none exists we fail closed below.
                    groupIdStart = content.IndexOf("<groupId>", groupIdCloseStart, StringComparison.OrdinalIgnoreCase);
                    continue;
                }

                var previousVersion = versionMatch.Groups[1].Value;
                var updatedBlock = dependencyBlock[..versionMatch.Index]
                                   + "<version>" + newVersion + "</version>"
                                   + dependencyBlock[(versionMatch.Index + versionMatch.Length)..];
                var newContent = content[..depOpen] + updatedBlock + content[(depOpen + dependencyBlock.Length)..];
                return (newContent, previousVersion);
            }

            groupIdStart = content.IndexOf("<groupId>", groupIdCloseStart, StringComparison.OrdinalIgnoreCase);
        }

        return (null, null);
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
