
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using ACT.Contracts;

namespace ACT.DependencyAnalysis;

/// <summary>
/// Parses dependency manifests into a uniform <see cref="DependencyManifest"/> inventory.
/// Malformed file content is recorded as parse issues; unreadable files or streams fail closed.
/// </summary>
public sealed class ManifestParser
{
    /// <summary>Decides whether the given file name is a supported manifest.</summary>
    public static bool IsManifestFileName(string fileName)
    {
        if (fileName.EndsWith(".csproj", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return fileName.Equals("packages.lock.json", StringComparison.OrdinalIgnoreCase)
               || fileName.Equals("package-lock.json", StringComparison.OrdinalIgnoreCase)
               || fileName.Equals("requirements.txt", StringComparison.OrdinalIgnoreCase)
               || fileName.Equals("Cargo.toml", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Maps a supported manifest file name to its ecosystem.</summary>
    public static DependencyEcosystem EcosystemFor(string fileName)
    {
        var lower = fileName.ToLowerInvariant();
        return lower switch
        {
            var n when n.EndsWith(".csproj", StringComparison.Ordinal) => DependencyEcosystem.NuGet,
            "packages.lock.json" => DependencyEcosystem.NuGet,
            "package-lock.json" => DependencyEcosystem.Npm,
            "requirements.txt" => DependencyEcosystem.PyPi,
            "cargo.toml" => DependencyEcosystem.Cargo,
            _ => DependencyEcosystem.Unknown
        };
    }

    /// <summary>Opens and parses one manifest file from disk; unreadable files fail closed.</summary>
    public async Task<DependencyManifest> ParseFileAsync(string filePath, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        FileStream stream;
        try
        {
            stream = new FileStream(
                filePath, FileMode.Open, FileAccess.Read, FileShare.Read,
                bufferSize: 16 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException or IOException or UnauthorizedAccessException)
        {
            throw ActException.FailClosed(
                ErrorCategory.Parser,
                "A dependency manifest could not be opened for reading.",
                $"Opening manifest '{filePath}' failed: {ex.GetType().Name}: {ex.Message}",
                ex);
        }

        await using (stream.ConfigureAwait(false))
        {
            return await ParseAsync(Path.GetFileName(filePath), stream, filePath, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>Parses one manifest from an open stream; content problems become parse issues.</summary>
    public async Task<DependencyManifest> ParseAsync(
        string fileName,
        Stream contentStream,
        string sourceDisplayPath,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fileName);
        ArgumentNullException.ThrowIfNull(contentStream);

        var lower = fileName.ToLowerInvariant();
        if (lower.EndsWith(".csproj", StringComparison.Ordinal))
        {
            return await ParseCsprojAsync(contentStream, sourceDisplayPath, cancellationToken).ConfigureAwait(false);
        }

        if (lower is "packages.lock.json" or "package-lock.json")
        {
            return await ParseJsonLockAsync(lower, contentStream, sourceDisplayPath, cancellationToken).ConfigureAwait(false);
        }

        if (lower == "requirements.txt")
        {
            return await ParseRequirementsAsync(contentStream, sourceDisplayPath, cancellationToken).ConfigureAwait(false);
        }

        if (lower == "cargo.toml")
        {
            return await ParseCargoTomlAsync(contentStream, sourceDisplayPath, cancellationToken).ConfigureAwait(false);
        }

        return DependencyManifest.WithIssue(
            DependencyEcosystem.Unknown,
            sourceDisplayPath,
            "The file is not a supported dependency manifest format.",
            $"ParseAsync called with unsupported manifest name '{fileName}'.");
    }

    private static async Task<DependencyManifest> ParseCsprojAsync(Stream stream, string path, CancellationToken ct)
    {
        XDocument document;
        try
        {
            document = await XDocument.LoadAsync(stream, LoadOptions.None, ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is XmlException or InvalidOperationException)
        {
            return DependencyManifest.WithIssue(
                DependencyEcosystem.NuGet,
                path,
                "The project file is not well-formed XML and was skipped.",
                $"XML load failed for '{path}': {ex.Message}");
        }

        var entries = new List<DependencyEntry>();
        var issues = new List<ParseIssue>();
        foreach (var element in document.Descendants())
        {
            if (element.Name.LocalName != "PackageReference")
            {
                continue;
            }

            var include = element.Attribute("Include")?.Value.Trim();
            if (string.IsNullOrEmpty(include))
            {
                issues.Add(new ParseIssue(
                    path,
                    "A PackageReference is missing its Include attribute.",
                    $"PackageReference without Include in '{path}'."));
                continue;
            }

            var version = element.Attribute("Version")?.Value.Trim()
                          ?? element.Elements().FirstOrDefault(static e => e.Name.LocalName == "Version")?.Value.Trim();
            if (version is null)
            {
                issues.Add(new ParseIssue(
                    path,
                    "A PackageReference declares no Version and cannot be pinned.",
                    $"PackageReference '{include}' has no version in '{path}'."));
            }

            entries.Add(new DependencyEntry(include!, version, IsDirect: true, path));
        }

        return new DependencyManifest(DependencyEcosystem.NuGet, entries, issues);
    }

    private static async Task<DependencyManifest> ParseJsonLockAsync(string kind, Stream stream, string path, CancellationToken ct)
    {
        JsonDocument document;
        try
        {
            document = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (JsonException ex)
        {
            return DependencyManifest.WithIssue(
                EcosystemFor(kind),
                path,
                "The lock file is not valid JSON and was skipped.",
                $"JSON parse failed for '{path}': {ex.Message}");
        }

        using (document)
        {
            return kind == "packages.lock.json"
                ? ParsePackagesLock(document.RootElement, path)
                : ParseNpmPackageLock(document.RootElement, path);
        }
    }

    private static DependencyManifest ParsePackagesLock(JsonElement root, string path)
    {
        var entries = new List<DependencyEntry>();
        var issues = new List<ParseIssue>();
        if (!root.TryGetProperty("targets", out var targets) || targets.ValueKind != JsonValueKind.Object)
        {
            issues.Add(new ParseIssue(
                path,
                "The lock file has no targets section.",
                $"Missing 'targets' object in '{path}'."));
            return new DependencyManifest(DependencyEcosystem.NuGet, entries, issues);
        }

        foreach (var framework in targets.EnumerateObject())
        {
            if (framework.Value.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            foreach (var package in framework.Value.EnumerateObject())
            {
                if (package.Value.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var type = package.Value.TryGetProperty("type", out var typeElement) && typeElement.ValueKind == JsonValueKind.String
                    ? typeElement.GetString()
                    : null;
                if (type is "Project" or "CentralTransitiveDependencyGroup")
                {
                    continue;
                }

                var resolved = ReadString(package.Value, "resolved");
                var requested = ReadString(package.Value, "requested");
                var version = resolved ?? ExtractFirstVersionToken(requested);
                if (version is null)
                {
                    issues.Add(new ParseIssue(
                        path,
                        "A locked package entry exposes no resolvable version.",
                        $"Package '{package.Name}' in framework '{framework.Name}' of '{path}' has no usable version."));
                }

                entries.Add(new DependencyEntry(package.Name, version, IsDirect: type == "Direct", path));
            }
        }

        return new DependencyManifest(DependencyEcosystem.NuGet, entries, issues);
    }

    private static DependencyManifest ParseNpmPackageLock(JsonElement root, string path)
    {
        var entries = new List<DependencyEntry>();
        var issues = new List<ParseIssue>();
        var lockfileVersion = root.TryGetProperty("lockfileVersion", out var flag) && flag.ValueKind == JsonValueKind.Number
            ? flag.GetInt32()
            : 2;

        if (lockfileVersion >= 2 && root.TryGetProperty("packages", out var packages) && packages.ValueKind == JsonValueKind.Object)
        {
            var directNames = new HashSet<string>(StringComparer.Ordinal);
            if (packages.TryGetProperty("", out var projectRoot)
                && projectRoot.ValueKind == JsonValueKind.Object
                && projectRoot.TryGetProperty("dependencies", out var declared)
                && declared.ValueKind == JsonValueKind.Object)
            {
                foreach (var dep in declared.EnumerateObject())
                {
                    directNames.Add(dep.Name);
                }
            }

            const string Marker = "node_modules/";
            foreach (var packageKey in packages.EnumerateObject())
            {
                if (packageKey.Name.Length == 0 || packageKey.Value.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var markerIndex = packageKey.Name.LastIndexOf(Marker, StringComparison.Ordinal);
                var name = markerIndex >= 0 ? packageKey.Name[(markerIndex + Marker.Length)..] : packageKey.Name;
                var version = ReadString(packageKey.Value, "version");
                if (version is null)
                {
                    issues.Add(new ParseIssue(
                        path,
                        "A lock file package entry has no version.",
                        $"Entry '{packageKey.Name}' lacks 'version' in '{path}'."));
                }

                entries.Add(new DependencyEntry(name, version, directNames.Contains(name), path));
            }
        }
        else if (root.TryGetProperty("dependencies", out var dependencies) && dependencies.ValueKind == JsonValueKind.Object)
        {
            CollectNpmV1Entries(dependencies, isTopLevel: true, entries, issues, path);
        }

        return new DependencyManifest(DependencyEcosystem.Npm, entries, issues);
    }

    private static void CollectNpmV1Entries(
        JsonElement dependencies,
        bool isTopLevel,
        ICollection<DependencyEntry> entries,
        ICollection<ParseIssue> issues,
        string path)
    {
        foreach (var dependency in dependencies.EnumerateObject())
        {
            if (dependency.Value.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var version = ReadString(dependency.Value, "version");
            if (version is null)
            {
                issues.Add(new ParseIssue(
                    path,
                    "A lock file package entry has no version.",
                    $"v1 entry '{dependency.Name}' lacks 'version' in '{path}'."));
            }

            entries.Add(new DependencyEntry(dependency.Name, version, isTopLevel, path));
            if (dependency.Value.TryGetProperty("dependencies", out var nested) && nested.ValueKind == JsonValueKind.Object)
            {
                CollectNpmV1Entries(nested, isTopLevel: false, entries, issues, path);
            }
        }
    }

    private static async Task<DependencyManifest> ParseRequirementsAsync(Stream stream, string path, CancellationToken ct)
    {
        var entries = new List<DependencyEntry>();
        var issues = new List<ParseIssue>();
        try
        {
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
            while ((await reader.ReadLineAsync(ct).ConfigureAwait(false)) is { } line)
            {
                var trimmed = line.Trim();
                if (trimmed.Length == 0 || trimmed[0] == '#')
                {
                    continue;
                }

                if (trimmed[0] == '-')
                {
                    issues.Add(new ParseIssue(
                        path,
                        "A requirements option line was ignored during inventory.",
                        $"Option line '{trimmed}' ignored in '{path}'."));
                    continue;
                }

                var specifier = CutAtFirst(trimmed, ';').Trim();
                var pinIndex = specifier.IndexOf("==", StringComparison.Ordinal);
                if (pinIndex < 0)
                {
                    issues.Add(new ParseIssue(
                        path,
                        "A requirement is unpinned and was excluded from the inventory.",
                        $"Unpinned requirement '{specifier}' in '{path}'."));
                    continue;
                }

                var namePart = CutAtFirst(specifier[..pinIndex].Trim(), '[').Trim();
                var versionText = specifier[(pinIndex + 2)..].Trim();
                if (versionText.Length > 0 && versionText[0] == '=')
                {
                    versionText = versionText[1..].Trim();
                }

                if (!IsValidSimpleName(namePart, allowDot: true))
                {
                    issues.Add(new ParseIssue(
                        path,
                        "A requirement name is malformed and was skipped.",
                        $"Malformed python package name '{namePart}' in '{path}'."));
                    continue;
                }

                entries.Add(new DependencyEntry(namePart.ToLowerInvariant(), NormalizePinned(versionText), IsDirect: true, path));
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw ActException.FailClosed(
                ErrorCategory.Parser,
                "A requirements file could not be read to completion.",
                $"Reading '{path}' failed: {ex.GetType().Name}: {ex.Message}",
                ex);
        }

        return new DependencyManifest(DependencyEcosystem.PyPi, entries, issues);
    }

    private static async Task<DependencyManifest> ParseCargoTomlAsync(Stream stream, string path, CancellationToken ct)
    {
        var entries = new List<DependencyEntry>();
        var issues = new List<ParseIssue>();
        var sectionIsActive = false;
        try
        {
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
            while ((await reader.ReadLineAsync(ct).ConfigureAwait(false)) is { } line)
            {
                var trimmed = StripTomlComment(line).Trim();
                if (trimmed.Length == 0)
                {
                    continue;
                }

                if (trimmed[0] == '[')
                {
                    var header = trimmed.Trim('[', ']').Trim();
                    sectionIsActive = header.Equals("dependencies", StringComparison.OrdinalIgnoreCase)
                                      || header.Equals("dev-dependencies", StringComparison.OrdinalIgnoreCase)
                                      || header.Equals("build-dependencies", StringComparison.OrdinalIgnoreCase);
                    continue;
                }

                if (!sectionIsActive)
                {
                    continue;
                }

                var eq = trimmed.IndexOf('=');
                if (eq <= 0)
                {
                    issues.Add(new ParseIssue(
                        path,
                        "A Cargo.toml dependency line is malformed.",
                        $"Line '{trimmed}' has no key=value form in '{path}'."));
                    continue;
                }

                var name = trimmed[..eq].Trim();
                var value = trimmed[(eq + 1)..].Trim();
                if (!IsValidSimpleName(name, allowDot: false))
                {
                    issues.Add(new ParseIssue(
                        path,
                        "A Cargo.toml dependency name is malformed.",
                        $"Invalid crate name '{name}' in '{path}'."));
                    continue;
                }

                string? version;
                if (value.Length > 0 && value[0] == '"')
                {
                    var closing = value.IndexOf('"', 1);
                    if (closing < 0)
                    {
                        issues.Add(new ParseIssue(
                            path,
                            "A Cargo.toml version literal is unterminated.",
                            $"Unterminated quote after crate '{name}' in '{path}'."));
                        version = null;
                    }
                    else
                    {
                        version = value[1..closing];
                    }
                }
                else if (value.Length > 0 && value[0] == '{')
                {
                    version = ExtractInlineTomlVersion(value);
                    if (version is null)
                    {
                        issues.Add(new ParseIssue(
                            path,
                            "A Cargo.toml table-form dependency declares no pinned version.",
                            $"Crate '{name}' uses an inline table without 'version' in '{path}'."));
                    }
                }
                else
                {
                    issues.Add(new ParseIssue(
                        path,
                        "A Cargo.toml dependency value form is unsupported.",
                        $"Unsupported value for crate '{name}' in '{path}'."));
                    version = null;
                }

                entries.Add(new DependencyEntry(name, version, IsDirect: true, path));
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw ActException.FailClosed(
                ErrorCategory.Parser,
                "Cargo.toml could not be read to completion.",
                $"Reading '{path}' failed: {ex.GetType().Name}: {ex.Message}",
                ex);
        }

        return new DependencyManifest(DependencyEcosystem.Cargo, entries, issues);
    }

    private static string? ReadString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;

    private static string CutAtFirst(string text, char separator)
    {
        var index = text.IndexOf(separator);
        return index < 0 ? text : text[..index];
    }

    private static string? NormalizePinned(string version) =>
        SemanticVersion.TryParse(version, out _) ? version : version.Length == 0 ? null : version;

    private static bool IsValidSimpleName(string name, bool allowDot)
    {
        if (name.Length == 0)
        {
            return false;
        }

        foreach (var character in name)
        {
            var allowed = char.IsAsciiLetterOrDigit(character)
                          || character is '-' or '_'
                          || (allowDot && character == '.');
            if (!allowed)
            {
                return false;
            }
        }

        return true;
    }

    private static string StripTomlComment(string line)
    {
        var inString = false;
        for (var i = 0; i < line.Length; i++)
        {
            var character = line[i];
            if (character == '"')
            {
                inString = !inString;
            }
            else if (character == '#' && !inString)
            {
                return line[..i];
            }
        }

        return line;
    }

    private static string? ExtractInlineTomlVersion(string inlineTable)
    {
        // Matches both { version = "1.2.3" } and { "version": "1.2.3" } forms.
        foreach (var form in new[] { "version =", "\"version\":" })
        {
            var keyIndex = inlineTable.IndexOf(form, StringComparison.Ordinal);
            if (keyIndex < 0)
            {
                continue;
            }

            var openQuote = inlineTable.IndexOf('"', keyIndex + form.Length);
            if (openQuote < 0)
            {
                continue;
            }

            var closeQuote = inlineTable.IndexOf('"', openQuote + 1);
            if (closeQuote > openQuote)
            {
                return inlineTable[(openQuote + 1)..closeQuote];
            }
        }

        return null;
    }

    private static string? ExtractFirstVersionToken(string? requestedRange)
    {
        if (string.IsNullOrWhiteSpace(requestedRange))
        {
            return null;
        }

        int start = -1, end = -1;
        for (var i = 0; i < requestedRange.Length; i++)
        {
            var character = requestedRange[i];
            if (char.IsAsciiDigit(character))
            {
                if (start < 0)
                {
                    start = i;
                }
                else if (!(character == '.' || char.IsAsciiDigit(character)) && end < 0)
                {
                    end = i;
                    break;
                }
            }
            else if (start >= 0)
            {
                end = i;
                break;
            }
        }

        if (start < 0)
        {
            return null;
        }

        return requestedRange[start..(end < 0 ? requestedRange.Length : end)];
    }
}

