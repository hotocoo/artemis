
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
               || fileName.Equals("Cargo.toml", StringComparison.OrdinalIgnoreCase)
               || fileName.Equals("CMakeLists.txt", StringComparison.OrdinalIgnoreCase)
               || fileName.Equals("go.mod", StringComparison.OrdinalIgnoreCase);
    }
    /// <summary>
    /// Parses a go.mod file, extracting dependencies from require blocks.
    /// Indirect dependencies are marked as not direct.
    /// </summary>
    private static async Task<DependencyManifest> ParseGoModAsync(Stream stream, string path, CancellationToken ct)
    {
        var entries = new List<DependencyEntry>();
        var issues = new List<ParseIssue>();
        var seenNames = new HashSet<string>(StringComparer.Ordinal);

        try
        {
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
            var inRequireBlock = false;

            while ((await reader.ReadLineAsync(ct).ConfigureAwait(false)) is { } line)
            {
                var trimmed = line.Trim();

                // Skip comments and empty lines
                if (trimmed.Length == 0 || trimmed.StartsWith("//"))
                {
                    continue;
                }

                // Detect require block start
                if (trimmed.StartsWith("require (", StringComparison.Ordinal))
                {
                    inRequireBlock = true;
                    continue;
                }

                // Detect require block end
                if (inRequireBlock && trimmed == ")")
                {
                    inRequireBlock = false;
                    continue;
                }

                // Parse require entries inside a block
                if (inRequireBlock)
                {
                    var (name, version, isIndirect) = ParseGoRequireLine(trimmed);
                    if (name is not null && version is not null && seenNames.Add(name))
                    {
                        entries.Add(new DependencyEntry(name, version, IsDirect: !isIndirect, path));
                    }
                    continue;
                }

                // Handle single-line require statements: require module version
                if (trimmed.StartsWith("require ", StringComparison.Ordinal))
                {
                    var parts = trimmed.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                    if (parts.Length >= 2)
                    {
                        var name = parts[1];
                        var version = parts[2];
                        var isIndirect = trimmed.Contains("// indirect", StringComparison.Ordinal);
                        if (IsValidGoModuleName(name) && seenNames.Add(name))
                        {
                            entries.Add(new DependencyEntry(name, version, IsDirect: !isIndirect, path));
                        }
                    }
                }
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
                "A go.mod file could not be read to completion.",
                $"Reading '{path}' failed: {ex.GetType().Name}: {ex.Message}",
                ex);
        }

        return new DependencyManifest(DependencyEcosystem.Go, entries, issues);
    }

    /// <summary>Parses a require line inside a require block, returning name, version, and indirect flag.</summary>
    private static (string? Name, string? Version, bool IsIndirect) ParseGoRequireLine(string line)
    {
        // Remove inline comments
        var commentIndex = line.IndexOf("//", StringComparison.Ordinal);
        var isIndirect = commentIndex >= 0 && line[commentIndex..].Contains("indirect", StringComparison.Ordinal);
        if (commentIndex >= 0)
        {
            line = line[..commentIndex].TrimEnd();
        }

        var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length >= 2)
        {
            var name = parts[0];
            var version = parts[1];
            if (IsValidGoModuleName(name))
            {
                return (name, version, isIndirect);
            }
        }

        return (null, null, false);
    }

    /// <summary>True when the name is a valid Go module path.</summary>
    private static bool IsValidGoModuleName(string name)
    {
        if (name.Length == 0)
        {
            return false;
        }

        // Go module names must start with a letter or digit and contain only valid characters
        if (!char.IsLetterOrDigit(name[0]))
        {
            return false;
        }

        foreach (var c in name)
        {
            if (!char.IsLetterOrDigit(c) && c is not ('.' or '-' or '_' or '/'))
            {
                return false;
            }
        }

        return true;
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
            "cmakelists.txt" => DependencyEcosystem.CMake,
            "go.mod" => DependencyEcosystem.Go,
            "pom.xml" => DependencyEcosystem.Maven,
            "build.gradle" => DependencyEcosystem.Gradle,
            "build.gradle.kts" => DependencyEcosystem.Gradle,
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

        if (lower == "cmakelists.txt")
        {
            return await ParseCMakeListsAsync(contentStream, sourceDisplayPath, cancellationToken).ConfigureAwait(false);
        }

        if (lower == "go.mod")
        {
            return await ParseGoModAsync(contentStream, sourceDisplayPath, cancellationToken).ConfigureAwait(false);
        }

        if (lower == "pom.xml")
        {
            return await ParsePomXmlAsync(contentStream, sourceDisplayPath, cancellationToken).ConfigureAwait(false);
        }

        if (lower == "build.gradle" || lower == "build.gradle.kts")
        {
            return await ParseBuildGradleAsync(contentStream, sourceDisplayPath, cancellationToken).ConfigureAwait(false);
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

    /// <summary>
    /// Parses a CMakeLists.txt file, extracting FetchContent_Declare and find_package
    /// dependency declarations. CMake git dependencies have no canonical advisory feed;
    /// the consuming check evaluates supply-chain hygiene (transport, pinning) directly.
    /// </summary>
    private static async Task<DependencyManifest> ParseCMakeListsAsync(Stream stream, string path, CancellationToken ct)
    {
        var entries = new List<DependencyEntry>();
        var issues = new List<ParseIssue>();
        var seenNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
            var lines = new List<string>();
            while ((await reader.ReadLineAsync(ct).ConfigureAwait(false)) is { } line)
            {
                lines.Add(StripCMakeComment(line));
            }

            for (var i = 0; i < lines.Count; i++)
            {
                if (TryAccumulateCMakeCommand(lines, ref i, "FetchContent_Declare", out var fetchBuffer))
                {
                    var entry = ParseFetchContentDeclare(fetchBuffer, path, issues);
                    if (entry is not null && seenNames.Add(entry.Name))
                    {
                        entries.Add(entry);
                    }

                    continue;
                }

                if (TryAccumulateCMakeCommand(lines, ref i, "find_package", out var findBuffer))
                {
                    var entry = ParseFindPackage(findBuffer, path, issues);
                    if (entry is not null && seenNames.Add(entry.Name))
                    {
                        entries.Add(entry);
                    }
                }
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
                "A CMakeLists.txt file could not be read to completion.",
                $"Reading '{path}' failed: {ex.GetType().Name}: {ex.Message}",
                ex);
        }

        return new DependencyManifest(DependencyEcosystem.CMake, entries, issues);
    }

    /// <summary>
    /// Detects the given CMake command at or after <paramref name="index"/> and, when found,
    /// accumulates subsequent lines until the command's parentheses balance. Advances
    /// <paramref name="index"/> to the last consumed line and returns the full command text.
    /// </summary>
    private static bool TryAccumulateCMakeCommand(List<string> lines, ref int index, string command, out string buffer)
    {
        buffer = string.Empty;
        for (var scan = index; scan < lines.Count; scan++)
        {
            var line = lines[scan].Trim();
            if (line.Length == 0)
            {
                continue;
            }

            var commandIndex = line.IndexOf(command, StringComparison.OrdinalIgnoreCase);
            if (commandIndex < 0)
            {
                continue;
            }

            // Confirm a whole-word command occurrence, not a substring of a longer token.
            var beforeOk = commandIndex == 0 || char.IsWhiteSpace(line[commandIndex - 1]);
            var after = commandIndex + command.Length;
            var afterOk = after >= line.Length || line[after] is '(' or ' ' or '\t';
            if (!beforeOk || !afterOk)
            {
                continue;
            }

            buffer = line[commandIndex..];
            var last = scan;
            while (!CMakeParensBalanced(buffer) && last + 1 < lines.Count)
            {
                last++;
                buffer += " " + lines[last].Trim();
            }

            index = last;
            return true;
        }

        return false;
    }

    /// <summary>True when the buffer contains at least one opening paren and all are closed.</summary>
    private static bool CMakeParensBalanced(string text)
    {
        var depth = 0;
        var seenOpen = false;
        var inQuote = false;
        var quoteChar = '\0';
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (inQuote)
            {
                if (c == quoteChar)
                {
                    inQuote = false;
                }

                continue;
            }

            if (c is '"' or '\'')
            {
                inQuote = true;
                quoteChar = c;
                continue;
            }

            if (c == '(')
            {
                depth++;
                seenOpen = true;
            }
            else if (c == ')')
            {
                depth--;
            }
        }

        return seenOpen && depth <= 0;
    }

    /// <summary>Removes a CMake # comment while respecting quoted strings.</summary>
    private static string StripCMakeComment(string line)
    {
        var inQuote = false;
        var quoteChar = '\0';
        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];
            if (inQuote)
            {
                if (c == quoteChar)
                {
                    inQuote = false;
                }

                continue;
            }

            if (c is '"' or '\'')
            {
                inQuote = true;
                quoteChar = c;
                continue;
            }

            if (c == '#')
            {
                return line[..i];
            }
        }

        return line;
    }

    private static DependencyEntry? ParseFetchContentDeclare(string buffer, string path, List<ParseIssue> issues)
    {
        var openParen = buffer.IndexOf('(');
        if (openParen < 0)
        {
            return null;
        }

        var rest = buffer[(openParen + 1)..].Trim();
        var name = CutAtFirstToken(rest);
        if (name.Length == 0 || !IsValidCMakeIdentifier(name))
        {
            issues.Add(new ParseIssue(
                path,
                "A FetchContent declaration has no recognizable dependency name.",
                $"FetchContent_Declare without a valid name in '{path}'."));
            return null;
        }

        var url = ExtractCMakeOption(buffer, "GIT_REPOSITORY")
                  ?? ExtractCMakeOption(buffer, "URL");
        var tag = ExtractCMakeOption(buffer, "GIT_TAG");
        return new DependencyEntry(name, tag, IsDirect: true, path, SourceUrl: url);
    }

    private static DependencyEntry? ParseFindPackage(string buffer, string path, List<ParseIssue> issues)
    {
        var openParen = buffer.IndexOf('(');
        if (openParen < 0)
        {
            return null;
        }

        var rest = buffer[(openParen + 1)..].Trim().TrimEnd(')', ' ');
        var name = CutAtFirstToken(rest);
        if (name.Length == 0 || !IsValidCMakeIdentifier(name))
        {
            return null;
        }

        var tokens = rest.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        string? version = null;
        if (tokens.Length >= 2 && IsVersionLikeToken(tokens[1]))
        {
            version = tokens[1].TrimEnd(')');
        }

        return new DependencyEntry(name, version, IsDirect: true, path);
    }

    /// <summary>Extracts the value of a CMake option (e.g. GIT_REPOSITORY, GIT_TAG) from a command buffer.</summary>
    private static string? ExtractCMakeOption(string buffer, string option)
    {
        var match = System.Text.RegularExpressions.Regex.Match(
            buffer,
            $@"(?i)\b{option}\s+(""[^""]*""|'[^']*'|[^)\s]+)");
        if (!match.Success)
        {
            return null;
        }

        var value = match.Groups[1].Value.Trim('"', '\'');
        return value.Length > 0 ? value : null;
    }

    /// <summary>Returns the first whitespace-delimited token of the text.</summary>
    private static string CutAtFirstToken(string text)
    {
        text = text.TrimStart();
        var i = 0;
        while (i < text.Length && !char.IsWhiteSpace(text[i]))
        {
            i++;
        }

        return text[..i];
    }

    /// <summary>True when the token looks like a version constraint (starts with a digit or comparison operator).</summary>
    private static bool IsVersionLikeToken(string token)
    {
        if (token.Length == 0)
        {
            return false;
        }

        var first = token[0];
        return char.IsDigit(first)
               || (first is '>' or '<' or '=' && token.Length > 1 && char.IsDigit(token[1]));
    }

    /// <summary>True when the name is a valid CMake identifier (letters, digits, underscore, hyphen).</summary>
    private static bool IsValidCMakeIdentifier(string name)
    {
        if (name.Length == 0)
        {
            return false;
        }

        foreach (var c in name)
        {
            if (!char.IsLetterOrDigit(c) && c != '_' && c != '-')
            {
                return false;
            }
        }

        return true;
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
    /// <summary>
    /// Parses a pom.xml file, extracting dependencies from the dependencies section.
    /// All dependencies are marked as direct (Maven doesn't distinguish in the manifest).
    /// </summary>
    private static async Task<DependencyManifest> ParsePomXmlAsync(Stream stream, string path, CancellationToken ct)
    {
        var entries = new List<DependencyEntry>();
        var issues = new List<ParseIssue>();
        var seenNames = new HashSet<string>(StringComparer.Ordinal);

        try
        {
            var document = await XDocument.LoadAsync(stream, LoadOptions.None, ct).ConfigureAwait(false);

            // Find all dependency elements
            var dependencies = document.Descendants()
                .Where(x => x.Name.LocalName == "dependency")
                .ToList();

            foreach (var dep in dependencies)
            {
                var groupId = dep.Elements()
                    .FirstOrDefault(x => x.Name.LocalName == "groupId")?.Value;
                var artifactId = dep.Elements()
                    .FirstOrDefault(x => x.Name.LocalName == "artifactId")?.Value;
                var version = dep.Elements()
                    .FirstOrDefault(x => x.Name.LocalName == "version")?.Value;

                if (groupId is null || artifactId is null)
                {
                    continue;
                }

                var name = groupId + ":" + artifactId;
                if (seenNames.Add(name))
                {
                    entries.Add(new DependencyEntry(name, version, IsDirect: true, path));
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is XmlException or IOException or UnauthorizedAccessException)
        {
            throw ActException.FailClosed(
                ErrorCategory.Parser,
                "A pom.xml file could not be read to completion.",
                $"Reading '{path}' failed: {ex.GetType().Name}: {ex.Message}",
                ex);
        }

        return new DependencyManifest(DependencyEcosystem.Maven, entries, issues);
    }
    /// <summary>
    /// Parses a build.gradle file, extracting dependencies from the dependencies block.
    /// All dependencies are marked as direct (Gradle doesn't distinguish in the manifest).
    /// </summary>
    private static async Task<DependencyManifest> ParseBuildGradleAsync(Stream stream, string path, CancellationToken ct)
    {
        var entries = new List<DependencyEntry>();
        var issues = new List<ParseIssue>();
        var seenNames = new HashSet<string>(StringComparer.Ordinal);

        try
        {
            using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
            var inDependenciesBlock = false;

            while ((await reader.ReadLineAsync(ct).ConfigureAwait(false)) is { } line)
            {
                var trimmed = line.Trim();

                // Skip comments and empty lines
                if (trimmed.Length == 0 || trimmed.StartsWith("//") || trimmed.StartsWith("/*"))
                {
                    continue;
                }

                // Detect dependencies block start
                if (trimmed.StartsWith("dependencies {", StringComparison.Ordinal))
                {
                    inDependenciesBlock = true;
                    continue;
                }

                // Detect dependencies block end
                if (inDependenciesBlock && trimmed == "}")
                {
                    inDependenciesBlock = false;
                    continue;
                }

                // Parse dependency entries inside the block
                if (inDependenciesBlock)
                {
                    var (name, version) = ParseGradleDependencyLine(trimmed);
                    if (name is not null && seenNames.Add(name))
                    {
                        entries.Add(new DependencyEntry(name, version, IsDirect: true, path));
                    }
                }
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
                "A build.gradle file could not be read to completion.",
                $"Reading '{path}' failed: {ex.GetType().Name}: {ex.Message}",
                ex);
        }

        return new DependencyManifest(DependencyEcosystem.Gradle, entries, issues);
    }

    /// <summary>Parses a Gradle dependency line, returning name and version.</summary>
    private static (string? Name, string? Version) ParseGradleDependencyLine(string line)
    {
        // Look for quoted dependency specification: 'group:artifact:version' or "group:artifact:version"
        var quoteIndex = line.IndexOfAny(new[] { '\'', '"' });
        if (quoteIndex < 0)
        {
            return (null, null);
        }

        var quoteChar = line[quoteIndex];
        var endIndex = line.IndexOf(quoteChar, quoteIndex + 1);
        if (endIndex < 0)
        {
            return (null, null);
        }

        var spec = line[(quoteIndex + 1)..endIndex];
        var parts = spec.Split(':');

        if (parts.Length >= 2)
        {
            var name = parts[0] + ":" + parts[1];
            var version = parts.Length >= 3 ? parts[2] : null;
            return (name, version);
        }

        return (null, null);
    }


}

