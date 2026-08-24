using System.Diagnostics;
using System.Reflection;
using System.Text.Json;
using Xunit;
using Xunit.Sdk;

namespace ACT.Tests;

/// <summary>
/// Verification suite for the Artemis Test Lab (lab/ACT.Lab). Because ACT.Tests intentionally
/// carries no project reference to the lab application, behavioral tests reach the lab's pure
/// decision helpers through reflection over its freshly built assembly, while source-contract
/// tests assert the documented fixture-surface invariants directly against the sources.
/// </summary>
public class LabFixtureTests
{
    private const string BannerLine =
        "ARTEMIS TEST LAB — deliberate vulnerabilities for scanner verification. LOOPBACK ONLY. NEVER EXPOSE.";

    private static readonly Assembly LabAssembly = LoadLabAssembly();
    private static readonly Lazy<string> LabSources =
        new(() => string.Join('\n', LabSourceFiles().Select(static file => File.ReadAllText(file))));

    [Fact]
    public void Lab_AssemblyBuildsAndLoads() => Assert.Equal("ACT.Lab", LabAssembly.GetName().Name);

    [Fact]
    public void OpenApiDocument_DescribesOnlyTheDeclaredSafeSurface()
    {
        var json = Assert.IsType<string>(GetStaticProperty("ACT.Lab.LabApiDocuments", "OpenApiJson"));
        using var document = JsonDocument.Parse(json);

        Assert.Equal("3.0.3", document.RootElement.GetProperty("openapi").GetString());

        var paths = document.RootElement.GetProperty("paths");
        var declaredPaths = paths.EnumerateObject().Select(static path => path.Name)
            .OrderBy(static name => name, StringComparer.Ordinal).ToArray();
        Assert.Equal(new[] { "/api/jobs", "/authz-safe/items/{id}" }, declaredPaths);

        var jobSubmission = paths.GetProperty("/api/jobs").GetProperty("post");
        Assert.False(jobSubmission.TryGetProperty("security", out _), "POST /api/jobs must omit security declarations.");

        var safeLookup = paths.GetProperty("/authz-safe/items/{id}").GetProperty("get");
        Assert.True(safeLookup.TryGetProperty("security", out _), "The safe variant declares its tenant security requirement.");

        var schemes = document.RootElement.GetProperty("components").GetProperty("securitySchemes");
        Assert.Equal("X-Tenant", schemes.GetProperty("XTenantHeader").GetProperty("name").GetString());
    }

    [Theory]
    [InlineData(';')]
    [InlineData('&')]
    [InlineData('|')]
    [InlineData('\u0060')]
    [InlineData('$')]
    public void ShellMetaDetector_FlagsEveryInjectionMetacharacter(char probe) =>
        Assert.True(IsFlaggedByShellMetaDetector($"127.0.0.1{probe}example"), $"metacharacter {probe} must be flagged");

    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("-c 4")]
    [InlineData("")]
    [InlineData("example.internal")]
    public void ShellMetaDetector_AcceptsCleanHosts(string host) =>
        Assert.False(IsFlaggedByShellMetaDetector(host), $"clean host '{host}' must not be flagged");

    private static bool IsFlaggedByShellMetaDetector(string host) =>
        Assert.IsType<bool>(CallStatic("ACT.Lab.LabShellMetaDetector", "ContainsShellMetacharacter", host));

    [Fact]
    public void TraversalGuard_KeepsCandidatesInsideTheDataRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), "act-lab-fixture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var parent = Directory.GetParent(root)!.FullName;
            AssertStays(Path.Combine(root, "a.txt"), expected: true);
            AssertStays(Path.Combine(root, "nested", "deeper", "b.txt"), expected: true);
            AssertStays(Path.Combine(parent, "sibling.txt"), expected: false);
            AssertStays(root, expected: false);
            AssertStays(Path.GetFullPath(Path.Combine(root, "..", "escaped.txt")), expected: false);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }

        void AssertStays(string candidate, bool expected) =>
            Assert.Equal(expected, Assert.IsType<bool>(CallStatic("ACT.Lab.LabTraversalGuard", "StaysInsideRoot", root, candidate)));
    }

    [Fact]
    public void Tokens_AreFreshHexStringsAndComparedExactly()
    {
        var first = Assert.IsType<string>(CallStatic("ACT.Lab.LabTokens", "NewToken"));
        var second = Assert.IsType<string>(CallStatic("ACT.Lab.LabTokens", "NewToken"));

        Assert.NotEqual(first, second);
        Assert.True(first.Length >= 32, "tokens carry at least 128 bits of entropy");
        Assert.All(first, static character => Assert.True(Uri.IsHexDigit(character)));

        Assert.True(Assert.IsType<bool>(CallStatic("ACT.Lab.LabTokens", "Matches", "token-one", "token-one")));
        Assert.False(Assert.IsType<bool>(CallStatic("ACT.Lab.LabTokens", "Matches", "token-one ", "token-one")));
        Assert.False(Assert.IsType<bool>(CallStatic("ACT.Lab.LabTokens", "Matches", string.Empty, "token-one")));
    }

    [Fact]
    public void Source_StartupBannerIsDeclaredVerbatim() => Assert.Contains(BannerLine, LabSources.Value);

    [Fact]
    public void Source_ListenersBindLoopbackOnly()
    {
        Assert.Contains("IPAddress.Loopback", LabSources.Value);
        Assert.DoesNotContain("0.0.0.0", LabSources.Value);
        Assert.DoesNotContain("IPAddress.Any", LabSources.Value);
        Assert.DoesNotContain("IPAddress.IPv6Any", LabSources.Value);
    }

    [Fact]
    public void Source_NeverSpawnsExternalProcesses()
    {
        Assert.DoesNotContain("Process.Start", LabSources.Value);
        Assert.DoesNotContain("ProcessStartInfo", LabSources.Value);
    }

    [Fact]
    public void Source_CarriesNoProhibitedMarkers()
    {
        foreach (var marker in new[] { "TODO", "FIXME", "HACK", "NotImplementedException" })
        {
            Assert.DoesNotContain(marker, LabSources.Value);
        }
    }

    [Fact]
    public void Source_TraversalFixtureFailsClosedWithDetectionMarker()
    {
        var source = File.ReadAllText(LabSourceFile("TraversalEndpoints.cs"));
        Assert.Contains("Path.Combine", source);
        Assert.Contains("Path.GetFullPath", source);
        Assert.Contains("StaysInsideRoot", source);
        Assert.Contains("X-Lab-Traversal-Blocked", source);
        Assert.Contains("\"blocked\"", source);
    }

    [Fact]
    public void Source_CorsOpenFixtureReflectsOriginsWithCredentials()
    {
        var source = File.ReadAllText(LabSourceFile("CorsEndpoints.cs"));
        Assert.Contains("Access-Control-Allow-Origin", source);
        Assert.Contains("Access-Control-Allow-Credentials", source);
        Assert.Contains("\"true\"", source);
    }

    [Fact]
    public void Source_SecretsPageMarksEverySecretAsSynthetic()
    {
        var source = File.ReadAllText(LabSourceFile("SecretEndpoints.cs"));
        Assert.Contains("AKIAIOSFODNN7EXAMPLE", source);
        Assert.Contains("eyJhbGciOi.NONE.SYNTH", source);
        Assert.Contains("\"ghp_\"", source);
        Assert.True(CountSyntheticMarkers(source) >= 6, "each of the three secrets needs BEGIN and END synthetic markers");
    }

    [Fact]
    public void Source_CookieFixturesProvideTheHardenedContrast()
    {
        var source = File.ReadAllText(LabSourceFile("CookieEndpoints.cs"));
        Assert.Contains("SYNTHETIC-session-value", source);
        Assert.Contains("Secure = true", source);
        Assert.Contains("HttpOnly = true", source);
        Assert.Contains("SameSiteMode.Strict", source);
    }

    private static string LabSourceFile(string fileName) => Path.Combine(RepoRoot(), "lab", "ACT.Lab", fileName);

    private static IReadOnlyList<string> LabSourceFiles()
    {
        var directory = Path.Combine(RepoRoot(), "lab", "ACT.Lab");
        return Directory.EnumerateFiles(directory, "*.cs", SearchOption.AllDirectories)
            .Where(static path => !path.Contains($"{Path.DirectorySeparatorChar}bin{Path.DirectorySeparatorChar}")
                && !path.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"))
            .OrderBy(static path => path, StringComparer.Ordinal)
            .ToList();
    }

    private static int CountSyntheticMarkers(string source)
    {
        var count = 0;
        var cursor = 0;
        while ((cursor = source.IndexOf("SYNTHETIC TEST SECRET", cursor, StringComparison.Ordinal)) >= 0)
        {
            count++;
            cursor += 1;
        }

        return count;
    }

    private static string RepoRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        for (var depth = 0; depth < 16 && directory is not null; depth++, directory = directory.Parent)
        {
            if (File.Exists(Path.Combine(directory.FullName, "Artemis.slnx")))
            {
                return directory.FullName;
            }
        }

        throw new XunitException("Unable to locate the repository root (Artemis.slnx) from the test binaries.");
    }

    private static object? GetStaticProperty(string fullTypeName, string propertyName)
    {
        var property = LabAssembly.GetType(fullTypeName, throwOnError: true)!
            .GetProperty(propertyName, BindingFlags.Public | BindingFlags.Static);
        Assert.NotNull(property);
        return property!.GetValue(null);
    }

    private static object? CallStatic(string fullTypeName, string methodName, params object?[] arguments)
    {
        var type = LabAssembly.GetType(fullTypeName, throwOnError: true)!;
        var parameterTypes = arguments.Select(static argument => argument?.GetType() ?? typeof(object)).ToArray();
        var method = type.GetMethod(methodName, parameterTypes);
        Assert.NotNull(method);
        return method!.Invoke(null, arguments);
    }

    private static Assembly LoadLabAssembly()
    {
        InstallSharedFrameworkResolver();
        var repositoryRoot = RepoRoot();
        var assemblyPath = FindBuiltLabAssembly(repositoryRoot) ?? BuildLabAssembly(repositoryRoot);
        return Assembly.LoadFrom(assemblyPath);
    }

    private static string? FindBuiltLabAssembly(string repositoryRoot)
    {
        foreach (var configuration in new[] { "Debug", "Release" })
        {
            var candidate = Path.Combine(repositoryRoot, "lab", "ACT.Lab", "bin", configuration, "net10.0", "ACT.Lab.dll");
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    private static string BuildLabAssembly(string repositoryRoot)
    {
        using var process = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = ResolveDotnetExecutable(),
                ArgumentList = { "build", "lab/ACT.Lab/ACT.Lab.csproj", "--nologo", "-v", "q" },
                WorkingDirectory = repositoryRoot,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            },
        };
        Assert.True(process.Start(), "failed to spawn the dotnet build for the lab assembly");

        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(5));
        var standardOutput = process.StandardOutput.ReadToEndAsync(timeout.Token);
        var standardError = process.StandardError.ReadToEndAsync(timeout.Token);
        try
        {
            process.WaitForExitAsync(timeout.Token).GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
        }

        var output = standardOutput.GetAwaiter().GetResult() + standardError.GetAwaiter().GetResult();
        int exitCode;
        try
        {
            exitCode = process.ExitCode;
        }
        catch (InvalidOperationException)
        {
            exitCode = -1;
        }

        var assemblyPath = Path.Combine(repositoryRoot, "lab", "ACT.Lab", "bin", "Debug", "net10.0", "ACT.Lab.dll");
        Assert.True(
            File.Exists(assemblyPath),
            $"The lab assembly was not produced (exit code {exitCode}). Build output:\n{output}");
        return assemblyPath;
    }

    private static string ResolveDotnetExecutable()
    {
        var candidates = new List<string>();
        var hostedPath = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH");
        if (!string.IsNullOrWhiteSpace(hostedPath))
        {
            candidates.Add(hostedPath);
        }

        var dotnetRoot = Environment.GetEnvironmentVariable("DOTNET_ROOT");
        if (!string.IsNullOrWhiteSpace(dotnetRoot))
        {
            candidates.Add(Path.Combine(dotnetRoot, OperatingSystem.IsWindows() ? "dotnet.exe" : "dotnet"));
        }

        candidates.Add(OperatingSystem.IsWindows() ? "dotnet.exe" : "dotnet");
        foreach (var candidate in candidates)
        {
            var resolved = ResolveAgainstPath(candidate);
            if (resolved is not null)
            {
                return resolved;
            }
        }

        throw new XunitException("Unable to locate a dotnet executable to build the lab assembly.");
    }

    private static string? ResolveAgainstPath(string candidate)
    {
        if (Path.IsPathRooted(candidate))
        {
            return File.Exists(candidate) ? candidate : null;
        }

        var pathVariable = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(pathVariable))
        {
            return null;
        }

        foreach (var directory in pathVariable.Split(Path.PathSeparator))
        {
            if (string.IsNullOrWhiteSpace(directory))
            {
                continue;
            }

            var full = Path.Combine(directory.Trim('"'), candidate);
            if (File.Exists(full))
            {
                return full;
            }
        }

        return null;
    }

    private static void InstallSharedFrameworkResolver()
    {
        // Defensive: the invoked lab helpers use only BCL types, but if the CLR probes for an
        // ASP.NET Core assembly anyway, resolve it from the installed shared framework.
        AppDomain.CurrentDomain.AssemblyResolve += static (_, resolveArgs) =>
        {
            if (!resolveArgs.Name.StartsWith("Microsoft.AspNetCore", StringComparison.Ordinal))
            {
                return null;
            }

            var dotnetRoot = Environment.GetEnvironmentVariable("DOTNET_ROOT");
            if (string.IsNullOrWhiteSpace(dotnetRoot))
            {
                return null;
            }

            var frameworks = Path.Combine(dotnetRoot, "shared", "Microsoft.AspNetCore.App");
            if (!Directory.Exists(frameworks))
            {
                return null;
            }

            var simpleName = new AssemblyName(resolveArgs.Name).Name + ".dll";
            var newest = Directory.EnumerateDirectories(frameworks).Order(StringComparer.OrdinalIgnoreCase).LastOrDefault();
            if (newest is null)
            {
                return null;
            }

            var candidate = Path.Combine(newest, simpleName);
            return File.Exists(candidate) ? Assembly.LoadFrom(candidate) : null;
        };
    }
}
