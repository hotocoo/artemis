
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Xunit;

namespace ACT.IntegrationTests;

/// <summary>
/// Boots the disposable vulnerable lab once per test class run on a random free loopback port.
/// The lab is TEST-ONLY and binds exclusively to 127.0.0.1. Launch executes the ALREADY-BUILT
/// lab dll with the configuration of the running tests - 'dotnet run --no-build' would default
/// to Debug and never start under a Release-only CI build.
/// </summary>
public sealed class LabFixture : IAsyncLifetime
{
    private Process? _labProcess;
    private readonly StringBuilder _stderrTail = new();

    public Uri BaseUrl { get; private set; } = new("http://127.0.0.1:1");

    public async Task InitializeAsync()
    {
        var port = GetFreePort();
        BaseUrl = new Uri($"http://127.0.0.1:{port}");

        var labDll = FindLabDll();
        var info = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = (char)34 + labDll + (char)34 + " --port " + port + " --lab-token e2e-lab-token",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        _labProcess = Process.Start(info) ?? throw new InvalidOperationException("Could not start lab.");
        _labProcess.ErrorDataReceived += (_, e) => { if (e.Data is not null) lock (_stderrTail) _stderrTail.AppendLine(e.Data); };
        _labProcess.BeginErrorReadLine();

        using var client = new HttpClient();
        for (var attempt = 0; attempt < 240; attempt++)
        {
            if (_labProcess.HasExited)
            {
                break;
            }

            try
            {
                var response = await client.GetAsync(new Uri(BaseUrl, "/healthz"));
                if (response.IsSuccessStatusCode) return;
            }
            catch (HttpRequestException)
            {
            }
            catch (SocketException)
            {
            }
            await Task.Delay(500);
        }

        lock (_stderrTail)
        {
            throw new TimeoutException("Lab did not become healthy within 120 seconds. Exit="
                + _labProcess.HasExited + " Stderr tail: " + _stderrTail);
        }
    }

    public async Task DisposeAsync()
    {
        if (_labProcess is not null && !_labProcess.HasExited)
        {
            _labProcess.Kill(entireProcessTree: true);
            await _labProcess.WaitForExitAsync();
        }
        _labProcess?.Dispose();
    }

    private static int GetFreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
        finally
        {
            listener.Stop();
        }
    }

    /// <summary>Matches the configuration directory the running tests were loaded from.</summary>
    private static string TestConfiguration()
    {
        var configuration = new DirectoryInfo(AppContext.BaseDirectory).Parent?.Name;
        return configuration is "Release" or "Debug" ? configuration : "Debug";
    }

    private static string FindLabDll()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            var binRoot = Path.Combine(current.FullName, "lab", "ACT.Lab", "bin", TestConfiguration());
            if (Directory.Exists(binRoot))
            {
                var dll = Directory.EnumerateFiles(binRoot, "ACT.Lab.dll", SearchOption.AllDirectories).FirstOrDefault();
                if (dll is not null) return dll;
            }

            current = current.Parent!;
        }

        throw new InvalidOperationException(
            "ACT.Lab.dll could not be located from the test directory; build the solution before running integration tests.");
    }
}

[CollectionDefinition("lab")]
public sealed class LabCollection : ICollectionFixture<LabFixture>;
