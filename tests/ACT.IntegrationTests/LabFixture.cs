
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Xunit;

namespace ACT.IntegrationTests;

/// <summary>
/// Boots the disposable vulnerable lab once per test class run on a random free loopback port.
/// The lab is TEST-ONLY and binds exclusively to 127.0.0.1.
/// </summary>
public sealed class LabFixture : IAsyncLifetime
{
    private Process? _labProcess;

    public Uri BaseUrl { get; private set; } = new("http://127.0.0.1:1");

    public async Task InitializeAsync()
    {
        var port = GetFreePort();
        BaseUrl = new Uri($"http://127.0.0.1:{port}");

        var projectDir = FindLabProject();
        var info = new ProcessStartInfo
        {
            FileName = "dotnet",
            Arguments = "run --no-build --project " + (char)34 + projectDir + (char)34 + " -- --port " + port + " --lab-token e2e-lab-token",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false
        };
        _labProcess = Process.Start(info) ?? throw new InvalidOperationException("Could not start lab.");

        using var client = new HttpClient();
        for (var attempt = 0; attempt < 60; attempt++)
        {
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
        throw new TimeoutException("Lab did not become healthy within 30 seconds.");
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

    private static string FindLabProject()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            var candidate = Path.Combine(current.FullName, "lab", "ACT.Lab", "ACT.Lab.csproj");
            if (File.Exists(candidate)) return candidate;
            candidate = Path.Combine(current.FullName, "ACT.Lab.csproj");
            if (File.Exists(candidate)) return candidate;
            current = current.Parent!;
        }
        throw new InvalidOperationException("ACT.Lab project could not be located from the test directory.");
    }
}

[CollectionDefinition("lab")]
public sealed class LabCollection : ICollectionFixture<LabFixture>;
