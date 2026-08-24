using System.Net;
using System.Net.Sockets;
using ACT.Contracts;
using ACT.Lab;
using Microsoft.AspNetCore.Server.Kestrel.Https;

// ARTEMIS TEST LAB entry point. Parses loopback-only listener options, prints the mandatory
// startup banner, seeds the synthetic fixture state, and maps every fixture endpoint group.
// Any startup failure (bad arguments, unusable port, certificate generation) fails closed.
var options = LabRunOptions.Parse(args);

Console.WriteLine("ARTEMIS TEST LAB — deliberate vulnerabilities for scanner verification. LOOPBACK ONLY. NEVER EXPOSE.");
Console.WriteLine($"HTTP       http://127.0.0.1:{options.HttpPort}");
if (options.HttpsPort is { } modernTlsPort)
{
    Console.WriteLine($"HTTPS      https://127.0.0.1:{modernTlsPort} (self-signed, valid)");
}

if (options.HttpsExpiredPort is { } expiredTlsPort)
{
    Console.WriteLine($"HTTPS-EXP  https://127.0.0.1:{expiredTlsPort} (self-signed, expired)");
}

Console.WriteLine($"LAB TOKEN  {options.LabToken}");

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,

    // Pin the content root to the application directory so the labdata sandbox never
    // scatters into whatever working directory the operator launched from.
    ContentRootPath = AppContext.BaseDirectory,
});

builder.WebHost.ConfigureKestrel(kestrel =>
{
    // Hard rule of the lab: every listener binds the IPv4 loopback address only.
    kestrel.Listen(IPAddress.Loopback, options.HttpPort);
    if (options.HttpsPort is { } httpsPort)
    {
        kestrel.Listen(IPAddress.Loopback, httpsPort, listen => listen.UseHttps(LabCertificates.CreateModernServerCertificate()));
    }

    if (options.HttpsExpiredPort is { } expiredPort)
    {
        kestrel.Listen(IPAddress.Loopback, expiredPort, listen => listen.UseHttps(LabCertificates.CreateExpiredServerCertificate()));
    }
});

using var app = builder.Build();

// Per-request correlation header so lab traffic can be matched against operator-side observations.
app.Use(static async (context, next) =>
{
    context.Response.Headers[LabConstants.CorrelationHeader] = CorrelationId.New().ToString();
    await next();
});

await LabData.SeedAsync(app.Environment.ContentRootPath, CancellationToken.None);

app.MapSystemEndpoints();
app.MapHeaderEndpoints();
app.MapCookieEndpoints();
app.MapCorsEndpoints(options);
app.MapRedirectEndpoints();
app.MapAuthorizationEndpoints();
app.MapApiEndpoints(options);
app.MapTraversalEndpoints();
app.MapSqlEndpoints();
app.MapCommandEndpoints();
app.MapSecretEndpoints();
app.MapTlsEndpoints();
if (options.HasHttpsListeners)
{
    app.MapMixedContentEndpoints(options);
}

try
{
    await app.StartAsync(CancellationToken.None);
}
catch (Exception bindFailure) when (bindFailure is SocketException or IOException or InvalidOperationException)
{
    throw ActException.FailClosed(
        ErrorCategory.Configuration,
        "The test lab could not bind its loopback listener.",
        $"Kestrel failed to bind 127.0.0.1 (http={options.HttpPort}, https={options.HttpsPort?.ToString() ?? "none"}, "
        + $"expired={options.HttpsExpiredPort?.ToString() ?? "none"}): {bindFailure.Message}",
        bindFailure);
}

await app.WaitForShutdownAsync(CancellationToken.None);
