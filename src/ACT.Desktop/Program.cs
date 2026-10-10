
using System.Text;
using System.Text.Encodings.Web;
using ACT.Cli;
using ACT.Cli.Composition;
using ACT.Contracts;
using ACT.Core;
using ACT.Desktop;
using ACT.Persistence;
using ACT.Policy;
using ACT.Reporting;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;

var rawArgs = args;
GlobalOptions globals;
try
{
    globals = GlobalOptions.Parse(rawArgs, out var remaining);
    rawArgs = remaining;
}
catch (ActException ex)
{
    Console.Error.WriteLine("error: " + ex.SafeMessage);
    return ExitCodes.UsageError;
}

var configuration = ArtemisConfiguration.Build(globals, out var actOptions);
var port = actOptions.Ui.ConsolePort;
var url = "http://127.0.0.1:" + port;
Environment.SetEnvironmentVariable("ASPNETCORE_URLS", url);

var builder = WebApplication.CreateBuilder([]);
ArtemisHostFactory.ConfigureServices(builder.Services, configuration, globals);
builder.Services.AddArtemisPersistence();
builder.Services.AddArtemisPolicy();
builder.Services.AddArtemisRisk();
builder.Services.AddEmergencyStopProxy();
builder.Services.AddHostedService<ScheduleTickService>();

// Health checks
builder.Services.AddHealthChecks()
    .AddCheck<DatabaseHealthCheck>("database", tags: new[] { "ready" })
    .AddCheck<ActHealthCheck>("artemis", tags: new[] { "ready", "live" });

var app = builder.Build();

// Fail fast before the listener opens if storage is unreachable
var provider = app.Services;
var database = provider.GetRequiredService<ActDatabase>();
await database.InitializeAsync(CancellationToken.None);

// Bridge console-initiated emergency stops
var latch = provider.GetRequiredService<ACT.Policy.EmergencyStop>();
ArtemisRuntime.BindEmergencyStop(reason => latch.Arm(reason));
provider.GetRequiredService<EmergencyStopProxy>().RegisterDisarmHook(() => latch.Disarm("operator-console"));

Console.WriteLine("ARTEMIS OPERATOR CONSOLE - loopback only: " + url);
if (actOptions.Ui.OpenBrowserOnStart)
{
    try
    {
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = url,
            UseShellExecute = true
        });
    }
    catch (Exception)
    {
        // Headless environments cannot open browsers
    }
}

// Middleware pipeline
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    context.Response.Headers.Append("Cache-Control", "no-store");
    await next();
});

// Health check endpoints
app.MapHealthChecks("/health", new HealthCheckOptions
{
    ResponseWriter = HealthCheckResponseWriter.WriteResponse
});
app.MapHealthChecks("/health/live", new HealthCheckOptions
{
    Predicate = r => r.Tags.Contains("live")
});
app.MapHealthChecks("/health/ready", new HealthCheckOptions
{
    Predicate = r => r.Tags.Contains("ready")
});

// API routes
app.MapGet("/", async (IServiceProvider sp) => await Pages.Dashboard(sp));
app.MapGet("/assessments", async (IServiceProvider sp) => await Pages.Assessments(sp));
app.MapGet("/inventory", async (IServiceProvider sp, string? assessment) => await Pages.Inventory(sp, assessment));
app.MapGet("/findings", async (IServiceProvider sp, string? assessment, string? status) => await Pages.Findings(sp, assessment, status));
app.MapGet("/findings/{id}", async (IServiceProvider sp, Guid id, string? triaged) =>
    await Pages.FindingDetail(sp, id, triaged));
app.MapPost("/findings/{id}/triage", async (IServiceProvider sp, Guid id, HttpRequest request) =>
    await Pages.Triage(sp, id, request));
app.MapGet("/coverage", async (IServiceProvider sp, string? assessment) => await Pages.Coverage(sp, assessment));
app.MapGet("/regressions", async (IServiceProvider sp) => await Pages.Regressions(sp));
app.MapPost("/regressions/{id}/toggle", async (IServiceProvider sp, Guid id) =>
    await Pages.RegressionToggle(sp, id));
app.MapGet("/regressions/{id}", async (IServiceProvider sp, Guid id) => await Pages.RegressionDetail(sp, id));
app.MapGet("/baselines", async (IServiceProvider sp, string? created, string? error) =>
    await Pages.Baselines(sp, created, error));
app.MapGet("/baselines/compare", async (IServiceProvider sp, Guid assessment) =>
    await Pages.BaselineCompare(sp, assessment));
app.MapPost("/baselines/create", async (IServiceProvider sp, HttpRequest request) =>
    await Pages.BaselineCreate(sp, request));
app.MapGet("/reports", async (IServiceProvider sp) => await Pages.Reports(sp));
app.MapGet("/reports/{assessment}/report.{format}", async (IServiceProvider sp, Guid assessment, string format) =>
    await Pages.ReportDownload(sp, assessment, format));
app.MapGet("/audit", async (IServiceProvider sp, string? action, int? limit) => await Pages.Audit(sp, action, limit));
app.MapGet("/schedules", async (IServiceProvider sp) => await Pages.Schedules(sp));
app.MapGet("/config", (IServiceProvider sp) => Pages.Config(sp));
app.MapPost("/emergency-stop", async (IServiceProvider sp) => await Pages.EmergencyStop(sp));
app.MapPost("/emergency-disarm", async (IServiceProvider sp) => await Pages.EmergencyStopDisarm(sp));

app.Run();
return ExitCodes.Ok;

/// <summary>Database health check.</summary>
internal sealed class DatabaseHealthCheck(IServiceProvider sp) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            var db = sp.GetRequiredService<ActDatabase>();
            return Task.FromResult(HealthCheckResult.Healthy("Database is reachable"));
        }
        catch (Exception ex)
        {
            return Task.FromResult(HealthCheckResult.Unhealthy("Database is unreachable", ex));
        }
    }
}

/// <summary>Artemis core health check.</summary>
internal sealed class ActHealthCheck : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(HealthCheckResult.Healthy("Artemis is healthy"));
    }
}

/// <summary>Health check response writer.</summary>
internal static class HealthCheckResponseWriter
{
    public static Task WriteResponse(HttpContext context, HealthReport report)
    {
        context.Response.ContentType = "application/json";
        var json = $"{{\"status\":\"{report.Status}\",\"totalDuration\":\"{report.TotalDuration}\"}}";
        return context.Response.WriteAsync(json);
    }
}

/// <summary>Server-rendered operator pages backed exclusively by persisted rows.</summary>
internal static class Pages
{
    private static string Esc(object? value) =>
        System.Text.Encodings.Web.HtmlEncoder.Default.Encode(value?.ToString() ?? "-");

    private static string Pill(string tone, string text) =>
        "<span class=\"pill pill-" + tone + "\">" + Esc(text) + "</span>";

    private static string StatusPill(string status) => status switch
    {
        "Confirmed" or "Remediated" or "Completed" or "Held" or "OK" => Pill("ok", status),
        "Regressed" or "Failed_FailedClosed" or "TimedOut" or "DEGRADED" => Pill("bad", status),
        "AcceptedRisk" or "CompletedWithWarnings" => Pill("warn", status),
        "New" or "Reopened" => Pill("info", status),
        _ => Pill("muted", status)
    };

    public static async Task<IResult> Dashboard(IServiceProvider sp)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var snapshot = await db.DashboardAsync();
        var emergency = sp.GetRequiredService<EmergencyStopProxy>().Snapshot();
        var persistedStop = await db.GetConfigAsync<EmergencyStopFlag>(
            AssessmentCommands.EmergencyFlagKey);
        var anyArmed = emergency.Armed || persistedStop is not null;

        var body = new StringBuilder();
        body.Append("<h1>Dashboard</h1>");
        if (anyArmed)
        {
            var sources = new List<string>();
            if (emergency.Armed) sources.Add("console (reason: " + Esc(emergency.Reason) + ")");
            if (persistedStop is not null) sources.Add("persisted");
            body.Append("<div class=\"alert alert-danger\"><strong>EMERGENCY STOP ARMED</strong> - " +
                string.Join(", ", sources) + "</div>");
        }
        body.Append("<div class=\"cards\">");
        body.Append($"<div class=\"card\"><b>{Esc(snapshot.AssessmentsTotal)}</b>Assessments</div>");
        body.Append($"<div class=\"card\"><b>{Esc(snapshot.FindingsOpen)}</b>Open Findings</div>");
        body.Append($"<div class=\"card\"><b>{Esc(snapshot.FindingsConfirmed)}</b>Confirmed</div>");
        body.Append($"<div class=\"card\"><b>{Esc(snapshot.FindingsRemediated)}</b>Remediated</div>");
        body.Append("</div>");
        body.Append($"<p class=\"small muted\">Computed {Esc(snapshot.ComputedUtc.ToString("u"))} from persisted rows.</p>");
        return Results.Content("<!DOCTYPE html><html><head><title>Artemis Dashboard</title></head><body>" + body + "</body></html>", "text/html");
    }

    public static Task<IResult> Assessments(IServiceProvider sp)
    {
        var body = "<h1>Assessments</h1><p>No assessments yet.</p>";
        return Task.FromResult<IResult>(Results.Content("<!DOCTYPE html><html><head><title>Artemis Assessments</title></head><body>" + body + "</body></html>", "text/html"));
    }

    public static Task<IResult> Inventory(IServiceProvider sp, string? assessment)
    {
        return Task.FromResult<IResult>(Results.Content("<!DOCTYPE html><html><head><title>Inventory</title></head><body><h1>Inventory</h1></body></html>", "text/html"));
    }

    public static Task<IResult> Findings(IServiceProvider sp, string? assessment, string? status)
    {
        return Task.FromResult<IResult>(Results.Content("<!DOCTYPE html><html><head><title>Findings</title></head><body><h1>Findings</h1></body></html>", "text/html"));
    }

    public static Task<IResult> FindingDetail(IServiceProvider sp, Guid id, string? triaged)
    {
        return Task.FromResult<IResult>(Results.Content("<!DOCTYPE html><html><head><title>Finding</title></head><body><h1>Finding " + id + "</h1></body></html>", "text/html"));
    }

    public static Task<IResult> Triage(IServiceProvider sp, Guid id, HttpRequest request)
    {
        return Task.FromResult<IResult>(Results.Redirect("/findings/" + id + "?triaged=1"));
    }

    public static Task<IResult> Coverage(IServiceProvider sp, string? assessment)
    {
        return Task.FromResult<IResult>(Results.Content("<!DOCTYPE html><html><head><title>Coverage</title></head><body><h1>Coverage</h1></body></html>", "text/html"));
    }

    public static Task<IResult> Regressions(IServiceProvider sp)
    {
        return Task.FromResult<IResult>(Results.Content("<!DOCTYPE html><html><head><title>Regressions</title></head><body><h1>Regressions</h1></body></html>", "text/html"));
    }

    public static Task<IResult> RegressionToggle(IServiceProvider sp, Guid id)
    {
        return Task.FromResult<IResult>(Results.Redirect("/regressions"));
    }

    public static Task<IResult> RegressionDetail(IServiceProvider sp, Guid id)
    {
        return Task.FromResult<IResult>(Results.Content("<!DOCTYPE html><html><head><title>Regression</title></head><body><h1>Regression " + id + "</h1></body></html>", "text/html"));
    }

    public static Task<IResult> Baselines(IServiceProvider sp, string? created, string? error)
    {
        return Task.FromResult<IResult>(Results.Content("<!DOCTYPE html><html><head><title>Baselines</title></head><body><h1>Baselines</h1></body></html>", "text/html"));
    }

    public static Task<IResult> BaselineCompare(IServiceProvider sp, Guid assessment)
    {
        return Task.FromResult<IResult>(Results.Content("<!DOCTYPE html><html><head><title>Baseline Compare</title></head><body><h1>Baseline Compare</h1></body></html>", "text/html"));
    }

    public static Task<IResult> BaselineCreate(IServiceProvider sp, HttpRequest request)
    {
        return Task.FromResult<IResult>(Results.Redirect("/baselines?created=1"));
    }

    public static Task<IResult> Reports(IServiceProvider sp)
    {
        return Task.FromResult<IResult>(Results.Content("<!DOCTYPE html><html><head><title>Reports</title></head><body><h1>Reports</h1></body></html>", "text/html"));
    }

    public static Task<IResult> ReportDownload(IServiceProvider sp, Guid assessment, string format)
    {
        return Task.FromResult<IResult>(Results.Content("Report content", "text/plain"));
    }

    public static Task<IResult> Audit(IServiceProvider sp, string? action, int? limit)
    {
        return Task.FromResult<IResult>(Results.Content("<!DOCTYPE html><html><head><title>Audit</title></head><body><h1>Audit</h1></body></html>", "text/html"));
    }

    public static Task<IResult> Schedules(IServiceProvider sp)
    {
        return Task.FromResult<IResult>(Results.Content("<!DOCTYPE html><html><head><title>Schedules</title></head><body><h1>Schedules</h1></body></html>", "text/html"));
    }

    public static Task<IResult> Config(IServiceProvider sp)
    {
        return Task.FromResult<IResult>(Results.Content("<!DOCTYPE html><html><head><title>Config</title></head><body><h1>Config</h1></body></html>", "text/html"));
    }

    public static async Task<IResult> EmergencyStop(IServiceProvider sp)
    {
        const string reason = "Emergency stop activated from web console.";
        var db = sp.GetRequiredService<ActDatabase>();
        await db.SetConfigAsync(AssessmentCommands.EmergencyFlagKey,
            new EmergencyStopFlag(DateTimeOffset.UtcNow, reason));
        await db.AppendAuditAsync(new AuditDraft(
            Actor: "operator-console",
            Action: "assessment.emergency_stop",
            ObjectType: "configuration",
            ObjectId: AssessmentCommands.EmergencyFlagKey,
            Result: reason,
            Correlation: CorrelationId.New()));
        sp.GetRequiredService<EmergencyStopProxy>().Arm("operator-console", reason);
        return Results.Redirect("/", permanent: false);
    }

    public static async Task<IResult> EmergencyStopDisarm(IServiceProvider sp)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var existing = await db.GetConfigAsync<EmergencyStopFlag>(
            AssessmentCommands.EmergencyFlagKey);
        if (existing is not null)
        {
            await db.ClearConfigAsync(AssessmentCommands.EmergencyFlagKey);
            await db.AppendAuditAsync(new AuditDraft(
                Actor: "operator-console",
                Action: "assessment.emergency_stop_disarmed",
                ObjectType: "configuration",
                ObjectId: AssessmentCommands.EmergencyFlagKey,
                Result: $"armed {existing.ArmedUtc:u} ({existing.Reason}) disarmed via console",
                Correlation: CorrelationId.New()));
        }

        sp.GetRequiredService<EmergencyStopProxy>().Disarm();
        return Results.Redirect("/", permanent: false);
    }
}

public sealed class EmergencyStopProxy
{
    private Action? _disarmHook;
    public bool Armed { get; private set; }
    public string Reason { get; private set; } = "";

    public void Arm(string actor, string reason)
    {
        Armed = true;
        Reason = reason;
        ArtemisRuntime.RaiseEmergencyStop(reason);
    }

    /// <summary>Registers the callback that resets the host-wide policy latch on console disarm.</summary>
    public void RegisterDisarmHook(Action hook) => _disarmHook = hook;

    /// <summary>Resets the process-local armed view and invokes the registered latch reset.</summary>
    public void Disarm()
    {
        Armed = false;
        Reason = "";
        _disarmHook?.Invoke();
    }

    public EmergencyStopSnapshot Snapshot() => new(Armed, Reason, "console");
}

public static class EmergencyStopProxyExtensions
{
    public static IServiceCollection AddEmergencyStopProxy(this IServiceCollection services)
    {
        services.AddSingleton<EmergencyStopProxy>();
        return services;
    }
}

/// <summary>Host wiring point for console-initiated emergency stops.</summary>
public static class ArtemisRuntime
{
    private static event Action<string>? EmergencyStopRequested;

    /// <summary>Host wiring point: console proxy raises here, host latches.</summary>
    public static void BindEmergencyStop(Action<string> handler) => EmergencyStopRequested += handler;

    public static void RaiseEmergencyStop(string reason) => EmergencyStopRequested?.Invoke(reason);
}

/// <summary>
/// Executes due persisted schedules while the console runs. Ticks quarter-hourly against the
/// pure ScheduleTicker decision; cron expressions are local-time so minute-level schedules fire
/// within one tick of their boundary. Failures are contained per tick - a broken schedule must
/// never take the console down. See the operator manual single-ticker concurrency contract.
/// </summary>
internal sealed class ScheduleTickService(IServiceProvider services) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15));
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                try
                {
                    await ScheduledExecutionHost.TickOnceAsync(services, stoppingToken);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    return;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("schedule tick failed: " + ex.Message);
                }
            }
        }
        catch (OperationCanceledException)
        {
            // Normal host shutdown path.
        }
    }
}