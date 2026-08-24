
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
var services = ArtemisHostFactory.BuildServices(configuration, globals);
services.AddArtemisPersistence();
services.AddArtemisPolicy();
services.AddArtemisRisk();
services.AddEmergencyStopProxy();
services.AddHostedService<ScheduleTickService>();

await using var provider = services.BuildServiceProvider();
var database = provider.GetRequiredService<ActDatabase>();
await database.InitializeAsync(CancellationToken.None);

// Bridge console-initiated emergency stops to the process-wide policy latch.
var latch = provider.GetRequiredService<ACT.Policy.EmergencyStop>();
ArtemisRuntime.BindEmergencyStop(reason => latch.Arm(reason));

var port = actOptions.Ui.ConsolePort;
var url = "http://127.0.0.1:" + port;
Environment.SetEnvironmentVariable("ASPNETCORE_URLS", url);

var builder = WebApplication.CreateBuilder([]);
var app = builder.Build();

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
        // Headless environments cannot open browsers; the URL is printed above.
    }
}

app.MapGet("/", async (IServiceProvider sp) => Pages.Dashboard(sp));
app.MapGet("/assessments", async (IServiceProvider sp) => Pages.Assessments(sp));
app.MapGet("/findings", async (IServiceProvider sp, string? assessment, string? status) => Pages.Findings(sp, assessment, status));
app.MapGet("/findings/{id}", async (IServiceProvider sp, Guid id) => Pages.FindingDetail(sp, id));
app.MapGet("/audit", async (IServiceProvider sp) => Pages.Audit(sp));
app.MapGet("/schedules", async (IServiceProvider sp) => Pages.Schedules(sp));
app.MapGet("/config", (IServiceProvider sp) => Pages.Config(sp));
app.MapGet("/health", async (IServiceProvider sp) => await Pages.Health(sp));
app.MapPost("/emergency-stop", async (IServiceProvider sp) => await Pages.EmergencyStop(sp));

app.Run();
return ExitCodes.Ok;

/// <summary>Server-rendered operator pages backed exclusively by persisted rows.</summary>
internal static class Pages
{
    private static string Esc(object? value) =>
        System.Text.Encodings.Web.HtmlEncoder.Default.Encode(value?.ToString() ?? "-");

    public static async Task<IResult> Dashboard(IServiceProvider sp)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var snapshot = await db.DashboardAsync();
        var emergency = sp.GetRequiredService<EmergencyStopProxy>().Snapshot();

        var body = new StringBuilder();
        body.Append("<h1>Dashboard</h1>");
        if (emergency.Armed)
        {
            body.Append($"<p><strong style=\"color:#b71c1c\">EMERGENCY STOP ARMED</strong> - reason: {Esc(emergency.Reason)}</p>");
        }
        body.Append("<div class=\"cards\">");
        foreach (var (label, value) in new[]
                 {
                     ("Assessments", snapshot.AssessmentsTotal), ("Assets assessed", snapshot.AssetsAssessed),
                     ("Services observed", snapshot.ServicesObserved), ("Open findings", snapshot.FindingsOpen),
                     ("Critical/High", snapshot.FindingsCriticalOrHigh), ("Confirmed", snapshot.FindingsConfirmed),
                     ("Remediated", snapshot.FindingsRemediated), ("Regressions", snapshot.RegressionsDetected),
                     ("Checks executed", snapshot.ChecksExecuted), ("Checks failed", snapshot.ChecksFailed),
                     ("False positives", snapshot.FalsePositives), ("Requests sent", snapshot.RequestCount),
                     ("Risk score (max priority)", Math.Round(snapshot.CurrentRiskScore, 1))
                 })
        {
            body.Append($"<div class=\"card\"><b>{Esc(value)}</b>{Esc(label)}</div>");
        }
        body.Append("</div>");
        body.Append("<form class=\"inline\" method=\"post\" action=\"/emergency-stop\">");
        body.Append("<button class=\"danger\" type=\"submit\">Activate emergency stop</button></form>");
        body.Append($"<p style=\"margin-top:1rem;color:#667\">Computed {Esc(snapshot.ComputedUtc.ToString("u"))} from persisted rows.</p>");
        return Results.Content(ArtemisConsoleLayout.Render("Dashboard", "Dashboard", body.ToString()), "text/html");
    }

    public static async Task<IResult> Assessments(IServiceProvider sp)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var assessments = await db.ListAssessmentsAsync(50);
        var rows = new StringBuilder();
        foreach (var a in assessments)
        {
            rows.Append("<tr>");
            rows.Append($"<td><a href=\"/findings?assessment={a.AssessmentId}\">{Esc(a.Name)}</a></td>");
            rows.Append($"<td>{Esc(a.State)}</td><td>{Esc(a.OperatorIdentity)}</td>");
            rows.Append($"<td>{Esc(a.Organization)}</td><td>{Esc(a.CreatedUtc.ToString("u"))}</td>");
            rows.Append($"<td>{Esc(a.CompletedUtc?.ToString("u") ?? "-")}</td></tr>");
        }

        var table = "<table><tr><th>Name</th><th>State</th><th>Operator</th><th>Organization</th><th>Created</th><th>Completed</th></tr>" + rows + "</table>";
        return Results.Content(
            ArtemisConsoleLayout.Render("Assessments", "Assessments", "<h1>Assessments</h1>" + table), "text/html");
    }

    public static async Task<IResult> Findings(IServiceProvider sp, string? assessment, string? status)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var assessmentId = Guid.TryParse(assessment, out var parsed) ? parsed : (Guid?)null;
        var statusFilter = Enum.TryParse<FindingStatus>(status, ignoreCase: true, out var s) ? s : (FindingStatus?)null;
        var findings = await db.ListFindingsAsync(assessmentId, statusFilter, null, 300);

        var rows = new StringBuilder();
        foreach (var f in findings.OrderByDescending(f => f.PriorityScore))
        {
            rows.Append("<tr>");
            rows.Append($"<td><span class=\"sev-{f.TechnicalSeverity}\">{f.TechnicalSeverity}</span></td>");
            rows.Append($"<td><a href=\"/findings/{f.FindingId}\">{Esc(f.Title)}</a></td>");
            rows.Append($"<td>{Esc(f.Category)}</td><td>{Esc(f.Status)}</td>");
            rows.Append($"<td>{f.ConfidenceScore:0.0}</td><td>{f.PriorityScore:0}</td>");
            rows.Append($"<td>{Esc(f.TargetDisplay)}</td><td>{Esc(f.LastSeenUtc.ToString("u"))}</td></tr>");
        }

        var table = "<table><tr><th>Severity</th><th>Title</th><th>Category</th><th>Status</th><th>Conf.</th><th>Prio</th><th>Target</th><th>Last seen</th></tr>" + rows + "</table>";
        return Results.Content(
            ArtemisConsoleLayout.Render("Findings", "Findings", "<h1>Findings</h1>" + table), "text/html");
    }

    public static async Task<IResult> FindingDetail(IServiceProvider sp, Guid id)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var all = await db.ListFindingsAsync(null, null, null, 100000);
        var finding = all.FirstOrDefault(f => f.FindingId == id);
        if (finding is null) return Results.NotFound("Finding not found.");

        var b = new StringBuilder();
        b.Append($"<h1>{Esc(finding.Title)}</h1>");
        b.Append($"<p><span class=\"sev-{finding.TechnicalSeverity}\"><b>{finding.TechnicalSeverity}</b></span> ");
        b.Append($"confidence {finding.Confidence} ({finding.ConfidenceScore:0.00}), priority {finding.PriorityScore:0}, ");
        b.Append($"status <b>{finding.Status}</b>, category {finding.Category}.</p>");
        b.Append($"<h3>Target</h3><pre>{Esc(finding.TargetDisplay)}</pre>");
        b.Append($"<h3>Description</h3><p>{Esc(finding.Description)}</p>");
        b.Append($"<h3>Why it matters</h3><p>{Esc(finding.WhyItMatters)}</p>");
        b.Append($"<h3>Technical explanation</h3><p>{Esc(finding.TechnicalExplanation)}</p>");
        b.Append($"<h3>Remediation</h3><p>{Esc(finding.Remediation.Summary)}</p><ol>");
        foreach (var step in finding.Remediation.Steps) b.Append($"<li>{Esc(step)}</li>");
        b.Append("</ol>");
        if (finding.Remediation.References.Count > 0)
        {
            b.Append("<h3>References</h3><ul>");
            foreach (var reference in finding.Remediation.References) b.Append($"<li>{Esc(reference)}</li>");
            b.Append("</ul>");
        }
        b.Append($"<h3>Fingerprint</h3><pre>{finding.Fingerprint.Hash}</pre>");
        b.Append($"<p>First seen {finding.FirstSeenUtc:u} - last seen {finding.LastSeenUtc:u} - check {finding.CheckId.Value}</p>");
        return Results.Content(ArtemisConsoleLayout.Render("Finding detail", "Findings", b.ToString()), "text/html");
    }

    public static async Task<IResult> Audit(IServiceProvider sp)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var events = await db.ReadRecentAuditAsync(200);
        var chainOk = await db.VerifyChainAsync();

        var rows = new StringBuilder();
        foreach (var e in events)
        {
            rows.Append($"<tr><td>{e.Sequence}</td><td>{e.TimestampUtc:u}</td><td>{Esc(e.Actor)}</td>");
            rows.Append($"<td>{Esc(e.Action)}</td><td>{Esc(e.ObjectType)}:{Esc(e.ObjectId)}</td>");
            rows.Append($"<td>{Esc(e.Result)}</td><td style=\"font-size:.75rem\">{e.EventHash[..16]}...</td></tr>");
        }
        var banner = chainOk
            ? "<p>Hash chain verified over all stored events.</p>"
            : "<p style=\"color:#b71c1c\"><strong>HASH CHAIN VERIFICATION FAILED</strong> - the audit log may have been tampered with.</p>";
        var table = "<table><tr><th>#</th><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Object</th><th>Result</th><th>Hash</th></tr>" + rows + "</table>";
        return Results.Content(
            ArtemisConsoleLayout.Render("Audit Log", "Audit Log", "<h1>Audit Log</h1>" + banner + table), "text/html");
    }

    public static async Task<IResult> Schedules(IServiceProvider sp)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var schedules = await db.ListEnabledSchedulesAsync();
        var rows = new StringBuilder();
        foreach (var schedule in schedules)
        {
            var next = "-";
            if (CronSchedule.TryParse(schedule.CronExpression, out var cron))
            {
                try { next = cron.NextOccurrence(DateTimeOffset.Now).ToString("yyyy-MM-dd HH:mm"); }
                catch (ActException) { next = "never"; }
            }

            rows.Append("<tr><td>" + Esc(schedule.Name) + "</td><td>" + Esc(schedule.CronExpression) + "</td>");
            rows.Append("<td>" + Esc(schedule.Trigger.ToString()) + "</td>");
            rows.Append("<td>" + (schedule.LastRunUtc is { } last ? Esc(last.ToLocalTime().ToString("u")) : "never") + "</td>");
            rows.Append("<td>" + Esc(next) + "</td></tr>");
        }
        var table = "<table><tr><th>Name</th><th>Cron (local)</th><th>Trigger</th><th>Last run</th><th>Next run</th></tr>" + rows + "</table>";
        return Results.Content(
            ArtemisConsoleLayout.Render("Schedules", "Schedules", "<h1>Schedules</h1>" + table), "text/html");
    }

    public static IResult Config(IServiceProvider sp)
    {
        var options = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<ActOptions>>().Value;
        var json = ArtemisConfiguration.RenderSafe(options);
        var body = "<h1>Effective configuration</h1>" +
                   "<p>Secret values never appear here by design (only environment variable names).</p>" +
                   $"<pre>{Esc(json)}</pre>";
        return Results.Content(ArtemisConsoleLayout.Render("Configuration", "Configuration", body), "text/html");
    }

    public static async Task<IResult> Health(IServiceProvider sp)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var checks = new List<(string Name, bool Ok, string Detail)>
        {
            ("Database", true, "Opened and schema initialized at startup."),
            ("Audit chain", await db.VerifyChainAsync(), "SHA-256 hash chain over audit_events."),
        };

        var feedVersion = await db.LatestFeedVersionAsync("osv");
        checks.Add(("Advisory feeds", feedVersion is not null && feedVersion.IsCurrent,
            feedVersion is null
                ? "No feed data retrieved yet; dependency severities will be inconclusive."
                : "Last retrieval " + feedVersion.RetrievedUtc.ToString("u")));

        checks.Add(("Filesystem", ProbeWritableDirectory(AppContext.BaseDirectory), "Application directory writable probe."));

        var preview = await new RetentionSweeper(db).PreviewAsync();
        var pending = preview.Sum(row => row.ExpiredCount);
        var lastSweep = await db.GetConfigAsync<RetentionMaintenance.AutoSweepStamp>(RetentionMaintenance.LastSweepKey);
        checks.Add(("Evidence retention", true,
            pending > 0
                ? pending + " evidence item(s) past their configured window; the ticking host sweeps them "
                    + "(throttled, skipped while an emergency stop is armed). Last automatic sweep: "
                    + (lastSweep?.SweptUtc.ToString("u") ?? "never") + "."
                : "All evidence within its scope-configured window. Last automatic sweep: "
                    + (lastSweep?.SweptUtc.ToString("u") ?? "never") + "."));

        var rows = string.Join("", checks.Select(c =>
            "<tr><td>" + Esc(c.Name) + "</td><td>" + (c.Ok ? "OK" : "DEGRADED") + "</td><td>" + Esc(c.Detail) + "</td></tr>"));
        var body = "<h1>System Health</h1>" +
                   "<table><tr><th>Component</th><th>Status</th><th>Detail</th></tr>" + rows + "</table>";
        return Results.Content(ArtemisConsoleLayout.Render("System Health", "System Health", body), "text/html");
    }

    private static bool ProbeWritableDirectory(string path)
    {
        try
        {
            var probe = Path.Combine(path, ".artemis-health-probe");
            File.WriteAllText(probe, "probe");
            File.Delete(probe);
            return true;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    public static Task<IResult> EmergencyStop(IServiceProvider sp)
    {
        sp.GetRequiredService<EmergencyStopProxy>().Arm("operator-console", "Emergency stop activated from web console.");
        return Task.FromResult<IResult>(Results.Redirect("/", permanent: false));
    }
}

/// <summary>Bridges console-initiated stops to the host-wide policy latch.</summary>
public sealed class EmergencyStopProxy
{
    public bool Armed { get; private set; }
    public string Reason { get; private set; } = "";

    public void Arm(string actor, string reason)
    {
        Armed = true;
        Reason = reason;
        ArtemisRuntime.RaiseEmergencyStop(reason);
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
