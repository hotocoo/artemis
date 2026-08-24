
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using ACT.Cli;
using ACT.Cli.Composition;
using ACT.Contracts;
using ACT.Persistence;
using ACT.Reporting;

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

await using var provider = await services.BuildServiceProviderAsync();
var database = provider.GetRequiredService<ActDatabase>();
await database.InitializeAsync(CancellationToken.None);

// Bridge console-initiated emergency stops to the process-wide policy latch.
var latch = provider.GetRequiredService<ACT.Policy.EmergencyStop>();
ArtemisRuntime.EmergencyStopRequested += (actor, reason) => latch.Arm(actor, reason);

var port = actOptions.Ui.ConsolePort;
var url = $"http://127.0.0.1:{port}";

var builder = WebApplication.CreateBuilder([]);
builder.WebHost.UseUrls(url);
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
    private static readonly HtmlEncoder Encoder = HtmlEncoder.Default;

    private static string Layout(string title, string activeNav, string body)
    {
        var nav = new (string Href, string Name)[]
        {
            ("/", "Dashboard"),
            ("/assessments", "Assessments"),
            ("/findings", "Findings"),
            ("/schedules", "Schedules"),
            ("/audit", "Audit Log"),
            ("/config", "Configuration"),
            ("/health", "System Health")
        };
        var navHtml = string.Join("", nav.Select(n =>
            $"<a class="{(n.Name == activeNav ? "active" : "")}" href="{n.Href}">{n.Name}</a>"));
        return """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
""" + $"<title>{Encoder.Encode(title)} - Artemis</title>" + """
<style>
  :root { color-scheme: light dark; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; display: flex; min-height: 100vh; }
  nav { width: 200px; background: #1c2433; padding-top: 2rem; }
  nav a { display: block; color: #cfd8e6; padding: .7rem 1.2rem; text-decoration: none; font-size: .95rem; }
  nav a:hover, nav a.active { background: #2b3650; color: white; }
  main { flex: 1; padding: 2rem 2.5rem; max-width: 1200px; }
  h1 { font-weight: 600; margin-top: 0; }
  table { border-collapse: collapse; width: 100%; margin: 1rem 0; font-size: .92rem; }
  th, td { text-align: left; padding: .55rem .7rem; border-bottom: 1px solid #d5dbe4; vertical-align: top; }
  th { background: #eef2f7; font-weight: 600; }
  .sev-Informational{color:#5b6470}.sev-Low{color:#2e7d32}.sev-Medium{color:#b26a00}
  .sev-High{color:#c62828}.sev-Critical{color:#ffffff;background:#b71c1c;padding:.05rem .4rem;border-radius:3px}
  .cards { display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:1.5rem; }
  .card { background:#f4f6fa; border-radius:8px; padding:1rem 1.3rem; min-width:150px; }
  .card b { display:block; font-size:1.6rem; }
  form.inline { display:inline; }
  button.danger { background:#b71c1c; color:white; border:none; padding:.5rem 1rem; border-radius:4px; cursor:pointer; }
  code, pre { background:#f0f2f6; border-radius:4px; padding:.1rem .35rem; font-size:.85rem; }
</style>
</head>
<body>
<nav>""" + $"<div style="padding:0 1.2rem 1.5rem;color:#8fa1bd;font-weight:600;">ARTEMIS</div>{navHtml}" + """</nav>
<main>
""" + body + """
</main>
</body>
</html>
""";
    }

    private static string Esc(object? value) => Encoder.Encode(value?.ToString() ?? "-");

    public static async Task<IResult> Dashboard(IServiceProvider sp)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var snapshot = await db.DashboardAsync();
        var emergency = sp.GetRequiredService<EmergencyStopProxy>().Snapshot();

        var body = new StringBuilder();
        body.Append("<h1>Dashboard</h1>");
        if (emergency.Armed)
        {
            body.Append($"<p><strong style="color:#b71c1c">EMERGENCY STOP ARMED</strong> - reason: {Esc(emergency.Reason)}</p>");
        }
        body.Append("<div class="cards">");
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
            body.Append($"<div class="card"><b>{Esc(value)}</b>{Esc(label)}</div>");
        }
        body.Append("</div>");
        body.Append($"<form class="inline" method="post" action="/emergency-stop">" +
                    "<button class="danger" type="submit">Activate emergency stop</button></form>");
        body.Append($"<p style="margin-top:1rem;color:#667">Computed {Esc(snapshot.ComputedUtc.ToString("u"))} from persisted rows.</p>");
        return Results.Content(Layout("Dashboard", "Dashboard", body.ToString()), "text/html");
    }

    public static async Task<IResult> Assessments(IServiceProvider sp)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var assessments = await db.ListAssessmentsAsync(50);
        var rows = new StringBuilder();
        foreach (var a in assessments)
        {
            rows.Append("<tr>" +
                        $"<td><a href="/findings?assessment={a.AssessmentId}">{Esc(a.Name)}</a></td>" +
                        $"<td>{Esc(a.State)}</td><td>{Esc(a.OperatorIdentity)}</td><td>{Esc(a.Organization)}</td>" +
                        $"<td>{Esc(a.CreatedUtc.ToString("u"))}</td><td>{Esc(a.CompletedUtc?.ToString("u") ?? "-")}</td>" +
                        "</tr>");
        }
        var body = "<h1>Assessments</h1>" +
                   "<table><tr><th>Name</th><th>State</th><th>Operator</th><th>Organization</th><th>Created</th><th>Completed</th></tr>" +
                   rows + "</table>";
        return Results.Content(Layout("Assessments", "Assessments", body), "text/html");
    }

    public static async Task<IResult> Findings(IServiceProvider sp, string? assessment, string? status)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var assessmentId = Guid.TryParse(assessment, out var parsed) ? parsed : (Guid?)null;
        var statusFilter = Enum.TryParse<FindingStatus>(status, ignoreCase: true, out var s) ? s : (FindingStatus?)null;
        var findings = await db.ListFindingsAsync(assessmentId, statusFilter, null, 300);

        var rows = new StringBuilder();
        foreach (var f in findings)
        {
            rows.Append("<tr>" +
                        $"<td><span class="sev-{Esc(f.TechnicalSeverity)}">{Esc(f.TechnicalSeverity)}</span></td>" +
                        $"<td><a href="/findings/{f.FindingId}">{Esc(f.Title)}</a></td>" +
                        $"<td>{Esc(f.Category)}</td><td>{Esc(f.Status)}</td>" +
                        $"<td>{Esc(f.ConfidenceScore.ToString("0.0"))}</td><td>{Esc(f.PriorityScore.ToString("0"))}</td>" +
                        $"<td>{Esc(f.TargetDisplay)}</td><td>{Esc(f.LastSeenUtc.ToString("u"))}</td>" +
                        "</tr>");
        }
        var body = "<h1>Findings</h1>" +
                   $"<p>Showing up to 300 findings{(assessmentId is null ? "" : " for the selected assessment")}.</p>" +
                   "<table><tr><th>Severity</th><th>Title</th><th>Category</th><th>Status</th><th>Confidence</th><th>Priority</th><th>Target</th><th>Last seen</th></tr>" +
                   rows + "</table>";
        return Results.Content(Layout("Findings", "Findings", body), "text/html");
    }

    public static async Task<IResult> FindingDetail(IServiceProvider sp, Guid id)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var all = await db.ListFindingsAsync(null, null, null, 5000);
        var finding = all.FirstOrDefault(f => f.FindingId == id);
        if (finding is null)
        {
            return Results.NotFound("Finding not found.");
        }

        var body = new StringBuilder();
        body.Append($"<h1>{Esc(finding.Title)}</h1>");
        body.Append($"<p><span class="sev-{Esc(finding.TechnicalSeverity)}"><b>{Esc(finding.TechnicalSeverity)}</b></span> " +
                    $"confidence {Esc(finding.Confidence)} ({finding.ConfidenceScore:0.00}), priority {finding.PriorityScore:0}, " +
                    $"status <b>{Esc(finding.Status)}</b>, category {Esc(finding.Category)}.</p>");
        body.Append($"<h3>Target</h3><pre>{Esc(finding.TargetDisplay)}</pre>");
        body.Append($"<h3>Description</h3><p>{Esc(finding.Description)}</p>");
        body.Append($"<h3>Why it matters</h3><p>{Esc(finding.WhyItMatters)}</p>");
        body.Append($"<h3>Technical explanation</h3><p>{Esc(finding.TechnicalExplanation)}</p>");
        body.Append("<h3>Remediation</h3><p>" + Esc(finding.Remediation.Summary) + "</p><ol>");
        foreach (var step in finding.Remediation.Steps)
        {
            body.Append($"<li>{Esc(step)}</li>");
        }
        body.Append("</ol>");
        if (finding.Remediation.References.Count > 0)
        {
            body.Append("<h3>References</h3><ul>");
            foreach (var reference in finding.Remediation.References)
            {
                body.Append($"<li>{Esc(reference)}</li>");
            }
            body.Append("</ul>");
        }
        body.Append($"<h3>Fingerprint</h3><pre>{Esc(finding.Fingerprint.Hash)}</pre>");
        body.Append($"<p>First seen {Esc(finding.FirstSeenUtc.ToString("u"))} - last seen {Esc(finding.LastSeenUtc.ToString("u"))} - check {Esc(finding.CheckId.Value)}</p>");
        return Results.Content(Layout("Finding detail", "Findings", body.ToString()), "text/html");
    }

    public static async Task<IResult> Audit(IServiceProvider sp)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var events = await db.ReadRecentAuditAsync(200);
        var chainOk = await db.VerifyChainAsync();

        var rows = new StringBuilder();
        foreach (var e in events)
        {
            rows.Append("<tr>" +
                        $"<td>{Esc(e.Sequence)}</td><td>{Esc(e.TimestampUtc.ToString("u"))}</td>" +
                        $"<td>{Esc(e.Actor)}</td><td>{Esc(e.Action)}</td>" +
                        $"<td>{Esc(e.ObjectType)}:{Esc(e.ObjectId)}</td><td>{Esc(e.Result)}</td>" +
                        $"<td style="font-size:.75rem">{Esc(e.EventHash[..16])}...</td>" +
                        "</tr>");
        }
        var banner = chainOk
            ? "<p>Hash chain verified over all stored events.</p>"
            : "<p style="color:#b71c1c"><strong>HASH CHAIN VERIFICATION FAILED</strong> - the audit log may have been tampered with.</p>";
        var body = "<h1>Audit Log</h1>" + banner +
                   "<table><tr><th>#</th><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Object</th><th>Result</th><th>Hash</th></tr>" +
                   rows + "</table>";
        return Results.Content(Layout("Audit Log", "Audit Log", body), "text/html");
    }

    public static async Task<IResult> Schedules(IServiceProvider sp)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var schedules = await db.ListEnabledSchedulesAsync();
        var rows = new StringBuilder();
        foreach (var schedule in schedules)
        {
            rows.Append("<tr>" +
                        $"<td>{Esc(schedule.Name)}</td><td>{Esc(schedule.CronExpression)}</td>" +
                        $"<td>{Esc(schedule.Trigger)}</td><td>{Esc(schedule.LastRunUtc?.ToString("u") ?? "never")}</td>" +
                        "</tr>");
        }
        var body = "<h1>Schedules</h1>" +
                   "<table><tr><th>Name</th><th>Cron (local)</th><th>Trigger</th><th>Last run</th></tr>" + rows + "</table>";
        return Results.Content(Layout("Schedules", "Schedules", body), "text/html");
    }

    public static IResult Config(IServiceProvider sp)
    {
        var options = sp.GetRequiredService<Microsoft.Extensions.Options.IOptions<ActOptions>>().Value;
        var json = ArtemisConfiguration.RenderSafe(options);
        var body = "<h1>Effective configuration</h1>" +
                   "<p>Secret values are never part of this tree by design (only environment variable names).</p>" +
                   $"<pre>{Esc(json)}</pre>";
        return Results.Content(Layout("Configuration", "Configuration", body), "text/html");
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
                ? "No feed data retrieved yet; dependency severity will be marked stale/inconclusive."
                : "Last retrieval " + feedVersion.RetrievedUtc.ToString("u")));

        var dataDirWritable = ProbeWritableDirectory(AppContext.BaseDirectory);
        checks.Add(("Filesystem", dataDirWritable, "Application directory writable probe."));

        var rows = string.Join("", checks.Select(c =>
            $"<tr><td>{Esc(c.Name)}</td><td>{(c.Ok ? "OK" : "DEGRADED")}</td><td>{Esc(c.Detail)}</td></tr>"));
        var body = "<h1>System Health</h1>" +
                   "<table><tr><th>Component</th><th>Status</th><th>Detail</th></tr>" + rows + "</table>";
        return Results.Content(Layout("System Health", "System Health", body), "text/html");
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
        catch (IOException)
        {
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return false;
        }
    }

    public static Task<IResult> EmergencyStop(IServiceProvider sp)
    {
        sp.GetRequiredService<EmergencyStopProxy>().Arm("operator-console", "Emergency stop activated from web console.");
        return Task.FromResult<IResult>(Results.Redirect("/", permanent: false));
    }
}

/// <summary>Bridges the console to the process-wide emergency latch registered by the host.</summary>
public static class EmergencyStopProxyExtensions
{
    public static IServiceCollection AddEmergencyStopProxy(this IServiceCollection services)
    {
        services.AddSingleton<EmergencyStopProxy>();
        return services;
    }
}

public sealed class EmergencyStopProxy
{
    public bool Armed { get; private set; }
    public string Reason { get; private set; } = "";

    public void Arm(string actor, string reason)
    {
        Armed = true;
        Reason = reason;
        ArtemisRuntime.EmergencyStopRequested?.Invoke(actor, reason);
    }

    public EmergencyStopSnapshot Snapshot() => new(Armed, Reason, "console");
}

public static class ArtemisRuntime
{
    /// <summary>The host wires its EmergencyStop latch to this event at startup.</summary>
    public static event Action<string, string>? EmergencyStopRequested;
}
