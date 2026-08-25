
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
var port = actOptions.Ui.ConsolePort;
var url = "http://127.0.0.1:" + port;
// Must precede CreateBuilder: the web builder snapshots its configuration, URL settings included.
Environment.SetEnvironmentVariable("ASPNETCORE_URLS", url);

// The web host IS the composition root: pages, background tickers, and the database share one
// container. A second, parallel provider here would leave every page resolving from an empty
// container and every hosted service (database init, schedule ticks) never starting at all.
var builder = WebApplication.CreateBuilder([]);
ArtemisHostFactory.ConfigureServices(builder.Services, configuration, globals);
builder.Services.AddArtemisPersistence();
builder.Services.AddArtemisPolicy();
builder.Services.AddArtemisRisk();
builder.Services.AddEmergencyStopProxy();
builder.Services.AddHostedService<ScheduleTickService>();

var app = builder.Build();

// Fail fast before the listener opens if storage is unreachable; initialization is idempotent
// with the hosted DatabaseInitializationService that starts with the host.
var provider = app.Services;
var database = provider.GetRequiredService<ActDatabase>();
await database.InitializeAsync(CancellationToken.None);

// Bridge console-initiated emergency stops to the process-wide policy latch.
var latch = provider.GetRequiredService<ACT.Policy.EmergencyStop>();
ArtemisRuntime.BindEmergencyStop(reason => latch.Arm(reason));

// Console-initiated disarms reset the host-wide policy latch as well as the process-local view.
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
        // Headless environments cannot open browsers; the URL is printed above.
    }
}

app.MapGet("/", async (IServiceProvider sp) => await Pages.Dashboard(sp));
app.MapGet("/assessments", async (IServiceProvider sp) => await Pages.Assessments(sp));
app.MapGet("/inventory", async (IServiceProvider sp, string? assessment) => await Pages.Inventory(sp, assessment));
app.MapGet("/findings", async (IServiceProvider sp, string? assessment, string? status) => await Pages.Findings(sp, assessment, status));
app.MapGet("/findings/{id}", async (IServiceProvider sp, Guid id, string? triaged) =>
    await Pages.FindingDetail(sp, id, triaged));
app.MapPost("/findings/{id}/triage", async (IServiceProvider sp, Guid id, HttpRequest request) =>
    await Pages.Triage(sp, id, request));
app.MapGet("/audit", async (IServiceProvider sp) => await Pages.Audit(sp));
app.MapGet("/schedules", async (IServiceProvider sp) => await Pages.Schedules(sp));
app.MapGet("/config", (IServiceProvider sp) => Pages.Config(sp));
app.MapGet("/health", async (IServiceProvider sp) => await Pages.Health(sp));
app.MapPost("/emergency-stop", async (IServiceProvider sp) => await Pages.EmergencyStop(sp));
app.MapPost("/emergency-disarm", async (IServiceProvider sp) => await Pages.EmergencyStopDisarm(sp));

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

        // The stop lives on two surfaces by design: this process's latch AND the persisted flag
        // another process may have set via 'artemis assessment stop'. The banner reflects both,
        // so a stop armed from the CLI is visible here instead of silently denying schedules.
        var persistedStop = await db.GetConfigAsync<EmergencyStopFlag>(
            AssessmentCommands.EmergencyFlagKey);
        var anyArmed = emergency.Armed || persistedStop is not null;

        var body = new StringBuilder();
        body.Append("<h1>Dashboard</h1>");
        if (anyArmed)
        {
            var sources = new List<string>();
            if (emergency.Armed) sources.Add("console (reason: " + Esc(emergency.Reason) + ")");
            if (persistedStop is { } flag)
            {
                sources.Add("persisted flag, armed " + Esc(flag.ArmedUtc.ToString("u"))
                    + " (reason: " + Esc(flag.Reason) + ")");
            }

            body.Append("<p><strong style=\"color:#b71c1c\">EMERGENCY STOP ARMED</strong> - "
                + string.Join("; ", sources) + "</p>");
            body.Append("<form class=\"inline\" method=\"post\" action=\"/emergency-disarm\">");
            body.Append("<button type=\"submit\">Disarm emergency stop</button></form>");
        }
        else
        {
            body.Append("<form class=\"inline\" method=\"post\" action=\"/emergency-stop\">");
            body.Append("<button class=\"danger\" type=\"submit\">Activate emergency stop</button></form>");
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

    /// <summary>
    /// The discovered asset and service inventory, read-only by design. Out-of-scope discoveries
    /// stay permanently visible and flagged: an asset that should never have been reached is
    /// exactly the row an operator must not be able to lose.
    /// </summary>
    public static async Task<IResult> Inventory(IServiceProvider sp, string? assessment)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var assessmentId = Guid.TryParse(assessment, out var parsed) ? parsed : (Guid?)null;
        var assets = await db.ListAssetsAsync(assessmentId, 500);
        var services = await db.ListServicesAsync(assessmentId, 100_000);
        var byAsset = services.GroupBy(s => s.AssetId).ToDictionary(g => g.Key, g => g.ToList());

        var rows = new StringBuilder();
        foreach (var asset in assets)
        {
            var observed = byAsset.TryGetValue(asset.AssetId, out var found) ? found : [];
            var ports = observed.Count > 0
                ? Esc(string.Join(", ", observed
                    .OrderByDescending(s => s.TlsNegotiated).ThenBy(s => s.Port)
                    .Select(s => s.Port + "/" + s.Protocol + (s.TlsNegotiated ? "+tls" : ""))))
                : "-";
            rows.Append("<tr>");
            rows.Append("<td>").Append(Esc(asset.Kind)).Append("</td>");
            rows.Append("<td>").Append(Esc(asset.DisplayName)).Append("</td>");
            rows.Append("<td><code>").Append(Esc(asset.CanonicalTarget)).Append("</code></td>");
            rows.Append(asset.WithinScope
                ? "<td>in scope</td>"
                : "<td style=\"color:#b71c1c\"><strong>OUT OF SCOPE</strong></td>");
            rows.Append("<td>").Append(Esc(string.Join(", ", asset.ObservedIps))).Append("</td>");
            rows.Append("<td>").Append(ports).Append("</td>");
            rows.Append("<td>").Append(asset.DiscoveredAtUtc.ToLocalTime().ToString("u")).Append("</td></tr>");
        }

        // Filter form: one assessment or everything discovered so far.
        var assessments = await db.ListAssessmentsAsync(50);
        var options = new StringBuilder("<option value=\"\">All assessments</option>");
        foreach (var a in assessments)
        {
            options.Append(a.AssessmentId == assessmentId
                ? "<option value=\"" + a.AssessmentId + "\" selected>" + Esc(a.Name) + "</option>"
                : "<option value=\"" + a.AssessmentId + "\">" + Esc(a.Name) + "</option>");
        }

        var head = "<h1>Asset Inventory</h1>"
            + "<form class=\"inline\" method=\"get\" action=\"/inventory\"><select name=\"assessment\">"
            + options
            + "</select> <button type=\"submit\">Filter</button></form>";
        var table = "<table><tr><th>Kind</th><th>Name</th><th>Canonical target</th><th>Scope</th>"
            + "<th>Observed IPs</th><th>Services</th><th>Discovered</th></tr>"
            + rows + "</table>";
        return Results.Content(
            ArtemisConsoleLayout.Render("Asset Inventory", "Inventory", head + table), "text/html");
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

    public static Task<IResult> FindingDetail(IServiceProvider sp, Guid id, string? triaged) =>
        RenderFindingDetail(sp, id,
            triaged is null ? null : "<p><b>Triage decision recorded.</b> The status below and the "
            + "hash-chained audit log reflect it; the finding row shows who decided and why.</p>");

    private static async Task<IResult> RenderFindingDetail(IServiceProvider sp, Guid id, string? banner)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var all = await db.ListFindingsAsync(null, null, null, 100000);
        var finding = all.FirstOrDefault(f => f.FindingId == id);
        if (finding is null) return Results.NotFound("Finding not found.");

        var b = new StringBuilder();
        b.Append($"<h1>{Esc(finding.Title)}</h1>");
        if (banner is not null) b.Append(banner);
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

        // Triage: the persisted operator decision plus the form that produces the next one.
        // The select lists only the transitions the deterministic lifecycle allows from the
        // current status, so an illegal transition cannot even be composed here.
        var triage = await db.GetTriageAsync(finding.FindingId);
        b.Append("<h3>Triage</h3>");
        if (triage is { } decision)
        {
            b.Append("<p>Status <b>").Append(Esc(decision.Status)).Append("</b> decided by <b>")
                .Append(Esc(decision.TriagedBy)).Append("</b> at ").Append(decision.TriagedUtc?.ToString("u"));
            if (decision.Note is not null)
            {
                b.Append("<br>Note: ").Append(Esc(decision.Note));
            }

            b.Append("</p>");
        }
        else
        {
            b.Append("<p>No operator triage recorded yet.</p>");
        }

        var targets = FindingTransitions.AllowedTargets(finding.Status);
        b.Append("<form class=\"inline\" method=\"post\" action=\"/findings/")
            .Append(finding.FindingId).Append("/triage\">");
        b.Append("<select name=\"status\">");
        foreach (var target in targets)
        {
            b.Append("<option value=\"").Append(target).Append("\">").Append(target).Append("</option>");
        }

        b.Append("</select> ");
        b.Append("<input type=\"text\" name=\"note\" style=\"min-width:22rem\" "
            + "placeholder=\"Reason / note stored with the decision\" /> ");
        b.Append("<button type=\"submit\">Record triage</button></form>");
        return Results.Content(ArtemisConsoleLayout.Render("Finding detail", "Findings", b.ToString()), "text/html");
    }

    /// <summary>
    /// Console entry into the audited triage lifecycle. Success redirects back with the new status
    /// visible; refusal re-renders the page with the engine's fail-closed reason instead of
    /// pretending nothing happened.
    /// </summary>
    public static async Task<IResult> Triage(IServiceProvider sp, Guid id, HttpRequest request)
    {
        var form = await request.ReadFormAsync();
        var statusRaw = form["status"].ToString();
        var note = form["note"].ToString();
        if (!Enum.TryParse<FindingStatus>(statusRaw, ignoreCase: true, out var status)
            || !Enum.IsDefined(status))
        {
            return Results.BadRequest("Unknown triage status.");
        }

        var db = sp.GetRequiredService<ActDatabase>();
        try
        {
            await db.TriageFindingAsync(id, status, "operator-console",
                string.IsNullOrWhiteSpace(note) ? null : note.Trim(), CorrelationId.New());
            return Results.Redirect($"/findings/{id}?triaged={status}", permanent: false);
        }
        catch (ActException ex)
        {
            var failure = "<p style=\"color:#b71c1c\"><strong>Triage refused:</strong> "
                + Esc(ex.SafeMessage) + "</p>";
            return await RenderFindingDetail(sp, id, failure);
        }
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

    /// <summary>
    /// Ends an emergency stop from the console: clears the persisted flag other processes poll,
    /// disarms this host's latches, and records both in the hash-chained audit log.
    /// </summary>
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

/// <summary>Bridges console-initiated stops to the host-wide policy latch.</summary>
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
