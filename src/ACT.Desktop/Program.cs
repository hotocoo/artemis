
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

    /// <summary>
    /// Security baselines: one row per recent assessment with its scope's latest baseline and the
    /// two operator actions - snapshot this assessment into a new baseline, or compare it against
    /// the existing one. Creation accepts only fingerprints already dispositioned through triage,
    /// so a baseline can never silently bless open issues.
    /// </summary>
    public static async Task<IResult> Baselines(IServiceProvider sp, string? created, string? error)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var assessments = await db.ListAssessmentsAsync(50);

        var latestByScope = new Dictionary<Guid, SecurityBaseline>();
        foreach (var scopeId in assessments.Select(static a => a.ScopeId).Distinct())
        {
            if (await db.GetLatestBaselineAsync(scopeId) is { } baseline)
            {
                latestByScope[scopeId] = baseline;
            }
        }

        var b = new StringBuilder();
        b.Append("<h1>Security Baselines</h1>");
        if (created is not null)
        {
            b.Append("<p><b>Baseline stored.</b> It snapshots that assessment's observed services and ")
                .Append("only the finding fingerprints an operator had dispositioned through triage. ")
                .Append("Compare any later assessment of the same scope against it.</p>");
        }

        if (error is not null)
        {
            b.Append("<p style=\"color:#b71c1c\"><strong>Refused:</strong> ").Append(Esc(error)).Append("</p>");
        }

        b.Append("<p>A comparison lists service drift plus finding-level drift (new, regressed, resolved-or-unobserved) ")
            .Append("at honest severities. Resolved entries remind you that absence alone cannot distinguish a fix ")
            .Append("from checks that did not run.</p>");

        var rows = new StringBuilder();
        foreach (var assessment in assessments)
        {
            var baseline = latestByScope.GetValueOrDefault(assessment.ScopeId);
            rows.Append("<tr>");
            rows.Append($"<td><a href=\"/findings?assessment={assessment.AssessmentId}\">{Esc(assessment.Name)}</a></td>");
            rows.Append($"<td>{Esc(assessment.State)}</td><td><code>{ShortId(assessment.ScopeId)}</code></td>");
            rows.Append(baseline is null
                ? "<td>-</td>"
                : "<td>" + Esc(baseline.Name) + "<br><small>" + baseline.CreatedUtc.ToString("u")
                    + " - " + baseline.ExpectedServices.Count + " services, "
                    + baseline.AcceptedFindingFingerprints.Count + " accepted</small></td>");
            rows.Append("<td>");
            rows.Append("<form class=\"inline\" method=\"post\" action=\"/baselines/create\">");
            rows.Append($"<input type=\"hidden\" name=\"assessment\" value=\"{assessment.AssessmentId}\" /> ");
            rows.Append("<input type=\"text\" name=\"name\" style=\"max-width:12rem\" placeholder=\"optional name\" /> ");
            rows.Append("<button type=\"submit\">Create from this run</button></form>");
            if (baseline is not null)
            {
                rows.Append(" <a href=\"/baselines/compare?assessment=" + assessment.AssessmentId + "\">Compare</a>");
            }

            rows.Append("</td></tr>");
        }

        var table = "<table><tr><th>Assessment</th><th>State</th><th>Scope</th><th>Latest baseline for scope</th><th>Actions</th></tr>"
            + rows + "</table>";
        return Results.Content(
            ArtemisConsoleLayout.Render("Baselines", "Baselines", b.ToString() + table), "text/html");
    }

    public static async Task<IResult> BaselineCompare(IServiceProvider sp, Guid assessment)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        if (await db.GetAssessmentAsync(assessment) is not { } record)
        {
            return Results.NotFound("Assessment not found.");
        }

        string body;
        try
        {
            var comparison = await BaselineOperations.CompareAsync(
                db, assessment, null, "operator-console", CorrelationId.New());
            var summary = comparison.Observations.Count == 0
                ? "<p><b>No drift:</b> this assessment matches baseline <code>" + ShortId(comparison.BaselineId)
                    + "</code> exactly. That never means the environment is secure.</p>"
                : "<p><b>" + comparison.Observations.Count + " drift observation(s)</b> against baseline <code>"
                    + ShortId(comparison.BaselineId) + "</code>.</p>";
            var rows = new StringBuilder();
            foreach (var observation in comparison.Observations)
            {
                rows.Append("<tr>");
                rows.Append($"<td><span class=\"sev-{observation.SuggestedSeverity}\">{observation.SuggestedSeverity}</span></td>");
                rows.Append("<td><code>").Append(Esc(observation.Kind)).Append("</code></td>");
                rows.Append("<td>").Append(Esc(observation.Detail)).Append("</td></tr>");
            }

            var table = comparison.Observations.Count == 0
                ? ""
                : "<table><tr><th>Severity</th><th>Kind</th><th>Detail</th></tr>" + rows + "</table>";
            body = "<h1>Baseline comparison - " + Esc(record.Name) + "</h1>" + summary + table;
        }
        catch (ActException ex)
        {
            body = "<h1>Baseline comparison - " + Esc(record.Name) + "</h1>"
                + "<p style=\"color:#b71c1c\"><strong>Comparison refused:</strong> " + Esc(ex.SafeMessage) + "</p>";
        }

        return Results.Content(ArtemisConsoleLayout.Render("Baselines", "Baselines", body), "text/html");
    }

    /// <summary>Console entry into audited baseline creation; refusals re-render the page honestly.</summary>
    public static async Task<IResult> BaselineCreate(IServiceProvider sp, HttpRequest request)
    {
        var form = await request.ReadFormAsync();
        if (!Guid.TryParse(form["assessment"].ToString(), out var assessmentId))
        {
            return Results.BadRequest("Unknown assessment.");
        }

        var db = sp.GetRequiredService<ActDatabase>();
        var assessment = await db.GetAssessmentAsync(assessmentId);
        if (assessment is null)
        {
            return Results.Redirect("/baselines?error=" + Uri.EscapeDataString("assessment not found"), permanent: false);
        }

        var name = form["name"].ToString().Trim();
        try
        {
            var baseline = await BaselineOperations.CreateAsync(
                db,
                assessment,
                name.Length > 0 ? name : "baseline " + DateTimeOffset.UtcNow.ToString("yyyy-MM-dd HH:mm 'UTC'"),
                "operator-console",
                CorrelationId.New());
            return Results.Redirect("/baselines?created=" + baseline.BaselineId, permanent: false);
        }
        catch (ActException ex)
        {
            return Results.Redirect("/baselines?error=" + Uri.EscapeDataString(ex.SafeMessage), permanent: false);
        }
    }


    /// <summary>
    /// Reports: every stored assessment renders into any supported format from persisted rows
    /// only. Generation is audited exactly like on the CLI - a report handed to an auditor or a
    /// CI gate is part of the assessment lifecycle, not a private view.
    /// </summary>
    public static async Task<IResult> Reports(IServiceProvider sp)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var assessments = await db.ListAssessmentsAsync(50);

        var b = new StringBuilder();
        b.Append("<h1>Reports</h1>");
        b.Append("<p>Each report is assembled strictly from persisted rows and rendered deterministically ")
            .Append("per format (JSON, CSV, Markdown, HTML, SARIF 2.1). Every generation - here or via ")
            .Append("<code>artemis report generate</code> - lands in the hash-chained audit log as ")
            .Append("<code>report.generated</code>. Absence of findings never implies absence of vulnerabilities.</p>");

        if (assessments.Count == 0)
        {
            b.Append("<p>No assessments stored yet. Start one with <code>artemis assessment start --scope my-scope.json</code>.</p>");
        }
        else
        {
            var labels = new Dictionary<ReportFormat, string>
            {
                [ReportFormat.Json] = "JSON",
                [ReportFormat.Csv] = "CSV",
                [ReportFormat.Markdown] = "Markdown",
                [ReportFormat.Html] = "HTML",
                [ReportFormat.Sarif] = "SARIF"
            };
            var formats = new[] { ReportFormat.Json, ReportFormat.Csv, ReportFormat.Markdown, ReportFormat.Html, ReportFormat.Sarif };

            var rows = new StringBuilder();
            foreach (var a in assessments)
            {
                rows.Append("<tr>");
                rows.Append("<td><a href=\"/findings?assessment=").Append(a.AssessmentId).Append("\">")
                    .Append(Esc(a.Name)).Append("</a></td>");
                rows.Append("<td>").Append(Esc(a.State)).Append("</td>");
                rows.Append("<td>").Append(Esc(a.Organization)).Append("</td>");
                rows.Append("<td>").Append(a.CreatedUtc.ToLocalTime().ToString("u")).Append("</td>");
                rows.Append("<td>");
                for (var i = 0; i < formats.Length; i++)
                {
                    if (i > 0) rows.Append(" &#183; ");
                    rows.Append("<a href=\"/reports/").Append(a.AssessmentId).Append("/report.")
                        .Append(ReportOperations.Extension(formats[i])).Append("\">")
                        .Append(Esc(labels[formats[i]])).Append("</a>");
                }

                rows.Append("</td></tr>");
            }

            b.Append("<table><tr><th>Assessment</th><th>State</th><th>Organization</th><th>Created</th><th>Download</th></tr>")
                .Append(rows).Append("</table>");
        }

        return Results.Content(ArtemisConsoleLayout.Render("Reports", "Reports", b.ToString()), "text/html");
    }

    /// <summary>Serves one audited report generation as a download; refusals stay honest.</summary>
    public static async Task<IResult> ReportDownload(IServiceProvider sp, Guid assessment, string format)
    {
        if (!ReportOperations.TryParseFormat(format, out var parsed))
        {
            return Results.NotFound("Unknown report format '" + format + "'. Supported: json, csv, markdown, html, sarif.");
        }

        var db = sp.GetRequiredService<ActDatabase>();
        try
        {
            var report = await ReportOperations.GenerateAsync(db, assessment, parsed, "operator-console", CorrelationId.New());
            return Results.File(
                Encoding.UTF8.GetBytes(report.Content),
                ReportOperations.ContentType(parsed),
                ReportOperations.FileName(assessment, parsed));
        }
        catch (ActException ex)
        {
            return Results.NotFound(ex.SafeMessage);
        }
    }

    /// <summary>
    /// Stored regression tests: the durable promise that every fixture-backed authorization finding
    /// keeps being re-verified on its cadence. Due tests lead the list; disabled ones stay visible
    /// with their history instead of disappearing. Replays themselves run from the CLI against an
    /// explicitly supplied base URL - a console button that silently picked its own target to
    /// contact would be exactly the kind of unscoped network action this platform refuses.
    /// </summary>
    public static async Task<IResult> Regressions(IServiceProvider sp)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var tests = await db.ListRegressionTestsAsync(200);
        var assessments = await db.ListAssessmentsAsync(200);
        var names = assessments.ToDictionary(a => a.AssessmentId, static a => a.Name);
        var now = DateTimeOffset.UtcNow;

        var b = new StringBuilder();
        b.Append("<h1>Regression Tests</h1>");
        b.Append("<p>Each row re-verifies one known finding on its cadence: the stored replay runs ")
            .Append("from the CLI (<code>artemis regression run --finding ID --base-url URL</code>) and every ")
            .Append("verdict is recorded here with an audited event. A FAIL means the original issue returned.</p>");

        if (tests.Count == 0)
        {
            b.Append("<p>No regression tests stored yet. They are captured automatically when an assessment ")
                .Append("runs with operator-supplied <a href=\"/config\">authorization fixtures</a>.</p>");
        }
        else
        {
            var rows = new StringBuilder();
            foreach (var test in tests)
            {
                var due = test.Enabled && test.NextRunUtc <= now;
                string lastVerdict = "-";
                if (test.LastRunUtc is { } lastRun)
                {
                    var runs = await db.ListTestRunsAsync(test.RegressionTestId, 1);
                    lastVerdict = runs.Count > 0
                        ? $"<span class=\"sev-{(runs[0].Result == VerificationState.Confirmed ? "High" : "Low")}\">{runs[0].Result}</span> "
                            + Esc(runs[0].RanAtUtc.ToString("u"))
                        : "recorded " + Esc(lastRun.ToString("u"));
                }

                rows.Append("<tr>");
                rows.Append("<td><a href=\"/regressions/").Append(test.RegressionTestId).Append("\">")
                    .Append(Esc(test.Name)).Append("</a></td>");
                rows.Append($"<td><span class=\"sev-{test.SuggestedSeverity}\">{test.SuggestedSeverity}</span></td>");
                rows.Append("<td>").Append(test.Enabled ? "enabled" : "<b>disabled</b>").Append(due ? " <b>DUE</b>" : "").Append("</td>");
                rows.Append("<td>").Append(Esc(RegressionOperations.FormatCadence(test.Cadence))).Append("</td>");
                rows.Append("<td>").Append(lastVerdict).Append("</td>");
                rows.Append("<td>").Append(Esc(names.GetValueOrDefault(test.OriginAssessmentId, ShortId(test.OriginAssessmentId)))).Append("</td>");
                rows.Append("<td><form class=\"inline\" method=\"post\" action=\"/regressions/")
                    .Append(test.RegressionTestId).Append("/toggle\"><button type=\"submit\">")
                    .Append(test.Enabled ? "Pause" : "Resume").Append("</button></form></td>");
                rows.Append("</tr>");
            }

            b.Append("<table><tr><th>Test</th><th>Severity</th><th>State</th><th>Cadence</th>")
                .Append("<th>Last verdict</th><th>Origin assessment</th><th></th></tr>")
                .Append(rows).Append("</table>");
        }

        return Results.Content(
            ArtemisConsoleLayout.Render("Regressions", "Regressions", b.ToString()), "text/html");
    }

    public static async Task<IResult> RegressionDetail(IServiceProvider sp, Guid id)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var test = await db.GetRegressionTestAsync(id);
        if (test is null) return Results.NotFound("Regression test not found.");

        var b = new StringBuilder();
        b.Append("<h1>").Append(Esc(test.Name)).Append("</h1>");
        b.Append($"<p><span class=\"sev-{test.SuggestedSeverity}\">{test.SuggestedSeverity}</span>, ")
            .Append(test.Enabled ? "enabled" : "disabled").Append(", cadence ")
            .Append(Esc(RegressionOperations.FormatCadence(test.Cadence)))
            .Append(". Created ").Append(test.CreatedUtc.ToString("u"))
            .Append(" - next scheduled verification ").Append(test.NextRunUtc.ToString("u")).Append(".</p>");
        b.Append("<p>Origin finding <a href=\"/findings/").Append(test.FindingId).Append("\">")
            .Append(ShortId(test.FindingId)).Append("</a> from assessment ")
            .Append(ShortId(test.OriginAssessmentId)).Append(".</p>");

        if (test.RecipeJson is { } recipeJson)
        {
            try
            {
                var recipe = RegressionRunner.Deserialize(recipeJson);
                if (recipe is { } executable)
                {
                    b.Append("<h3>Replay steps</h3><ol>");
                    foreach (var step in executable.Steps)
                    {
                        b.Append("<li><b>Given</b> ").Append(Esc(step.Given))
                            .Append(" - <b>when</b> ").Append(Esc(step.When))
                            .Append(", <b>then</b> ").Append(Esc(step.Then)).Append("</li>");
                    }

                    b.Append("</ol>");
                    if (executable.HttpExpectation is { } expectation)
                    {
                        b.Append("<p>Executable check: <code>").Append(Esc(expectation.Method + " " + expectation.Url.PathAndQuery))
                            .Append("</code> must answer within <b>").Append(expectation.ExpectedStatusMin)
                            .Append("..").Append(expectation.ExpectedStatusMax).Append("</b>.</p>");
                        b.Append("<p>Run it from the CLI against the authorized origin:</p><pre>artemis regression run --finding ")
                            .Append(test.FindingId).Append(" --base-url URL</pre>");
                    }
                }
            }
            catch (ActException)
            {
                b.Append("<p style=\"color:#b71c1c\">Stored recipe unreadable; treat this test as manual-only.</p>");
            }
        }
        else
        {
            b.Append("<p>This row predates stored recipes; it is tracked manually.</p>");
        }

        var runs = await db.ListTestRunsAsync(id, 20);
        b.Append("<h3>Run history</h3>");
        if (runs.Count == 0)
        {
            b.Append("<p>Never executed yet.</p>");
        }
        else
        {
            var rows = new StringBuilder();
            foreach (var run in runs)
            {
                rows.Append("<tr><td>").Append(run.RanAtUtc.ToString("u")).Append("</td><td>")
                    .Append(run.Result == VerificationState.Confirmed
                        ? "<b style=\"color:#c62828\">REGRESSED</b>"
                        : "<span class=\"sev-Low\">held</span>")
                    .Append("</td><td>").Append(Esc(run.Detail)).Append("</td></tr>");
            }

            b.Append("<table><tr><th>Ran (UTC)</th><th>Verdict</th><th>Detail</th></tr>").Append(rows).Append("</table>");
        }

        return Results.Content(
            ArtemisConsoleLayout.Render("Regression detail", "Regressions", b.ToString()), "text/html");
    }

    /// <summary>Console entry into pausing or resuming one regression cadence, audited either way.</summary>
    public static async Task<IResult> RegressionToggle(IServiceProvider sp, Guid id)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var test = await db.GetRegressionTestAsync(id);
        if (test is null) return Results.NotFound("Regression test not found.");

        try
        {
            await RegressionOperations.SetEnabledAsync(db, id, !test.Enabled, "operator-console", CorrelationId.New());
        }
        catch (ActException ex)
        {
            return Results.BadRequest(ex.SafeMessage);
        }

        return Results.Redirect("/regressions", permanent: false);
    }

    private static string ShortId(Guid value) => value.ToString("N")[..8];

    public static async Task<IResult> Audit(IServiceProvider sp, string? action, int? limit)
    {
        var db = sp.GetRequiredService<ActDatabase>();
        var pageSize = limit is > 0 and <= 1000 ? limit.Value : 200;
        var actionPrefix = action?.Trim() is { Length: > 0 } prefix ? prefix : null;

        var events = await db.ListAuditEventsAsync(pageSize, actionPrefix);
        var total = await db.CountAuditEventsAsync();
        var verification = await db.VerifyChainDetailedAsync();

        var rows = new StringBuilder();
        foreach (var e in events)
        {
            rows.Append($"<tr><td>{e.Sequence}</td><td>{e.TimestampUtc:u}</td><td>{Esc(e.Actor)}</td>");
            rows.Append($"<td>{Esc(e.Action)}</td><td>{Esc(e.ObjectType)}:{Esc(e.ObjectId)}</td>");
            rows.Append($"<td>{Esc(e.Result)}</td><td style=\"font-size:.75rem\">{e.EventHash[..16]}...</td></tr>");
        }

        string banner;
        if (verification.Verified)
        {
            banner = $"<p>Hash chain verified over all {verification.EventCount} stored events.</p>";
        }
        else
        {
            // Name where the history stops being trustworthy instead of only saying that it does.
            banner = "<p style=\"color:#b71c1c\"><strong>HASH CHAIN VERIFICATION FAILED</strong> - the audit log may have been tampered with.<br>"
                + $"First broken entry: sequence {verification.FirstBrokenSequence} ({Esc(verification.Reason ?? "unverified")}).</p>";
        }

        // Quick filters over the event families every operator eventually hunts for.
        var chips = new StringBuilder();
        chips.Append("<p style=\"font-size:.85rem\">Filter: ");
        foreach (var candidate in new[] { null, "assessment.", "finding.", "baseline.", "regression.", "schedule.", "evidence." })
        {
            var label = candidate ?? "all";
            var selected = candidate == actionPrefix;
            chips.Append(selected
                ? "<b>" + Esc(label) + "</b> "
                : "<a href=\"/audit" + (candidate is null ? "" : "?action=" + Uri.EscapeDataString(candidate)) + "\">" + Esc(label) + "</a> ");
        }

        chips.Append("</p>");
        var head = "<h1>Audit Log</h1>" + chips
            + $"<p style=\"color:#555;font-size:.85rem\">showing {events.Count} of {total} stored event(s)"
            + (actionPrefix is null ? "" : ", action prefix &#39;" + Esc(actionPrefix) + "&#39;") + ", newest first.</p>";
        var table = "<table><tr><th>#</th><th>Time (UTC)</th><th>Actor</th><th>Action</th><th>Object</th><th>Result</th><th>Hash</th></tr>" + rows + "</table>";
        return Results.Content(
            ArtemisConsoleLayout.Render("Audit Log", "Audit Log", head + banner + table), "text/html");
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
