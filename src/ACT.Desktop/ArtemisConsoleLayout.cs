using System.Text;
using System.Text.Encodings.Web;

namespace ACT.Desktop;

/// <summary>
/// Shared HTML chrome for operator console pages. All dynamic values must arrive pre-encoded.
/// The stylesheet is a small design-token system: one accent, semantic status tones, one radius
/// scale, tabular numerals for data, and a responsive shell - deliberately static (no JavaScript)
/// because this is a dense operator surface where clarity outranks decoration.
/// </summary>
internal static class ArtemisConsoleLayout
{
    private static readonly HtmlEncoder Encoder = HtmlEncoder.Default;

    public static string Render(string title, string activeNav, string body)
    {
        var navItems = new (string Href, string Name)[]
        {
            ("/", "Dashboard"),
            ("/assessments", "Assessments"),
            ("/inventory", "Inventory"),
            ("/findings", "Findings"),
            ("/coverage", "Coverage"),
            ("/reports", "Reports"),
            ("/regressions", "Regressions"),
            ("/baselines", "Baselines"),
            ("/schedules", "Schedules"),
            ("/audit", "Audit Log"),
            ("/config", "Configuration"),
            ("/health", "System Health")
        };

        var html = new StringBuilder();
        html.Append("<!DOCTYPE html><html lang=\"en\"><head>");
        html.Append("<meta charset=\"utf-8\" />");
        html.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />");
        html.Append("<meta name=\"color-scheme\" content=\"light\" />");
        html.Append("<meta name=\"theme-color\" content=\"#151c28\" />");
        html.Append("<link rel=\"icon\" href=\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%23151c28'/%3E%3Cpath d='M16 6l9 4v7c0 5-3.8 8.2-9 9-5.2-.8-9-4-9-9v-7z' fill='none' stroke='%232563eb' stroke-width='2.4'/%3E%3C/svg%3E\" />");
        html.Append("<title>").Append(Encoder.Encode(title)).Append(" - Artemis</title>");
        AppendStyle(html);
        html.Append("</head><body><div class=\"shell\">");
        html.Append("<nav aria-label=\"Console sections\">");
        html.Append("<div class=\"brand\">ARTEMIS<span>operator console</span></div>");

        foreach (var (href, name) in navItems)
        {
            var isActive = name == activeNav;
            html.Append(isActive
                ? $"<a class=\"active\" aria-current=\"page\" href=\"{href}\">{Encoder.Encode(name)}</a>"
                : $"<a href=\"{href}\">{Encoder.Encode(name)}</a>");
        }

        html.Append("</nav><main id=\"main\">");
        html.Append(body);
        html.Append("</main></div></body></html>");
        return html.ToString();
    }

    private static void AppendStyle(StringBuilder html)
    {
        // Design tokens: one accent (steel blue), neutral ink/surface ramp, four semantic status
        // tones, one radius scale (6px controls / 10px surfaces). Severity classes keep their
        // historical names so every existing page upgrades without markup changes.
        const string css = """
            :root {
              --bg:#f4f6f9; --surface:#ffffff; --ink:#1d2530; --muted:#5b6572;
              --line:#dde3ea; --line-strong:#c8d0da;
              --accent:#2563eb; --accent-ink:#ffffff; --accent-soft:#e8effc;
              --ok:#1b7a43; --ok-soft:#e3f3e9;
              --warn:#9a5b00; --warn-soft:#fdf0dc;
              --bad:#b3261e; --bad-soft:#fbe9e7;
              --info:#5b6572; --info-soft:#eceff3;
              --sidebar:#151c28; --sidebar-ink:#9aa8bd; --sidebar-active:#f2f5fa;
              --radius-s:6px; --radius-m:10px;
              --mono:ui-monospace,'Cascadia Mono','SF Mono',Consolas,monospace;
            }
            * { box-sizing:border-box }
            html,body { margin:0 }
            body {
              font-family:'Segoe UI',system-ui,-apple-system,sans-serif;
              font-size:.95rem; line-height:1.55; color:var(--ink); background:var(--bg);
            }
            .shell { display:flex; min-height:100dvh }

            /* ---- sidebar ---- */
            .shell > nav {
              width:212px; flex:none; background:var(--sidebar); color:var(--sidebar-ink);
              padding:1.4rem .75rem 2rem; position:sticky; top:0;
              height:100dvh; overflow-y:auto;
            }
            .brand {
              padding:.2rem .75rem 1.1rem; color:#e8edf5; font-weight:700;
              letter-spacing:.22em; font-size:.95rem;
            }
            .brand span {
              display:block; letter-spacing:.02em; font-weight:400;
              font-size:.68rem; color:var(--sidebar-ink); margin-top:.15rem;
            }
            .shell > nav a {
              display:block; padding:.44rem .75rem; margin-bottom:2px;
              border-radius:var(--radius-s); text-decoration:none;
              color:var(--sidebar-ink); font-size:.88rem;
              border-left:3px solid transparent;
            }
            .shell > nav a:hover { background:rgba(255,255,255,.06); color:#dbe4f0 }
            .shell > nav a.active {
              background:rgba(255,255,255,.08); color:var(--sidebar-active);
              border-left-color:var(--accent); font-weight:600;
            }
            .shell > nav a:focus-visible { outline:2px solid var(--accent); outline-offset:-2px }

            /* ---- main column ---- */
            main {
              flex:1; padding:2.2rem 2.6rem 4rem; max-width:1240px; min-width:0;
            }
            h1 { font-size:1.45rem; font-weight:650; margin:0 0 .35rem; letter-spacing:-.01em }
            h2 { font-size:1.05rem; font-weight:650; margin:1.8rem 0 .4rem }
            h3 { font-size:.78rem; font-weight:650; text-transform:uppercase; letter-spacing:.09em;
                 color:var(--muted); margin:1.6rem 0 .45rem }
            p { margin:.45rem 0 }
            a { color:var(--accent) }
            a:hover { text-decoration-thickness:2px }
            .sub { color:var(--muted); max-width:72ch; margin-bottom:1.2rem }
            .small { font-size:.82rem }
            .muted { color:var(--muted) }
            .num { text-align:right; font-variant-numeric:tabular-nums }
            .mono { font-family:var(--mono); font-size:.8rem; overflow-wrap:anywhere }
            code, pre { font-family:var(--mono); font-size:.84em }
            code { background:var(--info-soft); border-radius:4px; padding:.08rem .32rem;
                   overflow-wrap:anywhere }
            pre {
              background:var(--surface); border:1px solid var(--line); border-radius:var(--radius-m);
              padding:.8rem 1rem; overflow-x:auto; line-height:1.45;
            }

            /* ---- tables ---- */
            table { border-collapse:collapse; width:100%; margin:1rem 0; font-size:.88rem }
            th, td { text-align:left; padding:.52rem .7rem; vertical-align:top;
                     border-bottom:1px solid var(--line) }
            th {
              background:var(--surface); color:var(--muted); font-weight:600;
              font-size:.68rem; text-transform:uppercase; letter-spacing:.08em;
              border-bottom:1px solid var(--line-strong);
            }
            tbody tr:hover td, tr:hover td { background:#f7f9fc }
            td { overflow-wrap:anywhere }

            /* ---- metric cards ---- */
            .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(142px,1fr));
                     gap:.7rem; margin:1.1rem 0 1.4rem }
            .card {
              background:var(--surface); border:1px solid var(--line); border-radius:var(--radius-m);
              padding:.8rem 1rem; font-size:.78rem; color:var(--muted);
            }
            .card b {
              display:block; font-size:1.45rem; font-weight:650; color:var(--ink);
              font-variant-numeric:tabular-nums; line-height:1.25;
            }

            /* ---- status pills and severity tones ---- */
            .pill {
              display:inline-block; padding:.06rem .5rem; border-radius:999px;
              font-size:.74rem; font-weight:600; white-space:nowrap;
            }
            .pill-ok   { background:var(--ok-soft);   color:var(--ok) }
            .pill-warn { background:var(--warn-soft); color:var(--warn) }
            .pill-bad  { background:var(--bad-soft);  color:var(--bad) }
            .pill-info { background:var(--info-soft); color:var(--info) }
            .pill-muted { background:transparent; color:var(--muted);
                          box-shadow:inset 0 0 0 1px var(--line-strong) }
            .sev-Critical      { background:var(--bad); color:#fff; padding:.06rem .5rem;
                                 border-radius:999px; font-size:.74rem; font-weight:600 }
            .sev-High          { color:var(--bad); font-weight:600 }
            .sev-Medium        { color:var(--warn); font-weight:600 }
            .sev-Low           { color:var(--ok); font-weight:600 }
            .sev-Informational { color:var(--info); font-weight:600 }

            /* ---- alerts and empty states ---- */
            .alert {
              border:1px solid var(--line); border-left-width:4px; border-radius:var(--radius-s);
              padding:.7rem 1rem; margin:.9rem 0; background:var(--surface);
            }
            .alert-danger { border-color:var(--bad-soft); border-left-color:var(--bad);
                            background:var(--bad-soft); color:#6e201b }
            .alert-warn   { border-color:var(--warn-soft); border-left-color:var(--warn);
                            background:var(--warn-soft); color:var(--warn) }
            .alert-ok     { border-color:var(--ok-soft); border-left-color:var(--ok);
                            background:var(--ok-soft); color:var(--ok) }
            .empty {
              border:1px dashed var(--line-strong); border-radius:var(--radius-m);
              padding:1.4rem 1.5rem; color:var(--muted); background:transparent;
            }

            /* ---- forms and buttons ---- */
            form.inline { display:inline }
            form.stack { margin:.6rem 0; display:flex; gap:.5rem; flex-wrap:wrap; align-items:center }
            button {
              font:inherit; font-size:.86rem; font-weight:600; cursor:pointer;
              background:var(--surface); color:var(--ink);
              border:1px solid var(--line-strong); border-radius:var(--radius-s);
              padding:.38rem .85rem;
            }
            button:hover { background:var(--accent-soft); border-color:var(--accent); color:var(--accent) }
            button:active { transform:translateY(1px) }
            button.danger { background:var(--bad); border-color:var(--bad); color:#fff }
            button.danger:hover { background:#99231c; border-color:#99231c; color:#fff }
            select, input[type="text"] {
              font:inherit; font-size:.88rem; color:var(--ink);
              background:var(--surface); border:1px solid var(--line-strong);
              border-radius:var(--radius-s); padding:.36rem .6rem;
            }
            select:focus-visible, input:focus-visible, button:focus-visible {
              outline:2px solid var(--accent); outline-offset:1px;
            }

            /* ---- audit filter chips ---- */
            .chips { display:flex; gap:.4rem; flex-wrap:wrap; margin:.6rem 0 }
            .chip {
              display:inline-block; padding:.14rem .7rem; border-radius:999px;
              border:1px solid var(--line-strong); text-decoration:none;
              font-size:.78rem; color:var(--muted); background:var(--surface);
            }
            .chip:hover { border-color:var(--accent); color:var(--accent) }
            .chip.active { background:var(--accent); border-color:var(--accent);
                           color:var(--accent-ink); font-weight:600 }

            @media (max-width:920px) {
              .shell { flex-direction:column }
              .shell > nav { position:static; width:100%; height:auto;
                             display:flex; flex-wrap:wrap; align-items:center; gap:.15rem;
                             padding:.6rem .8rem }
              .brand { width:100%; padding:.2rem .4rem .6rem }
              .shell > nav a { border-left:none; padding:.34rem .6rem }
              main { padding:1.4rem 1.1rem 3rem }
            }
            @media print {
              .shell > nav { display:none }
              main { max-width:none; padding:0 }
            }
            @media (prefers-reduced-motion:reduce) {
              * { transition:none !important }
            }
            """;

        html.Append("<style>").Append(css).Append("</style>");
    }
}
