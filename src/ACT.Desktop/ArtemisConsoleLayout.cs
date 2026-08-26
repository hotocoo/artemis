using System.Text;
using System.Text.Encodings.Web;

namespace ACT.Desktop;

/// <summary>Shared HTML chrome for operator console pages. All dynamic values must arrive pre-encoded.</summary>
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
        html.Append("<title>").Append(Encoder.Encode(title)).Append(" - Artemis</title>");
        AppendStyle(html);
        html.Append("</head><body style=\"font-family:'Segoe UI',system-ui,sans-serif;margin:0;display:flex;min-height:100vh\">");
        html.Append("<nav style=\"width:200px;background:#1c2433;padding-top:2rem\">");
        html.Append("<div style=\"padding:0 1.2rem 1.5rem;color:#8fa1bd;font-weight:600\">ARTEMIS</div>");

        foreach (var (href, name) in navItems)
        {
            var cssClass = name == activeNav ? "active" : "";
            html.Append($"<a class=\"{cssClass}\" href=\"{href}\">{Encoder.Encode(name)}</a>");
        }

        html.Append("</nav><main style=\"flex:1;padding:2rem 2.5rem;max-width:1200px\">");
        html.Append(body);
        html.Append("</main></body></html>");
        return html.ToString();
    }

    private static void AppendStyle(StringBuilder html)
    {
        const string css =
            "table{border-collapse:collapse;width:100%;margin:1rem 0;font-size:.92rem}" +
            "th,td{text-align:left;padding:.55rem .7rem;border-bottom:1px solid #d5dbe4;vertical-align:top}" +
            "th{background:#eef2f7;font-weight:600}" +
            ".sev-High{color:#c62828}.sev-Critical{color:#fff;background:#b71c1c;padding:.05rem .4rem;border-radius:3px}" +
            ".cards{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:1.5rem}" +
            ".card{background:#f4f6fa;border-radius:8px;padding:1rem 1.3rem;min-width:150px}" +
            ".card b{display:block;font-size:1.6rem}" +
            "form.inline{display:inline}" +
            "button.danger{background:#b71c1c;color:#fff;border:none;padding:.5rem 1rem;border-radius:4px;cursor:pointer}" +
            "code,pre{background:#f0f2f6;border-radius:4px;padding:.1rem .35rem;font-size:.85rem}";

        html.Append("<style>");
        html.Append("h1{font-weight:600;margin-top:0}");
        html.Append(css);
        html.Append(".sev-Low{color:#2e7d32}.sev-Medium{color:#b26a00}.sev-Informational{color:#5b6470}");
        html.Append("</style>");
    }
}
