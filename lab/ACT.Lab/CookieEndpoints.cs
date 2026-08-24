namespace ACT.Lab;

/// <summary>Session-cookie contrast fixtures: unprotected versus hardened.</summary>
public static class CookieEndpoints
{
    private const string SyntheticSessionValue = "SYNTHETIC-session-value";

    /// <summary>Maps /cookies/bad and /cookies/good.</summary>
    public static void MapCookieEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/cookies/bad", static (HttpResponse response) =>
        {
            // Fixture: session cookie issued with Path=/ only — no Secure, no HttpOnly, no SameSite.
            response.Cookies.Append("sid", SyntheticSessionValue, new CookieOptions { Path = "/" });
            return TypedResults.Content(Describe("Issued sid without Secure, HttpOnly, or SameSite."), "text/html; charset=utf-8");
        });

        endpoints.MapGet("/cookies/good", static (HttpResponse response) =>
        {
            response.Cookies.Append("sid", SyntheticSessionValue, new CookieOptions
            {
                Path = "/",
                Secure = true,
                HttpOnly = true,
                SameSite = SameSiteMode.Strict,
            });
            return TypedResults.Content(Describe("Issued sid with Secure, HttpOnly, and SameSite=Strict."), "text/html; charset=utf-8");
        });
    }

    private static string Describe(string sentence) => $"""
        <!doctype html>
        <html lang="en">
          <head><meta charset="utf-8"><title>Cookie fixture</title></head>
          <body><p>{sentence}</p></body>
        </html>
        """;
}
