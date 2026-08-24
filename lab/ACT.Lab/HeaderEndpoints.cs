namespace ACT.Lab;

/// <summary>Security-header contrast fixtures: one bare response and one fully hardened.</summary>
public static class HeaderEndpoints
{
    /// <summary>Maps /headers/missing and /headers/good.</summary>
    public static void MapHeaderEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/headers/missing", static () =>
            TypedResults.Content(PlainHtml("No security headers are set on this response."), "text/html; charset=utf-8"));

        endpoints.MapGet("/headers/good", static (HttpResponse response) =>
        {
            LabSecurityHeaders.ApplyGoodSet(response);
            return TypedResults.Content(PlainHtml("Every good security header is set on this response."), "text/html; charset=utf-8");
        });
    }

    private static string PlainHtml(string bodyText) => $"""
        <!doctype html>
        <html lang="en">
          <head><meta charset="utf-8"><title>Header fixture</title></head>
          <body>
            <h1>{bodyText}</h1>
          </body>
        </html>
        """;
}
