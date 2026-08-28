namespace ACT.Lab;

/// <summary>Operational surface: landing page, health probe, fixture catalog, pixel, and mixed content.</summary>
public static class SystemEndpoints
{
    private static readonly byte[] TransparentPixelGif =
    [
        0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0x21, 0xF9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2C, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3B,
    ];

    /// <summary>Maps the index, health, fixture-catalog, and pixel routes.</summary>
    public static void MapSystemEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/", static (HttpResponse response) =>
        {
            LabSecurityHeaders.ApplyGoodSet(response);
            return TypedResults.Content(LandingHtml(), "text/html; charset=utf-8");
        });

        endpoints.MapGet("/healthz", static (HttpResponse response) =>
        {
            LabSecurityHeaders.ApplyGoodSet(response);
            return TypedResults.Json(new { status = "ok", service = "artemis-test-lab" });
        });

        endpoints.MapGet("/fixtures", static (HttpResponse response) =>
        {
            LabSecurityHeaders.ApplyGoodSet(response);
            return TypedResults.Json(BuildCatalog());
        });

        endpoints.MapGet("/pixel.gif", static (HttpResponse response) =>
        {
            response.Headers.CacheControl = "no-store";
            return TypedResults.Bytes(TransparentPixelGif, "image/gif");
        });
    }

    /// <summary>Maps the deliberate mixed-active-content fixture; call only when HTTPS listeners exist.</summary>
    public static void MapMixedContentEndpoints(this IEndpointRouteBuilder endpoints, LabRunOptions options)
    {
        endpoints.MapGet("/mixedcontent", (HttpResponse response) =>
        {
            response.Headers.CacheControl = "no-store";
            var html = $"""
                <!doctype html>
                <html lang="en">
                  <head><meta charset="utf-8"><title>Mixed content fixture</title></head>
                  <body>
                    <h1>Mixed active content fixture</h1>
                    <!-- SYNTHETIC FIXTURE: insecure http:// subresource referenced from an https page -->
                    <img src="http://127.0.0.1:{options.HttpPort}/pixel.gif" alt="synthetic tracking pixel">
                  </body>
                </html>
                """;
            return TypedResults.Content(html, "text/html; charset=utf-8");
        });
    }

    private static string LandingHtml() => """
        <!doctype html>
        <html lang="en">
          <head><meta charset="utf-8"><title>Artemis Test Lab</title></head>
          <body>
            <h1>ARTEMIS TEST LAB</h1>
            <p>Deliberate vulnerabilities for scanner verification. LOOPBACK ONLY. NEVER EXPOSE.</p>
            <p><a href="/fixtures">Fixture catalog</a> &#183; <a href="/healthz">Health</a></p>
            <nav aria-label="Fixtures">
              <a href="/headers/missing">Missing headers</a> &#183;
              <a href="/cookies/bad">Insecure cookie</a> &#183;
              <a href="/cors/open">Open CORS</a> &#183;
              <a href="/redirect/out">Outbound redirect</a> &#183;
              <a href="/authz/items/alpha-1">Object authorization</a> &#183;
              <a href="/api/openapi.json">OpenAPI surface</a> &#183;
              <a href="/traversal/read">Path traversal</a> &#183;
              <a href="/sql/search">SQL data flow</a> &#183;
              <a href="/cmd/ping">Command injection</a> &#183;
              <a href="/secrets/page">Secret fixtures</a>
            </nav>
          </body>
        </html>
        """;

    private static object[] BuildCatalog() =>
    [
        CatalogEntry("GET", "/", "safe index with the complete good header set"),
        CatalogEntry("GET", "/healthz", "health probe with the complete good header set"),
        CatalogEntry("GET", "/headers/missing", "detect missing security headers"),
        CatalogEntry("GET", "/headers/good", "control: complete good security header set"),
        CatalogEntry("GET", "/cookies/bad", "detect session cookie without Secure/HttpOnly/SameSite"),
        CatalogEntry("GET", "/cookies/good", "control: hardened session cookie"),
        CatalogEntry("GET", "/cors/open", "detect CORS reflecting any origin together with credentials"),
        CatalogEntry("GET", "/cors/strict", "control: CORS restricted to the lab's own origin"),
        CatalogEntry("GET", "/redirect/out", "detect unvalidated outbound redirect to TEST-NET sink"),
        CatalogEntry("GET", "/authz/items/{id}", "detect broken object-level authorization (tenant header ignored)"),
        CatalogEntry("GET", "/authz-safe/items/{id}", "control: tenant ownership enforced, uniform 404 on mismatch"),
        CatalogEntry("GET", "/api/openapi.json", "declared safe surface; dangerous routes intentionally undocumented"),
        CatalogEntry("POST", "/api/jobs", "unauthenticated state-changing endpoint omitting security declarations"),
        CatalogEntry("GET", "/traversal/read", "detect path traversal; blocked attempts answer 500 with X-Lab-Traversal-Blocked"),
        CatalogEntry("GET", "/sql/search", "SQL-shaped string concatenation data flow (display string only, never executed)"),
        CatalogEntry("GET", "/sql/search-param", "control: parameterized-shaped lookup"),
        CatalogEntry("GET", "/cmd/ping", "detect command-injection probes via metacharacters; nothing is ever executed"),
        CatalogEntry("GET", "/secrets/page", "synthetic marked secret fixtures for secret-scanner verification"),
        CatalogEntry("GET", "/mixedcontent", "mixed active content (present only when HTTPS listeners are configured)"),
    ];

    private static object CatalogEntry(string method, string path, string detects) => new { method, path, detects };
}
