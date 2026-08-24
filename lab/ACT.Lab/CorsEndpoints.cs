namespace ACT.Lab;

/// <summary>CORS contrast fixtures: dangerous origin-reflection-with-credentials versus strict own-origin.</summary>
public static class CorsEndpoints
{
    /// <summary>Maps /cors/open and /cors/strict.</summary>
    public static void MapCorsEndpoints(this IEndpointRouteBuilder endpoints, LabRunOptions options)
    {
        endpoints.MapMethods(
            "/cors/open",
            [HttpMethods.Get, HttpMethods.Options],
            static IResult (HttpRequest request, HttpResponse response) =>
            {
                var origin = request.Headers.Origin.ToString();

                // Fixture: reflecting ANY origin verbatim while allowing credentials is the dangerous combo.
                if (origin.Length > 0)
                {
                    response.Headers.AccessControlAllowOrigin = origin;
                }
                else if (HttpMethods.IsOptions(request.Method))
                {
                    response.Headers.AccessControlAllowOrigin = "*";
                }

                response.Headers.AccessControlAllowCredentials = "true";
                if (HttpMethods.IsOptions(request.Method))
                {
                    response.Headers.AccessControlAllowMethods = request.Headers.AccessControlRequestMethod.Count > 0
                        ? request.Headers.AccessControlRequestMethod.ToString()
                        : "GET, POST, OPTIONS";
                    response.Headers.AccessControlAllowHeaders = request.Headers.AccessControlRequestHeaders.Count > 0
                        ? request.Headers.AccessControlRequestHeaders.ToString()
                        : "*";
                    return TypedResults.NoContent();
                }

                response.Headers.Vary = "Origin";
                return TypedResults.Json(new { reflectedOrigin = origin, allowCredentials = true });
            });

        endpoints.MapGet("/cors/strict", (HttpRequest request, HttpResponse response) =>
        {
            var origin = request.Headers.Origin.ToString();
            var isOwnOrigin = options.OwnOrigins().Contains(origin, StringComparer.OrdinalIgnoreCase);
            if (isOwnOrigin)
            {
                response.Headers.AccessControlAllowOrigin = origin;
            }

            // Without a matching own origin, no Access-Control-Allow-Origin is emitted at all.
            return TypedResults.Json(new { origin, allowed = isOwnOrigin });
        });
    }
}
