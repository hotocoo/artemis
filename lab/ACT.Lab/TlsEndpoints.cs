namespace ACT.Lab;

/// <summary>TLS listener identification fixtures served over both HTTPS ports.</summary>
public static class TlsEndpoints
{
    /// <summary>Maps /tls/modern and /tls/expired.</summary>
    public static void MapTlsEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/tls/modern", static (HttpResponse response) =>
        {
            LabSecurityHeaders.ApplyGoodSet(response);
            return TypedResults.Json(new
            {
                tls = "modern",
                certificate = "self-signed CN=artemis-lab-selfsigned, valid for one year",
            });
        });

        endpoints.MapGet("/tls/expired", static () => TypedResults.Json(new
        {
            tls = "expired",
            certificate = "self-signed CN=artemis-lab-selfsigned, expired thirty days ago",
        }));
    }
}
