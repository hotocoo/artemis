namespace ACT.Lab;

/// <summary>Outbound redirect fixture pointing at an unroutable documentation-address sink.</summary>
public static class RedirectEndpoints
{
    /// <summary>Maps /redirect/out.</summary>
    public static void MapRedirectEndpoints(this IEndpointRouteBuilder endpoints)
    {
        // Target is RFC 5737 TEST-NET-1 documentation space — unreachable by design, so following
        // the redirect can never contact a real host. Scanners should flag the unvalidated hop.
        endpoints.MapGet("/redirect/out", static () =>
            TypedResults.Redirect("http://192.0.2.111/outside", permanent: false, preserveMethod: false));
    }
}
