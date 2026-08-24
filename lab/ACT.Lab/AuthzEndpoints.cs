namespace ACT.Lab;

/// <summary>Broken-object-authorization fixture and its enforced safe twin.</summary>
public static class AuthzEndpoints
{
    /// <summary>Maps /authz/items/{id} (broken) and /authz-safe/items/{id} (enforced).</summary>
    public static void MapAuthorizationEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/authz/items/{id}", static IResult (string id) =>
        {
            // Fixture: the X-Tenant header is deliberately ignored, so any caller reads any tenant's item.
            return LabData.TryGetItemOwner(id, out var owner)
                ? TypedResults.Json(new { id, ownerTenant = owner, payload = "SYNTHETIC-item-payload" })
                : TypedResults.NotFound();
        });

        endpoints.MapGet("/authz-safe/items/{id}", static IResult (string id, HttpRequest request) =>
        {
            if (!LabData.TryGetItemOwner(id, out var owner))
            {
                return TypedResults.NotFound();
            }

            var callerTenant = request.Headers["X-Tenant"].ToString();
            return string.Equals(callerTenant, owner, StringComparison.Ordinal)
                ? TypedResults.Json(new { id, ownerTenant = owner, payload = "SYNTHETIC-item-payload" })
                : TypedResults.NotFound(); // Uniform 404 so item existence is never leaked.
        });
    }
}
