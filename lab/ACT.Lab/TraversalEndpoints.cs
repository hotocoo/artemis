namespace ACT.Lab;

/// <summary>Path-traversal fixture: reads inside the sandbox root, answers a marked 500 when containment breaks.</summary>
public static class TraversalEndpoints
{
    /// <summary>Maps GET /traversal/read?path=name.</summary>
    public static void MapTraversalEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/traversal/read", async (HttpContext context, CancellationToken cancellationToken) =>
        {
            var requested = context.Request.Query["path"].ToString();
            if (string.IsNullOrWhiteSpace(requested))
            {
                return TypedResults.BadRequest(new { error = "the path query parameter is required" });
            }

            var candidate = Path.Combine(LabData.DataRoot, requested);
            string resolved;
            try
            {
                resolved = Path.GetFullPath(candidate);
            }
            catch (Exception malformed) when (malformed is ArgumentException or NotSupportedException or PathTooLongException)
            {
                return Blocked(context);
            }

            if (!LabTraversalGuard.StaysInsideRoot(LabData.DataRoot, resolved))
            {
                return Blocked(context);
            }

            if (!File.Exists(resolved))
            {
                return TypedResults.NotFound();
            }

            return TypedResults.Text(await File.ReadAllTextAsync(resolved, cancellationToken));

            static IResult Blocked(HttpContext responding)
            {
                responding.Response.Headers[LabConstants.TraversalBlockedHeader] = "true";
                return TypedResults.Text("blocked", statusCode: StatusCodes.Status500InternalServerError);
            }
        });
    }
}
