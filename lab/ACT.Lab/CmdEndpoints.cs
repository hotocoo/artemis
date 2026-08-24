namespace ACT.Lab;

/// <summary>Command-injection probe fixture: detects metacharacters, never executes anything.</summary>
public static class CmdEndpoints
{
    /// <summary>Maps GET /cmd/ping?h=host.</summary>
    public static void MapCommandEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/cmd/ping", static (HttpContext context, string? h) =>
        {
            var host = h ?? string.Empty;
            if (LabShellMetaDetector.ContainsShellMetacharacter(host))
            {
                context.Response.Headers[LabConstants.CommandMetaDetectedHeader] = "true";
                return TypedResults.Text("shell-metacharacters-rejected", statusCode: StatusCodes.Status400BadRequest);
            }

            return TypedResults.Text("would-ping-not-executed");
        });
    }
}
