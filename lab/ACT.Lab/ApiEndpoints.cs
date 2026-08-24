using System.Text.Json;

namespace ACT.Lab;

/// <summary>OpenAPI description, synthetic job submission, and the token-guarded administrative reset.</summary>
public static class ApiEndpoints
{
    /// <summary>Maps /api/openapi.json, POST /api/jobs, and POST /api/admin/reset.</summary>
    public static void MapApiEndpoints(this IEndpointRouteBuilder endpoints, LabRunOptions options)
    {
        endpoints.MapGet("/api/openapi.json", static () =>
            TypedResults.Content(LabApiDocuments.OpenApiJson, "application/json"));

        endpoints.MapPost("/api/jobs", async Task<IResult> (HttpRequest request, CancellationToken cancellationToken) =>
        {
            // Fixture: state-changing endpoint with NO authentication or security declaration whatsoever.
            JobSubmitRequest? body;
            try
            {
                body = await request.ReadFromJsonAsync<JobSubmitRequest>(cancellationToken);
            }
            catch (JsonException)
            {
                body = null;
            }

            if (body is null)
            {
                return TypedResults.BadRequest(new { error = "body must be JSON with a non-empty kind field" });
            }

            return TypedResults.Json(new { jobId = LabData.CreateJob(), status = "queued" }, statusCode: StatusCodes.Status202Accepted);
        });

        endpoints.MapPost("/api/admin/reset", IResult (HttpRequest request) =>
        {
            // Administrative endpoint: guarded by the lab token, absent from the OpenAPI document on purpose.
            if (!LabTokens.Matches(request.Headers[LabConstants.TokenHeader].ToString(), options.LabToken))
            {
                return TypedResults.Json(new { error = "forbidden" }, statusCode: StatusCodes.Status403Forbidden);
            }

            LabData.Reset();
            return TypedResults.Json(new { reset = true });
        });
    }

    private sealed record JobSubmitRequest(string Kind);
}
