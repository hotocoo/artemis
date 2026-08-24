namespace ACT.Lab;

/// <summary>Synthetic, clearly-marked secret fixtures for secret-scanner verification.</summary>
public static class SecretEndpoints
{
    private const string AwsExampleAccessKeyId = "AKIAIOSFODNN7EXAMPLE";
    private const string JwtNoneShape = "eyJhbGciOi.NONE.SYNTH";

    // Fabricated pattern token: prefix plus 36 alternating x/y characters — never a real credential.
    private static readonly string GithubPatShape = "ghp_" + new string('x', 18) + new string('y', 18);

    /// <summary>Maps GET /secrets/page.</summary>
    public static void MapSecretEndpoints(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet("/secrets/page", static () => TypedResults.Content(PageHtml(), "text/html; charset=utf-8"));
    }

    private static string PageHtml() => $"""
        <!doctype html>
        <html lang="en">
          <head><meta charset="utf-8"><title>Synthetic secret fixtures</title></head>
          <body>
            <h1>Synthetic secret fixtures</h1>
            <!-- SYNTHETIC TEST SECRET fixture=aws-access-key-id note=documentation example identifier, never a real credential -->
            <p data-fixture="aws-access-key-id">{AwsExampleAccessKeyId}</p>
            <!-- END SYNTHETIC TEST SECRET -->
            <!-- SYNTHETIC TEST SECRET fixture=github-pat-shape note=fabricated x/y pattern, never a real token -->
            <p data-fixture="github-pat-shape">{GithubPatShape}</p>
            <!-- END SYNTHETIC TEST SECRET -->
            <!-- SYNTHETIC TEST SECRET fixture=jwt-none-shape note=fabricated unsigned-token marker, carries no claims -->
            <p data-fixture="jwt-none-shape">{JwtNoneShape}</p>
            <!-- END SYNTHETIC TEST SECRET -->
          </body>
        </html>
        """;
}
