namespace ACT.Lab;

/// <summary>SQL-injection detection fixtures built on an in-memory matcher; no database engine is involved.</summary>
public static class SqlEndpoints
{
    /// <summary>Maps /sql/search (concatenation shape) and /sql/search-param (parameterized control).</summary>
    public static void MapSqlEndpoints(this IEndpointRouteBuilder endpoints)
    {
        // The built "query" below is a DISPLAY STRING assembled by naive concatenation so scanners
        // observe the vulnerable source-to-sink data-flow shape. Nothing parses or executes it; row
        // selection is an in-memory substring predicate over synthetic products (BCL only, and no
        // SQL engine is referenced anywhere in this lab).
        endpoints.MapGet("/sql/search", static (string? q) =>
        {
            var needle = q ?? string.Empty;
            var queryBuilt = $"SELECT sku, name FROM synthetic_products WHERE name LIKE '%{needle}%' ORDER BY sku;";
            return TypedResults.Json(new { queryBuilt, rows = MatchByName(needle) });
        });

        endpoints.MapGet("/sql/search-param", static (string? q) =>
            TypedResults.Json(new { parameterized = true, rows = MatchByName(q ?? string.Empty) }));
    }

    private static SyntheticProduct[] MatchByName(string needle) =>
        [.. LabData.Products.Where(product => product.Name.Contains(needle, StringComparison.OrdinalIgnoreCase))];
}
