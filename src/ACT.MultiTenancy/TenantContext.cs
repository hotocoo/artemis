namespace ACT.MultiTenancy;

public class TenantContext
{
    private static readonly AsyncLocal<TenantInfo?> Current = new();

    public static TenantInfo? CurrentTenant => Current.Value;

    public static void Set(TenantInfo tenant)
    {
        Current.Value = tenant;
    }

    public static void Clear()
    {
        Current.Value = null;
    }
}

public record TenantInfo(
    string TenantId,
    string Name,
    string? DatabaseConnectionString,
    Dictionary<string, string> Metadata);
