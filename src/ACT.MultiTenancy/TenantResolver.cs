using System.Net.Http.Headers;

namespace ACT.MultiTenancy;

public interface ITenantResolver
{
    Task<TenantInfo?> ResolveAsync(string? tenantHeader, string? path, CancellationToken cancellationToken);
}

public class HeaderTenantResolver : ITenantResolver
{
    private readonly Dictionary<string, TenantInfo> _tenants;

    public HeaderTenantResolver(IEnumerable<TenantInfo> tenants)
    {
        _tenants = tenants.ToDictionary(t => t.TenantId, StringComparer.OrdinalIgnoreCase);
    }

    public Task<TenantInfo?> ResolveAsync(string? tenantHeader, string? path, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(tenantHeader))
        {
            return Task.FromResult<TenantInfo?>(null);
        }

        if (_tenants.TryGetValue(tenantHeader, out var tenant))
        {
            return Task.FromResult<TenantInfo?>(tenant);
        }

        return Task.FromResult<TenantInfo?>(null);
    }
}
