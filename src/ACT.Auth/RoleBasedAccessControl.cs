namespace ACT.Auth;

public enum Role
{
    Admin,
    Operator,
    Viewer
}

public record Permission(
    string Resource,
    string Action);

public static class RolePermissions
{
    public static IReadOnlyList<Permission> GetPermissionsForRole(Role role)
    {
        return role switch
        {
            Role.Admin => new List<Permission>
            {
                new("assessments", "create"),
                new("assessments", "read"),
                new("assessments", "update"),
                new("assessments", "delete"),
                new("findings", "read"),
                new("findings", "update"),
                new("findings", "delete"),
                new("reports", "create"),
                new("reports", "read"),
                new("reports", "export"),
                new("config", "read"),
                new("config", "update"),
                new("users", "read"),
                new("users", "create"),
                new("users", "update"),
                new("users", "delete"),
            },
            Role.Operator => new List<Permission>
            {
                new("assessments", "create"),
                new("assessments", "read"),
                new("findings", "read"),
                new("findings", "update"),
                new("reports", "create"),
                new("reports", "read"),
                new("reports", "export"),
                new("config", "read"),
            },
            Role.Viewer => new List<Permission>
            {
                new("assessments", "read"),
                new("findings", "read"),
                new("reports", "read"),
                new("config", "read"),
            },
            _ => Array.Empty<Permission>()
        };
    }

    public static bool HasPermission(Role role, string resource, string action)
    {
        var permissions = GetPermissionsForRole(role);
        return permissions.Any(p => p.Resource == resource && p.Action == action);
    }
}
