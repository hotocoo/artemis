namespace ACT.I18n;

public static class ResourceCulture
{
    private static readonly AsyncLocal<string?> Current = new();

    public static string? CurrentCulture => Current.Value;

    public static void Set(string culture)
    {
        Current.Value = culture;
    }

    public static void Clear()
    {
        Current.Value = null;
    }
}
