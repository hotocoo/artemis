namespace ACT.I18n;

public class TranslationService
{
    private readonly Dictionary<string, Dictionary<string, string>> _translations = new();

    public void LoadTranslations(string culture, Dictionary<string, string> translations)
    {
        _translations[culture] = translations;
    }

    public string Translate(string culture, string key, params object[] args)
    {
        if (_translations.TryGetValue(culture, out var dict) && dict.TryGetValue(key, out var value))
        {
            return string.Format(value, args);
        }

        // Fall back to key
        return key;
    }

    public string[] GetSupportedCultures()
    {
        return _translations.Keys.ToArray();
    }
}
