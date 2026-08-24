
namespace ACT.Contracts;

/// <summary>Which LLM provider style is active. Disabled is the default: core works offline.</summary>
public enum LlmProviderKind
{
    Disabled,
    /// <summary>Any OpenAI-compatible endpoint on localhost (Ollama, LM Studio, llama.cpp server).</summary>
    LocalOpenAiCompatible,
    /// <summary>Remote OpenAI-compatible endpoint explicitly configured by the operator.</summary>
    OpenAiCompatible
}

/// <summary>Where advisory metadata comes from. No feed provider is hardcoded into behavior.</summary>
public enum AdvisoryFeedKind
{
    /// <summary>OSV.dev batch/query API.</summary>
    Osv,

    /// <summary>A local JSON advisory snapshot file (offline mode, deterministic tests).</summary>
    OfflineFile,

    /// <summary>NVD-style CVE API endpoint.</summary>
    NvdApi
}

/// <summary>Root of the strongly typed configuration tree. Bindable from file/env/CLI.</summary>
public sealed class ActOptions
{
    public const string SectionName = "Act";

    public EngineLimits Limits { get; set; } = new();
    public StorageOptions Storage { get; set; } = new();
    public FeedOptions Feeds { get; set; } = new();
    public LlmOptions Llm { get; set; } = new();
    public RedactionOptions Redaction { get; set; } = new();
    public UiOptions Ui { get; set; } = new();

    /// <summary>Fails closed when the effective configuration violates safety invariants.</summary>
    public void Validate(EngineDefaults defaults)
    {
        var problems = new List<string>();
        if (Limits.MaxConcurrency <= 0 || Limits.MaxConcurrency > defaults.MaxConcurrency)
            problems.Add($"Limits.MaxConcurrency must be in 1..{defaults.MaxConcurrency}.");
        if (Limits.MaxRequestsPerAssessment <= 0 || Limits.MaxRequestsPerAssessment > defaults.MaxRequestsPerAssessment)
            problems.Add($"Limits.MaxRequestsPerAssessment must be in 1..{defaults.MaxRequestsPerAssessment}.");
        if (Limits.MaxResponseBytes <= 0 || Limits.MaxResponseBytes > defaults.MaxResponseBytes)
            problems.Add("Limits.MaxResponseBytes exceeds the engine hard cap.");
        if (Storage.RetentionDays <= 0) problems.Add("Storage.RetentionDays must be positive.");
        if (Llm.ProviderKind != LlmProviderKind.Disabled && string.IsNullOrWhiteSpace(Llm.Endpoint))
            problems.Add("Llm.Endpoint required when a provider is enabled.");
        if (problems.Count > 0)
        {
            throw ActException.FailClosed(ErrorCategory.Configuration,
                "The effective configuration is invalid.",
                "Configuration validation failed: " + string.Join(" | ", problems));
        }
    }
}

/// <summary>Operator-adjustable engine limits. Hard caps live in EngineDefaults and cannot be raised by configuration.</summary>
public sealed class EngineLimits
{
    public int MaxConcurrency { get; set; } = 4;
    public long MaxRequestsPerAssessment { get; set; } = 2_000;
    public long MaxResponseBytes { get; set; } = 2 * 1024 * 1024;
    public long MaxBodyBytes { get; set; } = 1024 * 1024;
    public long MaxFileBytes { get; set; } = 10 * 1024 * 1024;
    public long MemoryBudgetBytes { get; set; } = 512L * 1024 * 1024;
    public int PerOperationTimeoutSeconds { get; set; } = 15;
    public int MaxConnectionsPerHost { get; set; } = 4;
    public int MaxRedirects { get; set; } = 5;

    public EngineDefaults ToDefaults() => new(
        MaxConcurrency, MaxRequestsPerAssessment, MaxResponseBytes, MaxBodyBytes, MaxFileBytes,
        MemoryBudgetBytes, TimeSpan.FromSeconds(PerOperationTimeoutSeconds), MaxConnectionsPerHost, MaxRedirects);
}

public sealed class StorageOptions
{
    /// <summary>Path to the SQLite database file. Relative paths resolve under the product data directory.</summary>
    public string DatabasePath { get; set; } = "act.db";
    public int RetentionDays { get; set; } = 90;
    public bool WalEnabled { get; set; } = true;
}

public sealed class RedactionOptions
{
    public RedactionPolicy Level { get; set; } = RedactionPolicy.Standard;
    /// <summary>Extra value patterns treated as secrets, applied verbatim by the redactor.</summary>
    public List<string> AdditionalSecretPatterns { get; set; } = [];
}

public sealed class FeedOptions
{
    public List<FeedSourceDescriptor> Sources { get; set; } =
    [
        new FeedSourceDescriptor
        {
            Name = "osv",
            Kind = AdvisoryFeedKind.Osv,
            EndpointOrPath = "https://api.osv.dev/v1/querybatch",
            Enabled = false
        }
    ];
    public string CachePath { get; set; } = "feeds-cache";
    public int StaleAfterDays { get; set; } = 7;
}

public sealed class FeedSourceDescriptor
{
    public string Name { get; set; } = "";
    public AdvisoryFeedKind Kind { get; set; }
    public string EndpointOrPath { get; set; } = "";
    public bool Enabled { get; set; }
    /// <summary>Optional expected SHA-256 of an OfflineFile source; mismatch fails closed.</summary>
    public string? Sha256 { get; set; }
}

public sealed class LlmOptions
{
    public LlmProviderKind ProviderKind { get; set; } = LlmProviderKind.Disabled;
    public string? Endpoint { get; set; }
    public string Model { get; set; } = "";
    /// <summary>Name of the environment variable holding the API key. The key itself is never configured here.</summary>
    public string? ApiKeyEnvironmentVariable { get; set; }
    public int TimeoutSeconds { get; set; } = 60;
    public int MaxOutputTokens { get; set; } = 2048;
}

public sealed class UiOptions
{
    /// <summary>Loopback port for the operator console. Always bound to 127.0.0.1.</summary>
    public int ConsolePort { get; set; } = 47320;
    public bool OpenBrowserOnStart { get; set; } = true;
}
