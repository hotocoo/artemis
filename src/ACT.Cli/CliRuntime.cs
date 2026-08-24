
using System.Text.Json;
using ACT.Contracts;
using ACT.Core;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace ACT.Cli;

/// <summary>Scriptable exit codes consumed by CI pipelines.</summary>
public static class ExitCodes
{
    public const int Ok = 0;
    public const int UsageError = 2;
    public const int ScopeDenied = 3;
    public const int RuntimeFailure = 4;
    public const int GateFailed = 5;
}

/// <summary>Parsed global options shared by every command.</summary>
public sealed class GlobalOptions
{
    public bool Json { get; init; }
    public bool Quiet { get; init; }
    public bool Verbose { get; init; }
    public string? OutputPath { get; init; }
    public int? TimeoutSeconds { get; init; }
    public int? MaxConcurrency { get; init; }
    public string? ConfigFile { get; init; }

    public static GlobalOptions Parse(string[] args, out string[] remaining)
    {
        var options = new Dictionary<string, string?>();
        var rest = new List<string>();
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--json": options["json"] = "true"; break;
                case "--quiet" or "-q": options["quiet"] = "true"; break;
                case "--verbose": options["verbose"] = "true"; break;
                case "--output":
                    RequireValue(args, ref i, "--output");
                    options["output"] = args[i];
                    break;
                case "--timeout":
                    RequireValue(args, ref i, "--timeout");
                    options["timeout"] = args[i];
                    break;
                case "--max-concurrency":
                    RequireValue(args, ref i, "--max-concurrency");
                    options["concurrency"] = args[i];
                    break;
                case "--config":
                    RequireValue(args, ref i, "--config");
                    options["config"] = args[i];
                    break;
                default:
                    rest.Add(args[i]);
                    break;
            }
        }
        remaining = [.. rest];

        return new GlobalOptions
        {
            Json = options.ContainsKey("json"),
            Quiet = options.ContainsKey("quiet"),
            Verbose = options.ContainsKey("verbose"),
            OutputPath = options.GetValueOrDefault("output"),
            ConfigFile = options.GetValueOrDefault("config"),
            TimeoutSeconds = ParsePositiveInt(options.GetValueOrDefault("timeout"), "--timeout"),
            MaxConcurrency = ParsePositiveInt(options.GetValueOrDefault("concurrency"), "--max-concurrency"),
        };
    }

    private static int? ParsePositiveInt(string? raw, string flag)
    {
        if (raw is null) return null;
        if (!int.TryParse(raw, out var value) || value <= 0)
        {
            throw new ActException(ErrorCategory.Configuration,
                $"The {flag} value must be a positive integer.",
                $"Unparseable {flag} '{raw}'.");
        }
        return value;
    }

    private static void RequireValue(string[] args, ref int index, string flag)
    {
        if (index + 1 >= args.Length)
        {
            throw new ActException(ErrorCategory.Configuration,
                $"The flag {flag} requires a value.",
                $"{flag} at position {index} had no value.");
        }
        index++;
    }
}

/// <summary>
/// Deterministic configuration precedence: engine defaults <- config file <- environment
/// (prefix ARTM_) <- explicit CLI flags. The effective tree is validated fail-closed.
/// </summary>
public static class ArtemisConfiguration
{
    public const string EnvironmentPrefix = "ARTM_";

    public static IConfigurationRoot Build(GlobalOptions options, out ActOptions actOptions)
    {
        var builder = new ConfigurationBuilder();

        // 1. Defaults live in code via ActOptions property initializers; nothing to bind yet.
        var fileCandidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(options.ConfigFile))
        {
            fileCandidates.Add(options.ConfigFile);
        }
        else
        {
            fileCandidates.Add(Path.Combine(AppContext.BaseDirectory, "artemis.config.json"));
            fileCandidates.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "artemis", "artemis.config.json"));
            fileCandidates.Add("artemis.config.json");
        }
        var existingFile = fileCandidates.FirstOrDefault(File.Exists);
        if (existingFile is not null)
        {
            builder.AddJsonFile(existingFile, optional: false, reloadOnChange: false);
        }

        builder.AddEnvironmentVariables(EnvironmentPrefix);

        var overrides = new Dictionary<string, string?>();
        if (options.MaxConcurrency is { } c) overrides["Act:Limits:MaxConcurrency"] = c.ToString();
        if (options.TimeoutSeconds is { } t) overrides["Act:Limits:PerOperationTimeoutSeconds"] = t.ToString();
        if (overrides.Count > 0) builder.AddInMemoryCollection(overrides);

        var configuration = builder.Build();
        actOptions = new ActOptions();
        configuration.GetSection(ActOptions.SectionName).Bind(actOptions);

        try
        {
            actOptions.Validate(ContractsDefaults.Engine);
        }
        catch (ActException ex)
        {
            throw new ActException(ex.Category, ex.SafeMessage, ex.DiagnosticDetail + " Source: " +
                (existingFile ?? "environment or flags"), ex);
        }
        return configuration;
    }

    /// <summary>Effective configuration rendered as JSON with zero secret material by construction.</summary>
    public static string RenderSafe(ActOptions options)
    {
        // The options tree intentionally never contains secret VALUES (only env-var NAMES), so a
        // plain serialization is safe; this method exists as the single sanctioned rendering path.
        return JsonSerializer.Serialize(options, new JsonSerializerOptions
        {
            WriteIndented = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
    }
}

internal static class ContractsDefaults
{
    public static EngineDefaults Engine => EngineDefaults.Conservative;
}

/// <summary>Builds the service provider for command execution.</summary>
public static class ArtemisHostFactory
{
    public static ServiceCollection BuildServices(IConfiguration configuration, GlobalOptions globals)
    {
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(configuration);
        services.Configure<ActOptions>(configuration.GetSection(ActOptions.SectionName));
        services.AddSingleton(globals);
        services.AddArtemisCore();

        services.AddLogging(logging =>
        {
            logging.SetMinimumLevel(globals.Verbose ? LogLevel.Debug : LogLevel.Warning);
            logging.AddSimpleConsole(console =>
            {
                console.SingleLine = true;
                console.TimestampFormat = "HH:mm:ss ";
            });
        });

        // Components with primary constructors (e.g. AssessmentEngine) request the non-generic
        // ILogger, which AddLogging does not register by itself. Alias it through the factory so
        // every consumer shares one configured pipeline instead of failing activation.
        services.AddSingleton<ILogger>(sp =>
            sp.GetRequiredService<ILoggerFactory>().CreateLogger("Artemis"));

        return services;
    }
}
