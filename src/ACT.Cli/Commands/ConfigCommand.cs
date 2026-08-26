
using System.Text.Json;
using ACT.Contracts;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace ACT.Cli;

/// <summary>artemis config show - renders the effective configuration, secrets-free by construction.</summary>
public static class ConfigCommand
{
    public static async Task<int> Run(IServiceProvider services, string[] args)
    {
        if (args.Length == 0 || args[0] != "show")
        {
            Console.Error.WriteLine("usage: artemis config show [--json]");
            return ExitCodes.UsageError;
        }

        var configuration = services.GetRequiredService<IConfiguration>();
        var options = new ActOptions();
        configuration.GetSection(ActOptions.SectionName).Bind(options);
        options.Validate(EngineDefaults.Conservative);

        return await OutputWriter.WriteAsync(services,
            ArtemisConfiguration.RenderSafe(options),
            ArtemisConfiguration.RenderSafe(options));
    }
}

/// <summary>artemis scope validate|list.</summary>
public static class ScopeCommand
{
    public static async Task<int> Run(IServiceProvider services, string[] args)
    {
        if (args.Length >= 1 && args[0] == "validate")
        {
            return Validate(services, args.Skip(1).ToArray());
        }
        if (args.Length >= 1 && args[0] == "list")
        {
            return List(services);
        }
        Console.Error.WriteLine("usage: artemis scope validate --file SCOPE.json | artemis scope list");
        return ExitCodes.UsageError;
    }

    private static int Validate(IServiceProvider services, string[] args)
    {
        var fileFlag = Array.FindIndex(args, a => a == "--file" || a == "-f");
        if (fileFlag < 0 || fileFlag + 1 >= args.Length)
        {
            Console.Error.WriteLine("error: scope validate requires --file SCOPE.json");
            return ExitCodes.UsageError;
        }
        var path = args[fileFlag + 1];
        if (!File.Exists(path))
        {
            Console.Error.WriteLine("error: scope file not found: " + path);
            return ExitCodes.UsageError;
        }

        ScopeDefinition scope;
        try
        {
            scope = ScopeFile.Load(path);
        }
        catch (ActException ex) when (ex.Category == ErrorCategory.Parser)
        {
            Console.Error.WriteLine("error: " + ex.SafeMessage);
            return ExitCodes.UsageError;
        }

        // Structural validation (throws fail-closed with precise diagnostics).
        scope.Validate();

        // Compilation proves every entry parses unambiguously before anything may run.
        var compiled = new ACT.Scope.CompiledScope(scope);

        var summary = new
        {
            scopeId = scope.ScopeId,
            assessmentId = scope.AssessmentId,
            targetType = scope.TargetType.ToString(),
            allowlistEntries = scope.AllowlistedTargets.Count,
            excludedTargets = scope.ExcludedTargets.Count,
            compiledAllowMatchers = compiled.AllowMatchers.Count,
            permittedPorts = string.Join(",", scope.PermittedPorts.Select(p => p.ToString())),
            permittedProtocols = string.Join(",", scope.PermittedProtocols),
            rateLimitPerSecond = scope.RequestsPerSecond,
            concurrencyLimit = scope.ConcurrencyLimit,
            maxRequests = scope.MaxRequests,
            maxRuntimeMinutes = scope.MaxRuntime.TotalMinutes,
            emergencyStopEnabled = scope.EmergencyStopEnabled,
            verdict = "VALID"
        };
        return OutputWriter.WriteAsync(services,
            System.Text.Json.JsonSerializer.Serialize(summary, new System.Text.Json.JsonSerializerOptions { WriteIndented = true }).Replace("{", "").Replace("}", "").Trim(),
            System.Text.Json.JsonSerializer.Serialize(summary)).GetAwaiter().GetResult();
    }

    private static int List(IServiceProvider services)
    {
        // Scopes are persisted with their assessments; until a database exists this lists nothing.
        var dbPath = ResolveDatabasePath(services);
        if (!File.Exists(dbPath))
        {
            return OutputWriter.WriteAsync(services, "no assessments stored yet", """{"scopes":[]}""").GetAwaiter().GetResult();
        }
        return OutputWriter.WriteAsync(services, "scope listing available after first assessment", """{"scopes":[]}""").GetAwaiter().GetResult();
    }

    internal static string ResolveDatabasePath(IServiceProvider services)
    {
        // One database-location rule shared with composition, doctor, and the console host.
        return Composition.ArtemisComposition.ResolveDatabasePath(services.GetRequiredService<IConfiguration>());
    }
}

/// <summary>Loads and parses operator-authored scope files. Parsing failures are Parser errors.</summary>
public static class ScopeFile
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        AllowTrailingCommas = false
    };

    public static ScopeDefinition Load(string path)
    {
        string json;
        try
        {
            json = File.ReadAllText(path);
        }
        catch (Exception ex)
        {
            throw ActException.FailClosed(ErrorCategory.Parser,
                "The scope file could not be read.",
                $"Read failure on '{path}': {ex.Message}", ex);
        }

        try
        {
            var dto = JsonSerializer.Deserialize<ScopeDto>(json, JsonOptions)
                ?? throw new JsonException("Scope document is empty.");

            return new ScopeDefinition(
                ParseGuid(dto.ScopeId, "scopeId"),
                ParseGuid(dto.AssessmentId, "assessmentId"),
                Require(dto.OperatorIdentity, "operatorIdentity"),
                Require(dto.Organization, "organization"),
                ParseEnum<TargetTypeKind>(dto.TargetType, "targetType"),
                dto.AllowlistedTargets ?? [],
                dto.ExcludedTargets ?? [],
                (dto.PermittedProtocols ?? []).Select(p => ParseEnum<ProtocolKind>(p, "permittedProtocols")).ToList(),
                ParsePorts(dto.PermittedPorts),
                dto.RequestsPerSecond is > 0 ? dto.RequestsPerSecond.Value : throw Fail("requestsPerSecond must be positive."),
                dto.ConcurrencyLimit is > 0 ? dto.ConcurrencyLimit.Value : throw Fail("concurrencyLimit must be positive."),
                TimeSpan.FromSeconds(dto.MaxRuntimeSeconds ?? 0),
                dto.MaxRequests ?? 0,
                (dto.AllowedCategories ?? ["Network", "Tls", "Http", "Api", "Authorization", "Source", "Dependency", "Configuration"])
                    .Select(c => ParseEnum<CheckCategory>(c, "allowedCategories")).ToList(),
                (dto.ProhibitedCategories ?? []).Select(c => ParseEnum<CheckCategory>(c, "prohibitedCategories")).ToList(),
                dto.EmergencyStopEnabled ?? true,
                TimeSpan.FromDays(dto.EvidenceRetentionDays ?? 30),
                dto.RedactionPolicy is null ? RedactionPolicy.Standard : ParseEnum<RedactionPolicy>(dto.RedactionPolicy, "redactionPolicy"),
                Require(dto.AuthorizationStatement, "authorizationStatement"));
        }
        catch (JsonException ex)
        {
            throw ActException.FailClosed(ErrorCategory.Parser,
                "The scope file is not valid JSON for an Artemis scope.",
                $"JSON parse error in '{path}': {ex.Message}", ex);
        }
        catch (ActException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw ActException.FailClosed(ErrorCategory.Parser,
                "The scope file could not be interpreted.",
                $"Unexpected parse failure in '{path}': {ex.Message}", ex);
        }
    }

    private sealed record ScopeDto(
        string? ScopeId,
        string? AssessmentId,
        string? OperatorIdentity,
        string? Organization,
        string? TargetType,
        IReadOnlyList<string>? AllowlistedTargets,
        IReadOnlyList<string>? ExcludedTargets,
        IReadOnlyList<string>? PermittedProtocols,
        IReadOnlyList<string>? PermittedPorts,
        double? RequestsPerSecond,
        int? ConcurrencyLimit,
        int? MaxRuntimeSeconds,
        long? MaxRequests,
        IReadOnlyList<string>? AllowedCategories,
        IReadOnlyList<string>? ProhibitedCategories,
        bool? EmergencyStopEnabled,
        int? EvidenceRetentionDays,
        string? RedactionPolicy,
        string? AuthorizationStatement);

    private static Guid ParseGuid(string? value, string field) =>
        Guid.TryParse(value, out var guid) && guid != Guid.Empty
            ? guid
            : throw Fail($"Field '{field}' must be a non-empty GUID.");

    private static T ParseEnum<T>(string? value, string field) where T : struct, Enum
    {
        if (!string.IsNullOrWhiteSpace(value) && Enum.TryParse<T>(value, true, out var parsed))
        {
            return parsed;
        }
        throw Fail($"Field '{field}' has unrecognized value '{value}'.");
    }

    private static IReadOnlyList<PortRange> ParsePorts(IReadOnlyList<string>? ports)
    {
        var ranges = new List<PortRange>();
        foreach (var spec in ports ?? [])
        {
            var dash = spec.IndexOf('-');
            if (dash > 0 &&
                int.TryParse(spec[..dash], out var lo) && int.TryParse(spec[(dash + 1)..], out var hi))
            {
                ranges.Add(new PortRange(lo, hi));
            }
            else if (int.TryParse(spec, out var single))
            {
                ranges.Add(PortRange.Single(single));
            }
            else
            {
                throw Fail($"Permitted port entry '{spec}' is not a port or range.");
            }
        }
        return ranges;
    }

    private static string Require(string? value, string field) =>
        string.IsNullOrWhiteSpace(value) ? throw Fail($"Field '{field}' is required.") : value.Trim();

    private static ActException Fail(string detail) =>
        ActException.FailClosed(ErrorCategory.Parser, "The scope file contains invalid values.", detail);
}
