
using ACT.Contracts;
using Microsoft.Extensions.DependencyInjection;

namespace ACT.Cli;

/// <summary>Static metadata about the product used across output surfaces.</summary>
public static class CommandMetadata
{
    public const string ProductName = "Artemis";
    public const string Version = "1.0.0";
    public static string VersionLine => $"{ProductName} {Version} - autonomous defensive security assessment";
}

public delegate Task<int> CommandHandler(IServiceProvider services, string[] args);

/// <summary>Registry of implemented commands. Commands appear here only once fully functional.</summary>
public static class CommandRegistry
{
    private static readonly Dictionary<string, CommandHandler> Commands = new(StringComparer.Ordinal);

    static CommandRegistry()
    {
        Register("config", ConfigCommand.Run);
        Register("scope", ScopeCommand.Run);
        Register("doctor", DoctorCommand.Run);
        Register("assessment", AssessmentCommands.Run);
        Register("check", CheckCommand.Run);
        Register("finding", FindingCommands.Run);
        Register("report", ReportCommands.Run);
        Register("regression", RegressionCommands.Run);
        Register("feed", FeedCommands.Run);
        Register("schedule", ScheduleCommands.Run);
        Register("retention", RetentionCommands.Run);
    }

    public static void Register(string name, CommandHandler handler) => Commands[name] = handler;

    public static bool TryGet(string name, out CommandHandler handler) => Commands.TryGetValue(name, out handler!);

    public static IReadOnlyList<string> Names => [.. Commands.Keys.OrderBy(n => n, StringComparer.Ordinal)];
}

public static class HelpPrinter
{
    public static void Print()
    {
        Console.WriteLine(CommandMetadata.VersionLine);
        Console.WriteLine();
        Console.WriteLine("USAGE: artemis <command> [arguments] [--json] [--quiet] [--verbose] [--output PATH]");
        Console.WriteLine("                         [--timeout SECONDS] [--max-concurrency N] [--config FILE]");
        Console.WriteLine();
        Console.WriteLine("COMMANDS");
        foreach (var name in CommandRegistry.Names)
        {
            Console.WriteLine("  " + name.PadRight(14) + Describe(name));
        }
    }

    private static string Describe(string name) => name switch
    {
        "config" => "show the effective, redacted configuration",
        "scope" => "validate and list assessment scopes",
        "doctor" => "environment health: db, audit chain, feeds, filesystem, network",
        "assessment" => "create, start, status, emergency stop and disarm assessments",
        "check" => "list built-in security checks",
        "finding" => "list, show, and triage stored findings",
        "report" => "generate JSON/CSV/Markdown/HTML/SARIF reports",
        "regression" => "replay machine-executable regression tests",
        "feed" => "refresh advisory feed state (stale data is labeled)",
        "schedule" => "list, add, enable, disable schedules and run due ticks",
        "retention" => "preview and sweep evidence past scope-configured retention windows",
        _ => ""
    };
}

public static class OutputWriter
{
    /// <summary>Writes either human text or JSON depending on global flags; honors --output.</summary>
    public static async Task<int> WriteAsync(IServiceProvider services, string humanText, string jsonText)
    {
        var globals = services.GetRequiredService<GlobalOptions>();
        var payload = globals.Json ? jsonText : humanText;

        if (!string.IsNullOrWhiteSpace(globals.OutputPath))
        {
            await File.WriteAllTextAsync(globals.OutputPath, payload);
            if (!globals.Quiet)
            {
                Console.WriteLine(payload);
                Console.Error.WriteLine($"written: {globals.OutputPath}");
            }
        }
        else if (!globals.Quiet || globals.Json)
        {
            Console.WriteLine(payload);
        }
        return ExitCodes.Ok;
    }
}
