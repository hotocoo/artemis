
using ACT.Cli;
using ACT.Cli.Composition;
using ACT.Contracts;
using Microsoft.Extensions.DependencyInjection;

var rawArgs = args.Length > 0 ? args : ["help"];
GlobalOptions globals;
try
{
    globals = GlobalOptions.Parse(rawArgs, out var remaining);
    rawArgs = remaining;
}
catch (ActException ex)
{
    Console.Error.WriteLine("error: " + ex.SafeMessage);
    return ExitCodes.UsageError;
}

if (rawArgs.Length == 0 || rawArgs[0] is "help" or "--help" or "-h")
{
    HelpPrinter.Print();
    return ExitCodes.Ok;
}

if (rawArgs[0] is "version")
{
    Console.WriteLine(CommandMetadata.VersionLine);
    return ExitCodes.Ok;
}

try
{
    var configuration = ArtemisConfiguration.Build(globals, out _);
    var services = ArtemisHostFactory.BuildServices(configuration, globals);
    services.AddArtemisPersistence();
    services.AddArtemisPolicy();
    services.AddArtemisRisk();
    await using var provider = services.BuildServiceProvider();

    if (!CommandRegistry.TryGet(rawArgs[0], out var handler))
    {
        Console.Error.WriteLine("error: unknown command '" + rawArgs[0] + "'. Run 'artemis help'.");
        return ExitCodes.UsageError;
    }

    return await handler(provider, rawArgs.Skip(1).ToArray());
}
catch (ActException ex)
{
    Console.Error.WriteLine("error (" + ex.Category.ToString().ToLowerInvariant() + "): " + ex.SafeMessage);
    if (globals.Verbose)
    {
        Console.Error.WriteLine("detail: " + ex.DiagnosticDetail);
    }
    return ex.Category switch
    {
        ErrorCategory.Scope => ExitCodes.ScopeDenied,
        ErrorCategory.Configuration => ExitCodes.UsageError,
        _ => ExitCodes.RuntimeFailure
    };
}
