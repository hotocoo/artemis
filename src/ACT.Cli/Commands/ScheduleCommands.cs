
using System.Text;
using System.Text.Json;
using ACT.Contracts;
using ACT.Core;
using ACT.Persistence;
using Microsoft.Extensions.DependencyInjection;

namespace ACT.Cli;

/// <summary>artemis schedule list|add|enable|disable|tick.</summary>
public static class ScheduleCommands
{
    public static async Task<int> Run(IServiceProvider services, string[] args)
    {
        if (args.Length == 0)
        {
            return Usage();
        }

        var db = services.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();

        return args[0] switch
        {
            "list" => await ListAsync(services, db),
            "add" => await AddAsync(services, db, args[1..]),
            "enable" => await SetEnabledAsync(services, db, args[1..], enabled: true),
            "disable" => await SetEnabledAsync(services, db, args[1..], enabled: false),
            "tick" => await TickAsync(services),
            _ => Usage()
        };

        static int Usage()
        {
            Console.Error.WriteLine("usage: artemis schedule list");
            Console.Error.WriteLine("       artemis schedule add --name NAME --scope FILE --cron EXPR [--trigger Scheduled]");
            Console.Error.WriteLine("       artemis schedule enable SCHEDULE_ID");
            Console.Error.WriteLine("       artemis schedule disable SCHEDULE_ID");
            Console.Error.WriteLine("       artemis schedule tick");
            Console.Error.WriteLine();
            Console.Error.WriteLine("Schedules reference frozen validated scopes; they can never widen authorization.");
            Console.Error.WriteLine("Drive ticks from the console host OR an external scheduler - never both on one database.");
            return ExitCodes.UsageError;
        }
    }

    private static async Task<int> ListAsync(IServiceProvider services, ActDatabase db)
    {
        var schedules = await db.ListAllSchedulesAsync();

        var text = new StringBuilder();
        text.AppendLine(string.Format("{0,-24} {1,-14} {2,-22} {3,-8} {4,-22} {5}",
            "NAME", "CRON", "TRIGGER", "ENABLED", "LAST RUN", "NEXT RUN"));
        foreach (var schedule in schedules)
        {
            var next = "-";
            if (schedule.Enabled && CronSchedule.TryParse(schedule.CronExpression, out var cron))
            {
                try { next = cron.NextOccurrence(DateTimeOffset.Now).ToString("yyyy-MM-dd HH:mm"); }
                catch (ActException) { next = "never"; }
            }

            text.AppendLine(string.Format("{0,-24} {1,-14} {2,-22} {3,-8} {4,-22} {5}",
                schedule.Name,
                schedule.CronExpression,
                schedule.Trigger.ToString(),
                schedule.Enabled ? "yes" : "no",
                schedule.LastRunUtc?.ToLocalTime().ToString("yyyy-MM-dd HH:mm") ?? "never",
                next));
        }

        var json = JsonSerializer.Serialize(
            schedules.Select(ScheduledExecutionHost.ToJsonRow), JsonOpts.Indented);
        return await OutputWriter.WriteAsync(services, text.ToString(), json);
    }

    private static async Task<int> AddAsync(IServiceProvider services, ActDatabase db, string[] args)
    {
        var name = FlagValue(args, "--name");
        var scopeFile = FlagValue(args, "--scope");
        var cron = FlagValue(args, "--cron");
        var triggerText = FlagValue(args, "--trigger") ?? nameof(ScheduleTriggerKind.Scheduled);

        if (name is null || scopeFile is null || cron is null)
        {
            Console.Error.WriteLine("error: --name NAME, --scope FILE, and --cron EXPR are required");
            return ExitCodes.UsageError;
        }

        if (!CronSchedule.TryParse(cron, out _))
        {
            Console.Error.WriteLine($"error: '{cron}' is not a valid five-field cron expression");
            return ExitCodes.UsageError;
        }

        if (!Enum.TryParse<ScheduleTriggerKind>(triggerText, ignoreCase: true, out var trigger))
        {
            Console.Error.WriteLine($"error: unknown trigger kind '{triggerText}'");
            return ExitCodes.UsageError;
        }

        // Fail closed before anything is stored: the scope file must load and validate NOW,
        // because this exact snapshot is what will run later.
        ScopeDefinition scope;
        try
        {
            scope = ScopeFile.Load(scopeFile);
            scope.Validate();
        }
        catch (ActException ex)
        {
            Console.Error.WriteLine("error: scope rejected: " + ex.SafeMessage);
            return ExitCodes.ScopeDenied;
        }

        var scheduleId = await ScheduledExecutionHost.AddAsync(services, name, scope, cron, trigger);
        return await OutputWriter.WriteAsync(services,
            $"scheduled '{name.Trim()}' ({cron}) against scope {scope.ScopeId}: {scheduleId}",
            JsonSerializer.Serialize(new
            {
                scheduleId,
                name = name.Trim(),
                cron,
                trigger = trigger.ToString(),
                scopeId = scope.ScopeId
            }, JsonOpts.Indented));
    }

    private static async Task<int> SetEnabledAsync(
        IServiceProvider services, ActDatabase db, string[] args, bool enabled)
    {
        if (args.Length == 0 || !Guid.TryParse(args[0], out var id))
        {
            Console.Error.WriteLine("usage: artemis schedule <enable|disable> SCHEDULE_ID");
            return ExitCodes.UsageError;
        }

        var existing = await db.GetScheduleAsync(id);
        if (existing is null)
        {
            Console.Error.WriteLine("error: schedule not found: " + id);
            return ExitCodes.RuntimeFailure;
        }

        var updated = existing with { Enabled = enabled };
        await db.SaveScheduleAsync(updated);
        await db.AppendAuditAsync(new AuditDraft(
            "operator", enabled ? "schedule.enabled" : "schedule.disabled",
            "schedule", id.ToString(), existing.Name, CorrelationId.New()));
        return await OutputWriter.WriteAsync(services,
            $"{(enabled ? "enabled" : "disabled")} schedule {id} ({existing.Name})",
            JsonSerializer.Serialize(ScheduledExecutionHost.ToJsonRow(updated), JsonOpts.Indented));
    }

    private static async Task<int> TickAsync(IServiceProvider services)
    {
        var outcomes = await ScheduledExecutionHost.TickOnceAsync(services);
        var failed = outcomes.Count(o => o.State is ScheduledRunState.ExecutionFailed
            or ScheduledRunState.MissingScope or ScheduledRunState.ScopeRejected
            or ScheduledRunState.InvalidExpression or ScheduledRunState.MaintenanceFailed);

        var text = new StringBuilder();
        text.AppendLine($"tick complete: {outcomes.Count} due schedule(s), {failed} failed");
        foreach (var outcome in outcomes)
        {
            text.AppendLine($"  {outcome.Name} [{outcome.State}] {outcome.Detail}");
        }

        var json = JsonSerializer.Serialize(new
        {
            ranAtUtc = DateTimeOffset.UtcNow,
            dueCount = outcomes.Count,
            failedCount = failed,
            outcomes = outcomes.Select(o => new
            {
                scheduleId = o.ScheduleId,
                name = o.Name,
                state = o.State.ToString(),
                assessmentId = o.AssessmentId,
                checksExecuted = o.ChecksExecuted,
                findingsEmitted = o.FindingsEmitted,
                detail = o.Detail
            })
        }, JsonOpts.Indented);

        await OutputWriter.WriteAsync(services, text.ToString(), json);
        // Scriptable honesty: a tick with failures exits non-zero even though the command itself ran.
        return failed > 0 ? ExitCodes.RuntimeFailure : ExitCodes.Ok;
    }

    private static string? FlagValue(string[] args, string flag)
    {
        var index = Array.FindIndex(args, a => a == flag);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }
}
