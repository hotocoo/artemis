
using System.Text.Json;
using ACT.Contracts;
using ACT.Core;
using ACT.Persistence;
using ACT.Policy;
using Microsoft.Extensions.DependencyInjection;

namespace ACT.Cli;

/// <summary>Terminal outcome of one schedule inside one tick, honestly separated.</summary>
public enum ScheduledRunState
{
    /// <summary>The assessment ran to engine completion.</summary>
    Executed,

    /// <summary>Due, but the emergency-stop latch denied execution; it stays due and fires after disarming.</summary>
    SkippedEmergencyStop,

    /// <summary>The stored cron expression does not parse; surfaced instead of silently dropped.</summary>
    InvalidExpression,

    /// <summary>The frozen scope snapshot for this schedule is missing from storage.</summary>
    MissingScope,

    /// <summary>The stored scope no longer passes structural validation.</summary>
    ScopeRejected,

    /// <summary>The launch failed after starting; details live in the audit log.</summary>
    ExecutionFailed
}

/// <summary>One schedule's tick result for human and JSON output.</summary>
public sealed record ScheduledRunOutcome(
    Guid ScheduleId,
    string Name,
    ScheduledRunState State,
    Guid? AssessmentId,
    int ChecksExecuted,
    int FindingsEmitted,
    string Detail);

/// <summary>
/// Bridges persisted schedules to assessment launches. The ticker decision is pure
/// (<see cref="ScheduleTicker.Evaluate"/>); this type owns persistence, auditing, and execution.
/// Schedules reference frozen, validated scope snapshots and can never widen authorization:
/// whatever was validated at 'schedule add' time is exactly what runs, revalidated structurally
/// before every launch.
///
/// Concurrency contract: one database is driven by ONE active ticker (the console host loop or an
/// external 'artemis schedule tick' invocation, never both), because due-selection reads
/// last_run_utc and executes without a distributed lease. This is documented in the operator
/// manual; cross-host leasing would add state the current schema deliberately avoids.
/// </summary>
public static class ScheduledExecutionHost
{
    /// <summary>Configuration key prefix under which each schedule's frozen scope snapshot lives.</summary>
    public const string ScopeConfigKeyPrefix = "schedule-scope:";

    /// <summary>
    /// Evaluates all enabled schedules against the current local time and executes what is due.
    /// Never throws for individual schedule failures - failures become honest outcomes plus audit
    /// entries; only cancellation propagates. Returns one outcome per non-NotDue decision.
    /// </summary>
    public static async Task<IReadOnlyList<ScheduledRunOutcome>> TickOnceAsync(
        IServiceProvider services,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(services);
        var db = services.GetRequiredService<ActDatabase>();
        var emergency = services.GetRequiredService<EmergencyStop>();

        // The stop latch lives in two places by design: this process's in-memory latch AND the
        // persisted flag written by 'artemis assessment stop' from another process. Both deny
        // execution; checking only one would let a scheduled run ignore an operator's stop.
        var persistedStop = await db.GetConfigAsync<EmergencyStopFlag>(
            AssessmentCommands.EmergencyFlagKey, cancellationToken);

        var enabled = await db.ListEnabledSchedulesAsync(cancellationToken);
        var decisions = ScheduleTicker.Evaluate(enabled, DateTimeOffset.Now);

        var outcomes = new List<ScheduledRunOutcome>();
        foreach (var decision in decisions)
        {
            cancellationToken.ThrowIfCancellationRequested();
            switch (decision.State)
            {
                case ScheduleDueState.NotDue:
                    continue;

                case ScheduleDueState.InvalidExpression:
                    await db.AppendAuditAsync(new AuditDraft(
                        "scheduler", "schedule.invalid_expression", "schedule",
                        decision.Schedule.ScheduleId.ToString(),
                        "cron expression does not parse", CorrelationId.New()), cancellationToken);
                    outcomes.Add(new ScheduledRunOutcome(
                        decision.Schedule.ScheduleId, decision.Schedule.Name,
                        ScheduledRunState.InvalidExpression, null, 0, 0,
                        $"cron expression '{decision.Schedule.CronExpression}' does not parse"));
                    break;

                case ScheduleDueState.Due when emergency.IsArmed || persistedStop is not null:
                    // Left unmarked as ran: the schedule stays due and executes after disarm.
                    await db.AppendAuditAsync(new AuditDraft(
                        "scheduler", "schedule.skipped_emergency_stop", "schedule",
                        decision.Schedule.ScheduleId.ToString(),
                        "emergency stop armed", CorrelationId.New()), cancellationToken);
                    outcomes.Add(new ScheduledRunOutcome(
                        decision.Schedule.ScheduleId, decision.Schedule.Name,
                        ScheduledRunState.SkippedEmergencyStop, null, 0, 0,
                        "due, but the emergency stop is armed"));
                    break;

                case ScheduleDueState.Due:
                default:
                    outcomes.Add(await ExecuteAsync(services, db, decision.Schedule, cancellationToken));
                    break;
            }
        }

        return outcomes;
    }

    private static async Task<ScheduledRunOutcome> ExecuteAsync(
        IServiceProvider services, ActDatabase db, ScheduleDefinition schedule, CancellationToken token)
    {
        // The fire instant is recorded before execution so cron cadence measures start-to-start.
        var firedAtUtc = DateTimeOffset.UtcNow;
        var correlation = CorrelationId.New();
        var scopeKey = ScopeConfigKeyPrefix + schedule.ScheduleId.ToString("N");

        var snapshot = await db.GetConfigAsync<ScopeDefinition>(scopeKey, token);
        if (snapshot is null)
        {
            await db.MarkScheduleRanAsync(schedule.ScheduleId, firedAtUtc, token);
            await db.AppendAuditAsync(new AuditDraft(
                "scheduler", "schedule.missing_scope", "schedule",
                schedule.ScheduleId.ToString(), "no stored scope snapshot", correlation), token);
            return new ScheduledRunOutcome(schedule.ScheduleId, schedule.Name,
                ScheduledRunState.MissingScope, null, 0, 0,
                "the stored scope snapshot is gone; recreate the schedule");
        }

        try
        {
            snapshot.Validate();
        }
        catch (ActException ex)
        {
            await db.MarkScheduleRanAsync(schedule.ScheduleId, firedAtUtc, token);
            await db.AppendAuditAsync(new AuditDraft(
                "scheduler", "schedule.scope_rejected", "schedule",
                schedule.ScheduleId.ToString(), ex.SafeMessage[..Math.Min(120, ex.SafeMessage.Length)],
                correlation), token);
            return new ScheduledRunOutcome(schedule.ScheduleId, schedule.Name,
                ScheduledRunState.ScopeRejected, null, 0, 0, ex.SafeMessage);
        }

        await db.AppendAuditAsync(new AuditDraft(
            "scheduler", "schedule.run_started", "assessment",
            snapshot.AssessmentId.ToString(), schedule.Name, correlation), token);

        // Each fire is its own assessment against the SAME frozen scope: fresh assessment id,
        // constant scope id. This mirrors the interactive create->start contract (the engine
        // requires a persisted assessment row) and keeps reports addressable per run while
        // drift/baseline comparisons still group by scope.
        var runScope = snapshot with { AssessmentId = Guid.NewGuid() };
        var record = new AssessmentRecord(
            runScope.AssessmentId, runScope.ScopeId, schedule.Name,
            AssessmentRunState.Created, firedAtUtc, null, null,
            runScope.OperatorIdentity, runScope.Organization);
        await db.CreateAssessmentAsync(record, runScope);
        await db.SetConfigAsync("scope:" + runScope.AssessmentId.ToString("N"), runScope, token);

        try
        {
            var baseUrl = AssessmentLauncher.ResolveBaseUrl(null, runScope);
            var summary = await AssessmentLauncher.LaunchAsync(
                services, runScope, baseUrl, AuthorizationFixtureSet.None, token);

            await db.MarkScheduleRanAsync(schedule.ScheduleId, firedAtUtc, token);
            await db.AppendAuditAsync(new AuditDraft(
                "scheduler", "schedule.run_completed", "assessment",
                summary.AssessmentId.ToString(),
                $"{summary.ChecksExecuted} checks, {summary.Findings.Count} findings", correlation), token);

            return new ScheduledRunOutcome(schedule.ScheduleId, schedule.Name,
                ScheduledRunState.Executed, summary.AssessmentId,
                summary.ChecksExecuted, summary.Findings.Count,
                $"{summary.ChecksExecuted} checks executed, {summary.Findings.Count} findings");
        }
        catch (OperationCanceledException)
        {
            // Host shutdown or cancellation: leave unmarked so the next tick retries honestly.
            throw;
        }
        catch (ActException ex)
        {
            await db.MarkScheduleRanAsync(schedule.ScheduleId, firedAtUtc, token);
            await db.AppendAuditAsync(new AuditDraft(
                "scheduler", "schedule.run_failed", "schedule",
                schedule.ScheduleId.ToString(), ex.SafeMessage[..Math.Min(120, ex.SafeMessage.Length)],
                correlation), token);
            return new ScheduledRunOutcome(schedule.ScheduleId, schedule.Name,
                ScheduledRunState.ExecutionFailed, null, 0, 0,
                string.IsNullOrEmpty(ex.DiagnosticDetail) ? ex.SafeMessage : ex.SafeMessage + " [" + ex.DiagnosticDetail + "]");
        }
        catch (Exception ex)
        {
            // Unexpected failures are contained here so one broken schedule cannot kill a host
            // loop. A CLI tick has no host log, so the operator-facing detail carries the
            // exception identity verbatim; the audit entry stays coarse on purpose.
            await db.MarkScheduleRanAsync(schedule.ScheduleId, firedAtUtc, token);
            await db.AppendAuditAsync(new AuditDraft(
                "scheduler", "schedule.run_failed", "schedule",
                schedule.ScheduleId.ToString(), "unexpected failure; see host diagnostics",
                correlation), token);
            return new ScheduledRunOutcome(schedule.ScheduleId, schedule.Name,
                ScheduledRunState.ExecutionFailed, null, 0, 0,
                ex.GetType().Name + ": " + ex.Message);
        }
    }

    /// <summary>Persists one schedule together with its frozen, structurally validated scope.</summary>
    public static async Task<Guid> AddAsync(
        IServiceProvider services, string name, ScopeDefinition validatedScope,
        string cronExpression, ScheduleTriggerKind trigger, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentException.ThrowIfNullOrWhiteSpace(name);

        var db = services.GetRequiredService<ActDatabase>();
        var schedule = new ScheduleDefinition(
            ScheduleId: Guid.NewGuid(),
            Name: name.Trim(),
            ScopeId: validatedScope.ScopeId,
            CronExpression: cronExpression,
            Trigger: trigger,
            Enabled: true,
            CreatedUtc: DateTimeOffset.UtcNow,
            LastRunUtc: null);

        await db.SaveScheduleAsync(schedule, token);
        await db.SetConfigAsync(ScopeConfigKeyPrefix + schedule.ScheduleId.ToString("N"), validatedScope, token);
        await db.AppendAuditAsync(new AuditDraft(
            "operator", "schedule.created", "schedule",
            schedule.ScheduleId.ToString(), $"{name} ({cronExpression})", CorrelationId.New()), token);
        return schedule.ScheduleId;
    }

    /// <summary>Serializes a schedule list row for --json output.</summary>
    public static object ToJsonRow(ScheduleDefinition schedule) => new
    {
        scheduleId = schedule.ScheduleId,
        name = schedule.Name,
        scopeId = schedule.ScopeId,
        cron = schedule.CronExpression,
        trigger = schedule.Trigger.ToString(),
        enabled = schedule.Enabled,
        createdUtc = schedule.CreatedUtc,
        lastRunUtc = schedule.LastRunUtc
    };

    /// <summary>Stable JSON options for schedule command output.</summary>
    public static JsonSerializerOptions Indented { get; } = new() { WriteIndented = true };
}
