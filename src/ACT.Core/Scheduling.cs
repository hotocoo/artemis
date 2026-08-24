
namespace ACT.Core;

using ACT.Contracts;

/// <summary>
/// Parsed five-field cron expression (minute hour day-of-month month day-of-week), standard
/// semantics including the DOM/DOW OR-rule when both are restricted.
/// </summary>
public sealed class CronSchedule
{
    private readonly HashSet<int>[] _fields = [.. Enumerable.Range(0, 5).Select(_ => new HashSet<int>())];
    private readonly bool[] _wildcard = new bool[5];
    private readonly int[][] _fieldRanges = [[0, 59], [0, 23], [1, 31], [1, 12], [0, 6]];

    public string Expression { get; }

    private CronSchedule(string expression) => Expression = expression;

    public static bool TryParse(string expression, out CronSchedule schedule)
    {
        schedule = new CronSchedule(expression.Trim());
        var parts = expression.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length != 5) return false;

        for (var f = 0; f < 5; f++)
        {
            if (!schedule.ParseField(f, parts[f])) return false;
        }
        return true;
    }

    private bool ParseField(int fieldIndex, string text)
    {
        var (low, high) = (_fieldRanges[fieldIndex][0], _fieldRanges[fieldIndex][1]);
        foreach (var part in text.Split(','))
        {
            var stepPart = part.Split('/');
            var step = 1;
            if (stepPart.Length == 2)
            {
                if (!int.TryParse(stepPart[1], out step) || step <= 0) return false;
            }
            else if (stepPart.Length > 2)
            {
                return false;
            }

            var range = stepPart[0];
            if (range == "*")
            {
                if (!_wildcard[fieldIndex] || _fields[fieldIndex].Count == 0)
                {
                    _wildcard[fieldIndex] = true;
                    for (var v = low; v <= high; v += step) _fields[fieldIndex].Add(v);
                }
                continue;
            }

            var bounds = range.Split('-');
            int start;
            int end;
            if (bounds.Length == 1)
            {
                if (!int.TryParse(bounds[0], out start)) return false;
                end = start;
            }
            else if (bounds.Length == 2)
            {
                if (!int.TryParse(bounds[0], out start) || !int.TryParse(bounds[1], out end)) return false;
            }
            else
            {
                return false;
            }

            if (start < low || end > high || start > end) return false;
            for (var v = start; v <= end; v += step) _fields[fieldIndex].Add(v);
        }
        return _fields[fieldIndex].Count > 0;
    }

    /// <summary>Whether the schedule fires at the given local time.</summary>
    public bool Matches(DateTimeOffset localTime)
    {
        if (!_fields[1].Contains(localTime.Hour)) return false;
        if (!_fields[0].Contains(localTime.Minute)) return false;
        if (!_fields[3].Contains(localTime.Month)) return false;

        var domRestricted = !_wildcard[2];
        var dowRestricted = !_wildcard[4];

        var domOk = _fields[2].Contains(localTime.Day);
        var cronDow = ((int)localTime.DayOfWeek) % 7; // cron: 0=Sunday
        var dowOk = _fields[4].Contains(cronDow);

        if (domRestricted && dowRestricted) return domOk || dowOk;
        if (domRestricted) return domOk;
        if (dowRestricted) return dowOk;
        return true;
    }

    /// <summary>Next occurrence strictly after 'after', scanning minute-by-minute up to 366 days.</summary>
    public DateTimeOffset NextOccurrence(DateTimeOffset afterLocal)
    {
        var candidate = new DateTimeOffset(afterLocal.Year, afterLocal.Month, afterLocal.Day, afterLocal.Hour,
            afterLocal.Minute, 0, afterLocal.Offset).AddMinutes(1);
        var limit = candidate.AddDays(366);
        while (candidate <= limit)
        {
            if (Matches(candidate)) return candidate;
            candidate = candidate.AddMinutes(1);
        }
        throw ActException.FailClosed(ErrorCategory.Configuration,
            "The schedule never fires within one year; it cannot be scheduled.",
            $"Cron '{Expression}' has no occurrence within 366 days.");
    }

    public bool IsDue(DateTimeOffset lastRunLocal, DateTimeOffset nowLocal) =>
        lastRunLocal == DateTimeOffset.MinValue || NextOccurrence(lastRunLocal) <= nowLocal;
}

/// <summary>Honest per-schedule outcome of one ticker evaluation.</summary>
public enum ScheduleDueState
{
    /// <summary>The schedule fires at or before the evaluated instant.</summary>
    Due,

    /// <summary>The next occurrence is still in the future.</summary>
    NotDue,

    /// <summary>The stored expression does not parse; the host must surface this instead of silently ignoring it.</summary>
    InvalidExpression
}

/// <summary>One schedule's relationship to a single tick instant.</summary>
public sealed record ScheduleDueDecision(ScheduleDefinition Schedule, ScheduleDueState State);

/// <summary>
/// Pure due-selection over a snapshot of enabled schedules. Hosts own persistence and execution;
/// this type owns only the deterministic "which schedules fire now" decision, so it stays unit
/// testable and free of I/O. Cron fields are local-time semantics; callers pass instants already
/// converted to the operator's local zone.
/// </summary>
public static class ScheduleTicker
{
    /// <summary>Evaluates every given schedule against one local instant, preserving input order.</summary>
    public static IReadOnlyList<ScheduleDueDecision> Evaluate(
        IReadOnlyList<ScheduleDefinition> enabledSchedules,
        DateTimeOffset nowLocal)
    {
        ArgumentNullException.ThrowIfNull(enabledSchedules);
        var decisions = new List<ScheduleDueDecision>(enabledSchedules.Count);
        foreach (var schedule in enabledSchedules)
        {
            if (!CronSchedule.TryParse(schedule.CronExpression, out var cron))
            {
                decisions.Add(new ScheduleDueDecision(schedule, ScheduleDueState.InvalidExpression));
                continue;
            }

            // A schedule that never ran is immediately due; otherwise compare against the first
            // occurrence strictly after the recorded local run time.
            var lastRunLocal = schedule.LastRunUtc?.ToLocalTime() ?? DateTimeOffset.MinValue;
            decisions.Add(new ScheduleDueDecision(
                schedule,
                cron.IsDue(lastRunLocal, nowLocal) ? ScheduleDueState.Due : ScheduleDueState.NotDue));
        }

        return decisions;
    }
}
