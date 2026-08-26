using ACT.Contracts;

namespace ACT.Cli;

/// <summary>
/// Tuning for the persisted-flag watcher that cancels a running assessment when an operator
/// arms the emergency stop from another process. The default keeps cross-process stop latency
/// near two seconds; hosts may tighten it through configuration, and tests bind a small
/// interval so in-flight cancellation is provable at deterministic speed. Production behavior
/// is unchanged unless the option is explicitly bound.
/// </summary>
public sealed class EmergencyStopWatchOptions
{
    /// <summary>How often a running assessment re-reads the persisted emergency flag.</summary>
    public TimeSpan PollInterval { get; set; } = TimeSpan.FromSeconds(2);

    /// <summary>Fails closed on non-positive intervals: a zero poll would spin the database.</summary>
    public void Validate()
    {
        if (PollInterval <= TimeSpan.Zero)
        {
            throw ActException.FailClosed(ErrorCategory.Configuration,
                "The emergency-stop watch interval must be positive.",
                "EmergencyStopWatchOptions.PollInterval was '" + PollInterval + "'.");
        }
    }
}
