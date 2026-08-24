
namespace ACT.Cli;

/// <summary>Persisted emergency-stop flag read by every running engine process.</summary>
public sealed record EmergencyStopFlag(DateTimeOffset ArmedUtc, string Reason);
