namespace ACT.Policy;

/// <summary>Stable machine-readable reason codes attached to every <see cref="PolicyDecision"/>.</summary>
public static class PolicyReasonCodes
{
    /// <summary>The check is permitted.</summary>
    public const string Allowed = "ALLOWED";

    /// <summary>The check's category is explicitly prohibited by the scope; this verdict outranks every other.</summary>
    public const string CategoryProhibited = "CATEGORY_PROHIBITED";

    /// <summary>The check's category is missing from the scope's enabled categories.</summary>
    public const string CategoryNotEnabled = "CATEGORY_NOT_ENABLED";

    /// <summary>The check requires permission bits outside the constructor-granted mask.</summary>
    public const string PermissionDenied = "PERMISSION_DENIED";

    /// <summary>The check's safety level exceeds the configured ceiling (active checks not enabled).</summary>
    public const string SafetyLevelExceeded = "SAFETY_LEVEL_EXCEEDED";

    /// <summary>The emergency-stop latch is armed; every check is halted.</summary>
    public const string EmergencyStopArmed = "EMERGENCY_STOP_ARMED";
}

/// <summary>
/// Structured verdict of one policy question about one check. Fails closed by convention:
/// anything that is not explicitly allowed is denied with a stable reason code.
/// </summary>
public sealed record PolicyDecision(bool Allowed, string ReasonCode, string SafeMessage, string DiagnosticDetail)
{
    /// <summary>Creates an allowing decision carrying the canonical <see cref="PolicyReasonCodes.Allowed"/> code.</summary>
    public static PolicyDecision Allow(string safeMessage, string diagnosticDetail) =>
        new(true, PolicyReasonCodes.Allowed, safeMessage, diagnosticDetail);

    /// <summary>Creates a denying decision with a specific reason code and a user-safe message.</summary>
    public static PolicyDecision Deny(string reasonCode, string safeMessage, string diagnosticDetail) =>
        new(false, reasonCode, safeMessage, diagnosticDetail);
}
