using ACT.Contracts;

namespace ACT.Policy;

/// <summary>
/// Scope-driven policy gate with a fixed verdict order: prohibited categories outrank everything,
/// then the emergency-stop latch, then category enablement, granted permissions, and finally the
/// safety-level ceiling. Scopes without any category policy fail closed.
/// </summary>
public sealed class ScopePolicyEvaluator : IPolicyEvaluator
{
    /// <summary>All four permission bits granted; the constructor default.</summary>
    public const PermissionRequirement AllPermissions =
        PermissionRequirement.OutboundNetworkToLocalTargets
        | PermissionRequirement.ReadRepositoryFiles
        | PermissionRequirement.ReadLocalDatabase
        | PermissionRequirement.UseProvidedTestCredentials;

    private readonly EmergencyStop? _emergencyStop;
    private readonly PermissionRequirement _grantedPermissions;
    private readonly bool _allowActiveChecks;

    /// <summary>Creates the evaluator. Without an injected latch the emergency stop never triggers.</summary>
    /// <param name="emergencyStop">Shared latch consulted before any other allow path.</param>
    /// <param name="grantedPermissions">Permission bits the operator granted; requests outside this mask are denied.</param>
    /// <param name="allowActiveChecks">Whether ActiveNonDestructive checks may run at all.</param>
    public ScopePolicyEvaluator(
        EmergencyStop? emergencyStop = null,
        PermissionRequirement grantedPermissions = AllPermissions,
        bool allowActiveChecks = false)
    {
        _emergencyStop = emergencyStop;
        _grantedPermissions = grantedPermissions;
        _allowActiveChecks = allowActiveChecks;
    }

    /// <inheritdoc />
    public PolicyDecision Evaluate(ScopeDefinition scope, SecurityCheckMetadata check)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentNullException.ThrowIfNull(check);

        if (scope.AllowedCategories.Count == 0 && scope.ProhibitedCategories.Count == 0)
        {
            throw ActException.FailClosed(
                ErrorCategory.Configuration,
                "The scope defines no category policy, so no check can be authorized.",
                $"Scope {scope.ScopeId} has empty AllowedCategories and ProhibitedCategories.");
        }

        if (scope.ProhibitedCategories.Contains(check.Category))
        {
            return PolicyDecision.Deny(
                PolicyReasonCodes.CategoryProhibited,
                "This check category is prohibited for the current assessment.",
                $"Category {check.Category} is prohibited; check '{check.Id.Value}' denied.");
        }

        if (_emergencyStop is { IsArmed: true })
        {
            return PolicyDecision.Deny(
                PolicyReasonCodes.EmergencyStopArmed,
                "An emergency stop is armed; every security check is halted.",
                $"Emergency stop armed while evaluating '{check.Id.Value}'; recorded reason: {_emergencyStop.Reason}");
        }

        if (!scope.AllowedCategories.Contains(check.Category))
        {
            return PolicyDecision.Deny(
                PolicyReasonCodes.CategoryNotEnabled,
                "This check category is not enabled for the current assessment.",
                $"Category {check.Category} is missing from the allowed set; check '{check.Id.Value}' denied.");
        }

        var missing = check.RequiredPermissions & ~_grantedPermissions;
        if (missing != PermissionRequirement.None)
        {
            return PolicyDecision.Deny(
                PolicyReasonCodes.PermissionDenied,
                "This check needs permissions the operator has not granted.",
                $"Check '{check.Id.Value}' requires {missing}, outside the granted mask {_grantedPermissions}.");
        }

        if (check.SafetyLevel == SafetyLevel.ActiveNonDestructive && !_allowActiveChecks)
        {
            return PolicyDecision.Deny(
                PolicyReasonCodes.SafetyLevelExceeded,
                "Active verification is not permitted by the current safety configuration.",
                $"Check '{check.Id.Value}' declares {nameof(SafetyLevel.ActiveNonDestructive)} while allowActiveChecks is false.");
        }

        return PolicyDecision.Allow(
            "This security check is permitted by the assessment policy.",
            $"Check '{check.Id.Value}' allowed in category {check.Category}.");
    }
}
