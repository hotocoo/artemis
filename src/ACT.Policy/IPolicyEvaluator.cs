using ACT.Contracts;

namespace ACT.Policy;

/// <summary>Decides whether one declared security check may run under one assessment scope.</summary>
public interface IPolicyEvaluator
{
    /// <summary>
    /// Evaluates the check against the scope. Returns a structured verdict; throws
    /// <see cref="ActException"/> only when the scope itself is unusable (fail closed).
    /// </summary>
    PolicyDecision Evaluate(ScopeDefinition scope, SecurityCheckMetadata check);
}
