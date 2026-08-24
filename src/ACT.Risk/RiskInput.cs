using ACT.Contracts;

namespace ACT.Risk;

/// <summary>
/// Deterministic inputs to technical risk prioritization. The business-impact band is carried
/// for reporting and is deliberately excluded from the priority score by contract.
/// </summary>
public sealed record RiskInput(
    Severity TechnicalSeverity,
    ConfidenceLevel Confidence,
    bool ExploitabilityIndicator,
    bool ExposedToNetwork,
    bool Recurring,
    bool RemediationAvailable,
    BusinessImpactLevel BusinessImpact);
