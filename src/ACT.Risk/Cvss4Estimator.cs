namespace ACT.Risk;

/// <summary>CVSS-v4-style attack vector, ordered least to most severe.</summary>
public enum Cvss4AttackVector
{
    Physical = 0,
    Local = 1,
    Adjacent = 2,
    Network = 3
}

/// <summary>CVSS-v4-style privileges required, ordered most restrictive first.</summary>
public enum Cvss4PrivilegesRequired
{
    High = 0,
    Low = 1,
    None = 2
}

/// <summary>CVSS-v4-style user-interaction requirement, ordered most restrictive first.</summary>
public enum Cvss4UserInteraction
{
    Required = 0,
    None = 1
}

/// <summary>CVSS-v4-style confidentiality/integrity/availability impact on one system, ordered least to most severe.</summary>
public enum Cvss4Impact
{
    None = 0,
    Low = 1,
    High = 2
}

/// <summary>CVSS-v4-style exploit maturity, ordered least to most mature. NotDefined follows the CVSS v4 default (equivalent to PocReported).</summary>
public enum Cvss4ExploitMaturity
{
    Unreported = 0,
    NotDefined = 1,
    PocReported = 2,
    Attacked = 3
}

/// <summary>
/// Complete, explicit CVSS-v4-style metric set covering AV, PR, UI, VC, VI, VA, SC, SI, SA, and
/// ExploitMaturity. Every member must be stated; any omitted (null) or out-of-range member makes
/// estimation impossible rather than guessed.
/// </summary>
public sealed record Cvss4Metrics(
    Cvss4AttackVector? AttackVector,
    Cvss4PrivilegesRequired? PrivilegesRequired,
    Cvss4UserInteraction? UserInteraction,
    Cvss4Impact? VulnerableConfidentiality,
    Cvss4Impact? VulnerableIntegrity,
    Cvss4Impact? VulnerableAvailability,
    Cvss4Impact? SubsequentConfidentiality,
    Cvss4Impact? SubsequentIntegrity,
    Cvss4Impact? SubsequentAvailability,
    Cvss4ExploitMaturity? ExploitMaturity);

/// <summary>
/// Conservative CVSS-v4-STYLE base-score approximation. This is NOT a certified CVSS v4
/// calculator: it is a simplified monotone model in which raising any metric never lowers the
/// score. Model, all factors multiplying with impact normalized to 0..10:
/// <list type="bullet">
/// <item>vulnerable-system impact = sum of VC, VI, VA mapped None=0, Low=1, High=2.5 (max 7.5)</item>
/// <item>subsequent-system impact = sum of SC, SI, SA mapped None=0, Low=0.5, High=1.5 (max 4.5)</item>
/// <item>impact = (vulnerable + subsequent) / 12 * 10</item>
/// <item>AV: Network=1.00, Adjacent=0.86, Local=0.70, Physical=0.55</item>
/// <item>PR: None=1.00, Low=0.88, High=0.70</item>
/// <item>UI: None=1.00, Required=0.85</item>
/// <item>E: Attacked=1.00, PocReported=0.96, NotDefined=0.96 (v4 default), Unreported=0.88</item>
/// <item>base = round_half_up(impact * exploitability factors, 1), clamped to [0, 10]</item>
/// </list>
/// Any unknown metric yields null: the estimator never guesses.
/// </summary>
public static class Cvss4Estimator
{
    /// <summary>Estimates the CVSS-v4-style base score, or null when any metric is unknown or out of range.</summary>
    public static double? Estimate(Cvss4Metrics? metrics)
    {
        if (metrics is null ||
            !Defined(metrics.AttackVector) ||
            !Defined(metrics.PrivilegesRequired) ||
            !Defined(metrics.UserInteraction) ||
            !Defined(metrics.VulnerableConfidentiality) ||
            !Defined(metrics.VulnerableIntegrity) ||
            !Defined(metrics.VulnerableAvailability) ||
            !Defined(metrics.SubsequentConfidentiality) ||
            !Defined(metrics.SubsequentIntegrity) ||
            !Defined(metrics.SubsequentAvailability) ||
            !Defined(metrics.ExploitMaturity))
        {
            return null;
        }

        var vulnerableSum = VulnerableImpact(metrics.VulnerableConfidentiality!.Value)
                            + VulnerableImpact(metrics.VulnerableIntegrity!.Value)
                            + VulnerableImpact(metrics.VulnerableAvailability!.Value);
        var subsequentSum = SubsequentImpact(metrics.SubsequentConfidentiality!.Value)
                            + SubsequentImpact(metrics.SubsequentIntegrity!.Value)
                            + SubsequentImpact(metrics.SubsequentAvailability!.Value);
        var impact = (vulnerableSum + subsequentSum) / 12d * 10d;

        var exploitability =
            metrics.AttackVector.Value switch
            {
                Cvss4AttackVector.Network => 1.00d,
                Cvss4AttackVector.Adjacent => 0.86d,
                Cvss4AttackVector.Local => 0.70d,
                _ => 0.55d
            }
            * (metrics.PrivilegesRequired.Value switch
            {
                Cvss4PrivilegesRequired.None => 1.00d,
                Cvss4PrivilegesRequired.Low => 0.88d,
                _ => 0.70d
            })
            * (metrics.UserInteraction.Value switch
            {
                Cvss4UserInteraction.None => 1.00d,
                _ => 0.85d
            })
            * (metrics.ExploitMaturity.Value switch
            {
                Cvss4ExploitMaturity.Attacked => 1.00d,
                Cvss4ExploitMaturity.PocReported => 0.96d,
                Cvss4ExploitMaturity.NotDefined => 0.96d,
                _ => 0.88d
            });

        var raw = Math.Clamp(impact * exploitability, 0d, 10d);
        return Math.Round(raw, 1, MidpointRounding.AwayFromZero);
    }

    private static double VulnerableImpact(Cvss4Impact impact) => impact switch
    {
        Cvss4Impact.None => 0d,
        Cvss4Impact.Low => 1d,
        _ => 2.5d
    };

    private static double SubsequentImpact(Cvss4Impact impact) => impact switch
    {
        Cvss4Impact.None => 0d,
        Cvss4Impact.Low => 0.5d,
        _ => 1.5d
    };

    private static bool Defined<T>(T? value)
        where T : struct, Enum => value is { } defined && Enum.IsDefined(defined);
}
