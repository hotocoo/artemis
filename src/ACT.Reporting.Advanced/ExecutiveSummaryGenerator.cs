using ACT.Contracts;

namespace ACT.Reporting.Advanced;

public class ExecutiveSummaryGenerator
{
    public ExecutiveSummary Generate(IReadOnlyList<Finding> findings)
    {
        var total = findings.Count;
        var critical = findings.Count(f => f.TechnicalSeverity == Severity.Critical);
        var high = findings.Count(f => f.TechnicalSeverity == Severity.High);
        var medium = findings.Count(f => f.TechnicalSeverity == Severity.Medium);
        var low = findings.Count(f => f.TechnicalSeverity == Severity.Low);
        var info = findings.Count(f => f.TechnicalSeverity == Severity.Informational);

        var riskScore = CalculateRiskScore(findings);
        var riskLevel = riskScore >= 80 ? "High" : riskScore >= 50 ? "Medium" : "Low";

        var topFindings = findings
            .OrderByDescending(f => f.TechnicalSeverity)
            .ThenBy(f => f.Title)
            .Take(5)
            .Select(f => new TopFinding(f.Title, f.TechnicalSeverity.ToString(), f.Description, f.Remediation.Summary))
            .ToArray();

        return new ExecutiveSummary(
            total,
            critical,
            high,
            medium,
            low,
            info,
            riskScore,
            riskLevel,
            topFindings,
            GenerateNarrative(critical, high, medium, low, info, riskLevel),
            DateTimeOffset.UtcNow);
    }

    private static int CalculateRiskScore(IReadOnlyList<Finding> findings)
    {
        var score = 0;
        foreach (var f in findings)
        {
            score += f.TechnicalSeverity switch
            {
                Severity.Critical => 25,
                Severity.High => 15,
                Severity.Medium => 8,
                Severity.Low => 3,
                _ => 1
            };
        }
        return Math.Min(100, score);
    }

    private static string GenerateNarrative(int critical, int high, int medium, int low, int info, string riskLevel)
    {
        var parts = new List<string>();
        parts.Add($"The security assessment identified {critical + high + medium + low + info} total findings.");

        if (critical > 0)
        {
            parts.Add($"{critical} critical finding(s) require immediate attention.");
        }
        if (high > 0)
        {
            parts.Add($"{high} high-severity finding(s) should be addressed within 30 days.");
        }
        if (medium > 0)
        {
            parts.Add($"{medium} medium-severity finding(s) should be addressed within 90 days.");
        }

        parts.Add($"Overall risk level: {riskLevel}.");
        return string.Join(" ", parts);
    }
}

public record ExecutiveSummary(
    int TotalFindings,
    int Critical,
    int High,
    int Medium,
    int Low,
    int Info,
    int RiskScore,
    string RiskLevel,
    IReadOnlyList<TopFinding> TopFindings,
    string Narrative,
    DateTimeOffset GeneratedAt);

public record TopFinding(
    string Title,
    string Severity,
    string Description,
    string? Recommendation);
