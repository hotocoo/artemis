using ACT.Contracts;

namespace ACT.Sla;

public record SlaPolicy(
    Severity Severity,
    TimeSpan ResponseTime,
    TimeSpan ResolutionTime);

public static class DefaultSlaPolicies
{
    public static IReadOnlyList<SlaPolicy> Policies => new List<SlaPolicy>
    {
        new(Severity.Critical, TimeSpan.FromHours(1), TimeSpan.FromDays(1)),
        new(Severity.High, TimeSpan.FromHours(4), TimeSpan.FromDays(7)),
        new(Severity.Medium, TimeSpan.FromHours(24), TimeSpan.FromDays(30)),
        new(Severity.Low, TimeSpan.FromDays(2), TimeSpan.FromDays(90)),
        new(Severity.Informational, TimeSpan.FromDays(7), TimeSpan.FromDays(180)),
    };

    public static SlaPolicy GetPolicyForSeverity(Severity severity)
    {
        return Policies.First(p => p.Severity == severity);
    }
}
