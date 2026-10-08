using ACT.Contracts;

namespace ACT.Sla;

public record SlaStatus(
    Finding Finding,
    SlaPolicy Policy,
    DateTimeOffset DueResponse,
    DateTimeOffset DueResolution,
    bool ResponseBreached,
    bool ResolutionBreached,
    TimeSpan TimeRemainingForResponse,
    TimeSpan TimeRemainingForResolution);

public class SlaTracker
{
    public SlaStatus GetStatus(Finding finding, DateTimeOffset now)
    {
        var policy = DefaultSlaPolicies.GetPolicyForSeverity(finding.TechnicalSeverity);
        var dueResponse = finding.FirstSeenUtc.Add(policy.ResponseTime);
        var dueResolution = finding.FirstSeenUtc.Add(policy.ResolutionTime);

        var responseBreached = finding.Status != FindingStatus.New && finding.Status != FindingStatus.Confirmed && now > dueResponse;
        var resolutionBreached = finding.Status == FindingStatus.New && now > dueResolution;

        return new SlaStatus(
            finding,
            policy,
            dueResponse,
            dueResolution,
            responseBreached,
            resolutionBreached,
            dueResponse - now,
            dueResolution - now);
    }

    public List<SlaStatus> GetBreached(IReadOnlyList<Finding> findings, DateTimeOffset now)
    {
        return findings
            .Select(f => GetStatus(f, now))
            .Where(s => s.ResponseBreached || s.ResolutionBreached)
            .ToList();
    }
}
