using ACT.Contracts;

namespace ACT.Compliance;

public class ComplianceReportGenerator
{
    public ComplianceReport Generate(IReadOnlyList<Finding> findings, ComplianceFramework framework)
    {
        var mappings = ComplianceMappingRegistry.GetMappingsForFramework(framework);
        var checkToMappings = mappings.ToLookup(m => m.CheckId);

        var controlResults = new List<ComplianceControlResult>();
        var controls = mappings.Select(m => (m.ControlId, m.ControlName)).Distinct().ToList();

        foreach (var (controlId, controlName) in controls)
        {
            var controlMappings = mappings.Where(m => m.ControlId == controlId).ToArray();
            var controlCheckIds = controlMappings.Select(m => m.CheckId).ToArray();
            var relevantFindings = findings.Where(f => controlCheckIds.Contains(f.CheckId.Value)).ToArray();

            var status = relevantFindings.Length == 0
                ? ComplianceStatus.Pass
                : relevantFindings.Any(f => f.TechnicalSeverity >= Severity.High)
                    ? ComplianceStatus.Fail
                    : ComplianceStatus.Warning;

            controlResults.Add(new ComplianceControlResult(
                controlId,
                controlName,
                status,
                relevantFindings,
                controlMappings.Select(m => m.ControlDescription).First()));
        }

        var passCount = controlResults.Count(c => c.Status == ComplianceStatus.Pass);
        var failCount = controlResults.Count(c => c.Status == ComplianceStatus.Fail);
        var warningCount = controlResults.Count(c => c.Status == ComplianceStatus.Warning);

        return new ComplianceReport(
            framework,
            controlResults,
            passCount,
            failCount,
            warningCount,
            DateTimeOffset.UtcNow);
    }
}

public record ComplianceReport(
    ComplianceFramework Framework,
    IReadOnlyList<ComplianceControlResult> Controls,
    int PassCount,
    int FailCount,
    int WarningCount,
    DateTimeOffset GeneratedAt);

public record ComplianceControlResult(
    string ControlId,
    string ControlName,
    ComplianceStatus Status,
    IReadOnlyList<Finding> Findings,
    string Description);

public enum ComplianceStatus
{
    Pass,
    Warning,
    Fail
}
