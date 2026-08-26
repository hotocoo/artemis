using ACT.Contracts;
using ACT.Persistence;
using ACT.Reporting;

namespace ACT.Cli;

/// <summary>
/// Shared baseline creation and comparison used by both the CLI and the operator console.
/// Creation snapshots the observed services of one assessment and accepts exactly those finding
/// fingerprints an operator has already dispositioned through audited triage (AcceptedRisk or
/// FalsePositive) - never everything, so a baseline can not silently bless open issues.
/// Comparison is read-only over persisted rows and appends its outcome to the hash-chained
/// audit log like every other lifecycle event.
/// </summary>
public static class BaselineOperations
{
    /// <summary>Creates one baseline from an assessment's observed state and stores it.</summary>
    public static async Task<SecurityBaseline> CreateAsync(
        ActDatabase db,
        AssessmentRecord assessment,
        string name,
        string actor,
        CorrelationId correlation)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(assessment);

        var services = await db.ListServicesAsync(assessment.AssessmentId, 100_000);
        var findings = await db.ListFindingsAsync(assessment.AssessmentId, limit: 100_000);
        var accepted = findings
            .Where(static f => f.Status is FindingStatus.AcceptedRisk or FindingStatus.FalsePositive)
            .Select(static f => f.Fingerprint.Hash)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static h => h, StringComparer.Ordinal)
            .ToList();

        var expectedServices = services
            .Select(static s => new ServiceBaselineEntry(s.Port, s.Protocol, BaselineServiceStatus.Expected))
            .Distinct()
            .OrderBy(static e => e.Port)
            .ThenBy(static e => e.Protocol)
            .ToList();

        var baseline = new SecurityBaseline(
            Guid.NewGuid(),
            assessment.ScopeId,
            name,
            expectedServices,
            accepted,
            DateTimeOffset.UtcNow);
        await db.SaveBaselineAsync(baseline);
        await db.AppendAuditAsync(new AuditDraft(
            Actor: actor,
            Action: "baseline.created",
            ObjectType: "baseline",
            ObjectId: baseline.BaselineId.ToString(),
            Result: "scope " + assessment.ScopeId + "; "
                + expectedServices.Count + " expected service(s); "
                + accepted.Count + " accepted finding fingerprint(s); source assessment "
                + assessment.AssessmentId,
            Correlation: correlation));
        return baseline;
    }

    /// <summary>
    /// Marks one port/protocol as prohibited in an existing baseline (resolved like comparison:
    /// explicit id, or the scope's latest). If anything ever answers there again, drift
    /// comparison reports "unexpected service exposed" at High severity. Only an explicit
    /// operator decision may create this expectation, so the decision is audited. Marking is
    /// idempotent, and any Expected entry for the same port/protocol is superseded - a port
    /// cannot be both wanted and forbidden.
    /// </summary>
    public static async Task<SecurityBaseline> MarkProhibitedAsync(
        ActDatabase db,
        Guid assessmentId,
        Guid? baselineId,
        int port,
        ProtocolKind protocol,
        string actor,
        CorrelationId correlation)
    {
        ArgumentNullException.ThrowIfNull(db);
        if (port is < 1 or > 65535)
        {
            throw ActException.FailClosed(ErrorCategory.Configuration,
                "The baseline port must be between 1 and 65535.",
                $"MarkProhibitedAsync received port {port}.");
        }

        var assessment = await db.GetAssessmentAsync(assessmentId)
            ?? throw ActException.FailClosed(
                ErrorCategory.Persistence,
                "The assessment used to resolve the baseline was not found.",
                $"Baseline prohibition requested unknown assessment '{assessmentId}'.");
        var baseline = baselineId is { } explicitId
            ? await db.GetBaselineAsync(assessment.ScopeId, explicitId)
                ?? throw ActException.FailClosed(
                    ErrorCategory.Report,
                    "The requested baseline was not found for this scope.",
                    $"Baseline '{explicitId}' does not exist under scope '{assessment.ScopeId}'.")
            : await db.GetLatestBaselineAsync(assessment.ScopeId)
                ?? throw ActException.FailClosed(
                    ErrorCategory.Report,
                    "No security baseline exists for this scope yet; create one from a completed assessment first.",
                    $"Scope '{assessment.ScopeId}' has no stored baseline to mark prohibited.");

        var entry = new ServiceBaselineEntry(port, protocol, BaselineServiceStatus.Prohibited);
        // Supersede ANY existing entry for this port/protocol - a port cannot be both wanted
        // and forbidden, and re-marking must never accumulate duplicate prohibitions.
        var services = baseline.ExpectedServices
            .Where(e => !(e.Port == port && e.Protocol == protocol))
            .Append(entry)
            .OrderBy(static e => e.Port)
            .ThenBy(static e => e.Protocol)
            .ToList();
        if (services.SequenceEqual(baseline.ExpectedServices))
        {
            // Idempotent re-mark: nothing changes, but the operator intent is still audited.
            return baseline;
        }

        var updated = baseline with { ExpectedServices = services };
        await db.SaveBaselineAsync(updated);
        await db.AppendAuditAsync(new AuditDraft(
            Actor: actor,
            Action: "baseline.prohibited",
            ObjectType: "baseline",
            ObjectId: baseline.BaselineId.ToString(),
            Result: "port " + port + "/" + protocol + " marked prohibited; scope " + assessment.ScopeId,
            Correlation: correlation));
        return updated;
    }

    /// <summary>
    /// Compares one assessment against an explicit baseline or the scope's latest one and audits
    /// the outcome. Fails closed when either side of the comparison does not exist.
    /// </summary>
    public static async Task<BaselineComparison> CompareAsync(
        ActDatabase db,
        Guid assessmentId,
        Guid? baselineId,
        string actor,
        CorrelationId correlation)
    {
        ArgumentNullException.ThrowIfNull(db);

        var assessment = await db.GetAssessmentAsync(assessmentId)
            ?? throw ActException.FailClosed(
                ErrorCategory.Persistence,
                "The assessment to compare was not found.",
                $"Baseline comparison requested unknown assessment '{assessmentId}'.");
        SecurityBaseline? baseline;
        if (baselineId is { } explicitId)
        {
            baseline = await db.GetBaselineAsync(assessment.ScopeId, explicitId)
                ?? throw ActException.FailClosed(
                    ErrorCategory.Report,
                    "The requested baseline was not found for this scope.",
                    $"Baseline '{explicitId}' does not exist under scope '{assessment.ScopeId}'.");
        }
        else
        {
            baseline = await db.GetLatestBaselineAsync(assessment.ScopeId)
                ?? throw ActException.FailClosed(
                    ErrorCategory.Report,
                    "No security baseline exists for this scope yet; create one from a completed assessment first.",
                    $"Scope '{assessment.ScopeId}' has no stored baseline.");
        }

        var services = await db.ListServicesAsync(assessmentId, 100_000);
        var findings = await db.ListFindingsAsync(assessmentId, limit: 100_000);
        var observations = DriftAnalyzer.Compare(baseline, services)
            .Concat(DriftAnalyzer.CompareFindings(baseline, findings))
            .ToList();

        var comparison = new BaselineComparison(
            baseline.BaselineId,
            assessment.ScopeId,
            assessmentId,
            DateTimeOffset.UtcNow,
            observations);
        await db.AppendAuditAsync(new AuditDraft(
            Actor: actor,
            Action: "baseline.compared",
            ObjectType: "baseline",
            ObjectId: baseline.BaselineId.ToString(),
            Result: observations.Count + " drift observation(s) against assessment " + assessmentId,
            Correlation: correlation));
        return comparison;
    }
}
