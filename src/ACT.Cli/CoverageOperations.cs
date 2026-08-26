using ACT.Contracts;
using ACT.Persistence;
using ACT.Reporting;

namespace ACT.Cli;

/// <summary>
/// Shared check-execution coverage used by both the CLI and the operator console. Every number is
/// derived strictly from persisted rows: the check_runs ledger the engine appends to for every
/// outcome (completed, skipped, failed closed, timed out) plus stored findings for their
/// confirmation states. Coverage that cannot be grounded in a recorded execution stays at zero -
/// a report or dashboard here can never claim more testing happened than the ledger proves.
/// </summary>
public static class CoverageOperations
{
    /// <summary>Aggregated execution facts for one assessment's check ledger.</summary>
    public sealed record ExecutionSummary(
        int Executed,
        int Skipped,
        int FailedClosed,
        int TimedOut,
        long RequestsSent,
        int TargetsExamined,
        int TotalRuns);

    /// <summary>
    /// One assessment's full coverage snapshot: raw ledger rows, honest aggregates, the derived
    /// <see cref="VerificationCoverage"/> reports render, and every registered catalog check with
    /// no recorded execution in this assessment.
    /// </summary>
    public sealed record CoverageSnapshot(
        AssessmentRecord Assessment,
        IReadOnlyList<CheckRunRecord> Runs,
        ExecutionSummary Summary,
        VerificationCoverage Coverage,
        IReadOnlyList<SecurityCheckMetadata> NeverExecuted);

    /// <summary>
    /// Builds the snapshot for one assessment. Fails closed when the assessment does not exist -
    /// coverage of nothing is not zero, it is a refusal.
    /// </summary>
    public static async Task<CoverageSnapshot> BuildAsync(ActDatabase db, Guid assessmentId)
    {
        ArgumentNullException.ThrowIfNull(db);

        var assessment = await db.GetAssessmentAsync(assessmentId)
            ?? throw ActException.FailClosed(
                ErrorCategory.Report,
                "The requested assessment does not exist.",
                "Assessment '" + assessmentId + "' was not found.");

        var runs = await db.ListCheckRunsAsync(assessmentId, 100_000);
        var findings = await db.ListFindingsAsync(assessmentId, limit: 100_000);
        var neverExecuted = UnexecutedCatalogChecks(CheckRegistry.Catalog(), runs);

        return new CoverageSnapshot(
            assessment,
            runs,
            Summarize(runs),
            ComputeVerificationCoverage(runs, findings),
            neverExecuted);
    }

    /// <summary>
    /// Maps the check execution ledger onto honest verification counts:
    /// tested = executions that actually examined targets and returned a verdict;
    /// not tested = runs skipped before examining anything (not applicable, out of scope,
    /// policy denied); inaccessible = runs that timed out waiting on the target;
    /// inconclusive = runs contained by fail-closed handling, where no verdict is possible.
    /// Confirmed/inferred remain finding-level facts exactly as reports have always worded them.
    /// An empty ledger yields zeros everywhere - never fabricated counts.
    /// </summary>
    public static VerificationCoverage ComputeVerificationCoverage(
        IReadOnlyList<CheckRunRecord> runs,
        IReadOnlyList<Finding> findings)
    {
        ArgumentNullException.ThrowIfNull(runs);
        ArgumentNullException.ThrowIfNull(findings);

        return new VerificationCoverage(
            Tested: runs.Count(static r => r.Status
                is CheckExecutionStatus.Completed or CheckExecutionStatus.CompletedWithWarnings),
            NotTested: runs.Count(static r => r.Status
                is CheckExecutionStatus.Skipped_NotApplicable
                    or CheckExecutionStatus.Skipped_OutOfScope
                    or CheckExecutionStatus.Skipped_PolicyDenied),
            Inaccessible: runs.Count(static r => r.Status == CheckExecutionStatus.TimedOut),
            Inconclusive: runs.Count(static r => r.Status == CheckExecutionStatus.Failed_FailedClosed),
            Confirmed: findings.Count(static f => f.Status == FindingStatus.Confirmed),
            Inferred: findings.Count(static f => f.Confidence != ConfidenceLevel.High));
    }

    /// <summary>
    /// One-line honest summary of the verification counts for text operator surfaces. Worded
    /// exactly like the report formatters' own coverage line so CLI, console, and rendered
    /// reports never disagree about what the numbers mean.
    /// </summary>
    public static string VerificationCountsLine(VerificationCoverage coverage) =>
        "tested " + coverage.Tested + ", not tested " + coverage.NotTested
        + ", inaccessible " + coverage.Inaccessible + ", inconclusive " + coverage.Inconclusive
        + ", confirmed " + coverage.Confirmed + ", inferred " + coverage.Inferred;

    /// <summary>Plain aggregates over the ledger for cards and text summaries.</summary>
    public static ExecutionSummary Summarize(IReadOnlyList<CheckRunRecord> runs)
    {
        ArgumentNullException.ThrowIfNull(runs);

        return new ExecutionSummary(
            Executed: runs.Count(static r => r.Status
                is CheckExecutionStatus.Completed or CheckExecutionStatus.CompletedWithWarnings),
            Skipped: runs.Count(static r => r.Status
                is CheckExecutionStatus.Skipped_NotApplicable
                    or CheckExecutionStatus.Skipped_OutOfScope
                    or CheckExecutionStatus.Skipped_PolicyDenied),
            FailedClosed: runs.Count(static r => r.Status == CheckExecutionStatus.Failed_FailedClosed),
            TimedOut: runs.Count(static r => r.Status == CheckExecutionStatus.TimedOut),
            RequestsSent: runs.Sum(static r => r.RequestCount),
            TargetsExamined: runs.Sum(static r => r.TargetsExamined),
            TotalRuns: runs.Count);
    }

    /// <summary>
    /// Registered built-in checks with no recorded execution in this assessment. The reason a
    /// check never ran (planning exclusion, unsupported target kind) is intentionally NOT guessed
    /// here - the row says only what the ledger proves: nothing was recorded.
    /// </summary>
    public static IReadOnlyList<SecurityCheckMetadata> UnexecutedCatalogChecks(
        IReadOnlyList<SecurityCheckMetadata> catalog,
        IReadOnlyList<CheckRunRecord> runs)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        ArgumentNullException.ThrowIfNull(runs);

        var executed = runs.Select(static r => r.CheckId).ToHashSet(StringComparer.Ordinal);
        return [.. catalog
            .Where(m => !executed.Contains(m.Id.Value))
            .OrderBy(m => m.Category)
            .ThenBy(m => m.Id.Value, StringComparer.Ordinal)];
    }
}
