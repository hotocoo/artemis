using ACT.Contracts;
using ACT.Persistence;

namespace ACT.Cli;

/// <summary>
/// Recovers assessment rows stranded by a dead process. A hard crash (kill -9, power loss,
/// OOM kill) leaves the row in a non-terminal state forever: the dashboard, reports, and
/// coverage pages would then describe a run that is neither alive nor dead, and an operator
/// reading "Running" hours later would believe work is in flight when nothing is.
///
/// The only safe rule is budget-derived. A row whose stored scope's MaxRuntime plus a grace
/// window has fully elapsed since the row was created CANNOT be a legitimate in-flight run -
/// the engine enforces that same budget on every launch - so it is marked Failed and audited.
/// Fresh rows, including ones a live process started moments ago, are never touched: two
/// processes sharing one database therefore never reconcile each other's live work.
///
/// Rows without a stored scope are skipped rather than guessed at: absence of a budget is not
/// evidence of death.
/// </summary>
public static class AssessmentReconciliation
{
    /// <summary>
    /// Grace window beyond the scope's MaxRuntime before a non-terminal row is declared orphaned.
    /// Covers shutdown latency and clock skew between the writing process and the reconciling host.
    /// </summary>
    public static readonly TimeSpan GracePeriod = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Marks provably orphaned non-terminal assessments as Failed and audits each decision.
    /// Returns the number of rows reconciled.
    /// </summary>
    public static async Task<int> ReconcileOrphansAsync(
        ActDatabase db, CancellationToken cancellationToken = default)
    {
        var reconciled = 0;
        var now = DateTimeOffset.UtcNow;

        foreach (var assessment in await db.ListAssessmentsAsync(1000, cancellationToken))
        {
            if (assessment.State is AssessmentRunState.Completed
                or AssessmentRunState.Failed
                or AssessmentRunState.Stopped
                or AssessmentRunState.EmergencyStopped)
            {
                continue;
            }

            var scope = await db.GetConfigAsync<ScopeDefinition>(
                "scope:" + assessment.AssessmentId.ToString("N"), cancellationToken);
            if (scope is null)
            {
                continue;
            }

            var deadline = assessment.CreatedUtc + scope.MaxRuntime + GracePeriod;
            if (now < deadline)
            {
                continue;
            }

            await db.UpdateAssessmentStateAsync(
                assessment.AssessmentId, AssessmentRunState.Failed, cancellationToken);
            await db.AppendAuditAsync(new AuditDraft(
                Actor: "engine",
                Action: "assessment.crash_reconciled",
                ObjectType: "assessment",
                ObjectId: assessment.AssessmentId.ToString(),
                Result: "stranded in " + assessment.State + " beyond its "
                    + (int)scope.MaxRuntime.TotalSeconds + "s budget plus grace; the owning process is gone",
                Correlation: CorrelationId.New()), cancellationToken);
            reconciled++;
        }

        return reconciled;
    }
}
