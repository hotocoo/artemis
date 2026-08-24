
using System.Diagnostics;
using ACT.Contracts;
using Microsoft.Extensions.Logging;

namespace ACT.Core;

/// <summary>Everything produced by one assessment run, honestly separated.</summary>
public sealed record AssessmentRunSummary(
    Guid AssessmentId,
    AssessmentRunState FinalState,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<SecurityCheckResult> CheckResults,
    int ChecksExecuted,
    int ChecksFailedOrSkipped,
    long RequestsReserved,
    TimeSpan Duration,
    IReadOnlyList<ExclusionDecision> Exclusions);

/// <summary>
/// The assessment pipeline: validate scope -> resolve targets -> discovery -> specialized checks
/// -> dedup -> risk scoring -> persistence hooks. Every stage is bounded, cancellable, and fails
/// closed on scope ambiguity.
/// </summary>
public sealed class AssessmentEngine(
    ICheckGate gate,
    IAssessmentRecorder recorder,
    IAuditSink auditSink,
    ILogger logger)
{
    public async Task<AssessmentRunSummary> RunAsync(
        AssessmentRunRequest request,
        CancellationToken externalCancellation)
    {
        var stopwatch = Stopwatch.StartNew();
        request.Scope.Validate();

        using var runtimeCts = CancellationTokenSource.CreateLinkedTokenSource(externalCancellation);
        runtimeCts.CancelAfter(request.Scope.MaxRuntime);
        var token = runtimeCts.Token;

        await auditSink.AppendAsync(new AuditDraft("operator", "assessment.started",
            "assessment", request.AssessmentId.ToString(), "ok", request.Correlation), token);

        await recorder.SetAssessmentStateAsync(request.AssessmentId, AssessmentRunState.Running, token);

        try
        {
            var accountant = new BudgetAccountant(request.Budget);
            var orchestrator = new Orchestrator(gate);

            // Discovery checks first so later stages can key off observed services.
            var orderedChecks = request.Checks
                .OrderBy(c => c.Metadata.Category == CheckCategory.Network ? 0 : 1)
                .ThenBy(c => c.Metadata.Id.Value, StringComparer.Ordinal)
                .ToList();

            var plan = orchestrator.BuildPlan(request.Scope, orderedChecks, request.Contexts, accountant);
            foreach (var exclusion in plan.Exclusions)
            {
                logger.LogDebug("Check {Check} excluded: {Reason} - {Message}",
                    exclusion.CheckId, exclusion.ReasonCode, exclusion.SafeMessage);
            }

            var results = new List<SecurityCheckResult>();
            var deduplicator = new FindingDeduplicator(request.PreexistingFindings);
            var scorer = request.Scorer;

            using var throttle = new SemaphoreSlim(Math.Max(1, request.Budget.MaxConcurrency));
            var tasks = plan.Work.Select(item => Task.Run(async () =>
            {
                await throttle.WaitAsync(token);
                try
                {
                    token.ThrowIfCancellationRequested();
                    var result = await ExecuteCheckAsync(request.AssessmentId, item, request.Correlation, token);
                    lock (results) results.Add(result);
                    await recorder.RecordCheckRunAsync(result, request.AssessmentId, token);

                    if (result.StandaloneEvidence.Count > 0)
                    {
                        await recorder.RecordEvidenceBatchAsync(result.StandaloneEvidence, token);
                    }

                    foreach (var finding in result.Findings)
                    {
                        var outcome = deduplicator.Merge(finding);
                        var scored = outcome.Finding.PriorityScore > 0 || scorer is null
                            ? outcome.Finding
                            : outcome.Finding with { PriorityScore = scorer.Score(outcome.Finding) };
                        await recorder.UpsertFindingAsync(scored, token);
                        await auditSink.AppendAsync(new AuditDraft("engine", "finding.created",
                            "finding", scored.FindingId.ToString(),
                            scored.TechnicalSeverity.ToString(), request.Correlation), token);
                    }
                }
                finally
                {
                    throttle.Release();
                }
            }, token)).ToList();

            await Task.WhenAll(tasks);

            stopwatch.Stop();
            var finalState = AssessmentRunState.Completed;
            var summary = new AssessmentRunSummary(
                request.AssessmentId,
                finalState,
                deduplicator.Snapshot().OrderByDescending(f => f.PriorityScore).ToList(),
                results,
                results.Count(r => r.Status is CheckExecutionStatus.Completed or CheckExecutionStatus.CompletedWithWarnings),
                results.Count(r => r.Status is not (CheckExecutionStatus.Completed or CheckExecutionStatus.CompletedWithWarnings)),
                accountant.RequestsReserved,
                stopwatch.Elapsed,
                plan.Exclusions);

            await recorder.SetAssessmentStateAsync(request.AssessmentId, finalState, token);
            await auditSink.AppendAsync(new AuditDraft("engine", "assessment.completed",
                "assessment", request.AssessmentId.ToString(), $"{summary.ChecksExecuted} checks",
                request.Correlation), CancellationToken.None);

            return summary;
        }
        catch (OperationCanceledException) when (!externalCancellation.IsCancellationRequested)
        {
            await recorder.SetAssessmentStateAsync(request.AssessmentId, AssessmentRunState.Stopped, CancellationToken.None);
            await auditSink.AppendAsync(new AuditDraft("engine", "assessment.stopped",
                "assessment", request.AssessmentId.ToString(), "runtime-limit-or-emergency",
                request.Correlation), CancellationToken.None);
            throw;
        }
    }

    private async Task<SecurityCheckResult> ExecuteCheckAsync(Guid assessmentId, Orchestrator.WorkItem item,
        CorrelationId correlation, CancellationToken token)
    {
        var meta = item.Check.Metadata;
        var started = DateTimeOffset.UtcNow;
        try
        {
            var result = await item.Check.ExecuteAsync(item.Context, token);
            await auditSink.AppendAsync(new AuditDraft("engine", "check.executed",
                "check", meta.Id.Value + ":" + item.Context.Asset.CanonicalTarget,
                result.Status.ToString(), correlation), token);
            return result with { CompletedUtc = DateTimeOffset.UtcNow };
        }
        catch (ActException ex)
        {
            logger.LogWarning("Check {Check} failed closed: {Detail}", meta.Id.Value, ex.DiagnosticDetail);
            return SecurityCheckResult.Empty(meta, started, CheckExecutionStatus.Failed_FailedClosed, ex.SafeMessage);
        }
        catch (OperationCanceledException)
        {
            return SecurityCheckResult.Empty(meta, started, CheckExecutionStatus.TimedOut, "Cancelled by runtime limit.");
        }
        catch (Exception ex)
        {
            // Unexpected engine bugs must never crash the whole assessment.
            logger.LogError(ex, "Check {Check} crashed", meta.Id.Value);
            return SecurityCheckResult.Empty(meta, started, CheckExecutionStatus.Failed_FailedClosed,
                "The check failed unexpectedly and was contained.");
        }
    }
}

/// <summary>Inputs for one run. Everything explicit; nothing inferred at runtime.</summary>
public sealed record AssessmentRunRequest(
    Guid AssessmentId,
    CorrelationId Correlation,
    ScopeDefinition Scope,
    ResourceBudget Budget,
    IReadOnlyList<ISecurityCheck> Checks,
    IReadOnlyList<SecurityCheckContext> Contexts,
    IReadOnlyList<Finding>? PreexistingFindings,
    IFindingScorer? Scorer);

/// <summary>Assigns a deterministic priority to findings; implemented by ACT.Risk.</summary>
public interface IFindingScorer
{
    double Score(Finding finding);
}
