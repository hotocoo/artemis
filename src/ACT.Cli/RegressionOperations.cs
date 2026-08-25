
using ACT.Contracts;
using ACT.Core;
using ACT.Persistence;

namespace ACT.Cli;

/// <summary>
/// Shared regression-test lifecycle used by the assessment launcher, the CLI, and the operator
/// console. Capturing turns fixture-backed access-control findings into durable, machine-executable
/// re-verification tests (upserted per finding so repeated captures refresh one row instead of
/// piling duplicates); recording stores every replay verdict and advances the cadence. Only
/// HTTP-expectation regressions are ever stored - a "replay the check later" placeholder persisted
/// as a row would pretend to be executable when it is not.
/// </summary>
public static class RegressionOperations
{
    /// <summary>Cadence applied when an operator does not choose one explicitly.</summary>
    public static readonly TimeSpan DefaultCadence = TimeSpan.FromDays(7);

    /// <summary>
    /// Creates or refreshes one stored regression test per fixture-backed finding of a completed
    /// run. Returns every stored row this call produced or updated; findings without an executable
    /// template are skipped at this layer because "no executable regression exists" is the honest
    /// outcome there, not an error.
    /// </summary>
    public static async Task<IReadOnlyList<RegressionTestRecord>> CaptureForFindingsAsync(
        ActDatabase db,
        Guid assessmentId,
        IReadOnlyList<Finding> findings,
        AuthorizationFixtureSet fixtures,
        Uri? baseUrl,
        string actor,
        CorrelationId correlation)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentNullException.ThrowIfNull(fixtures);
        if (baseUrl is null || fixtures.Principals.Count < 2 || fixtures.Objects.Count == 0)
        {
            return [];
        }

        var stored = new List<RegressionTestRecord>();
        foreach (var finding in findings)
        {
            var generated = RegressionGenerator.TryGenerate(finding, fixtures, baseUrl);
            if (generated?.HttpExpectation is null)
            {
                continue;
            }

            if (await UpsertAsync(db, assessmentId, finding, generated, actor, correlation).ConfigureAwait(false)
                is { } saved)
            {
                stored.Add(saved);
            }
        }

        return stored;
    }

    /// <summary>
    /// Persists one generated regression for a single finding (the CLI 'regression run' path) and
    /// returns the stored row. Fails closed when the generator yields no executable expectation -
    /// storing a non-executable recipe would promise more than the runner can deliver.
    /// </summary>
    public static async Task<RegressionTestRecord> StoreForFindingAsync(
        ActDatabase db,
        Guid assessmentId,
        Finding finding,
        GeneratedRegression generated,
        string actor,
        CorrelationId correlation,
        TimeSpan? cadence = null)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(finding);
        ArgumentNullException.ThrowIfNull(generated);
        if (generated.HttpExpectation is null)
        {
            throw ActException.FailClosed(ErrorCategory.Configuration,
                "This finding class has no executable HTTP regression template; supply authorization "
                + "fixtures describing real principals and objects.",
                $"Regression for finding {finding.FindingId} carries no HttpRequestExpectation.");
        }

        var stored = await UpsertAsync(db, assessmentId, finding, generated, actor, correlation, cadence)
            .ConfigureAwait(false);
        return stored ?? throw ActException.FailClosed(ErrorCategory.Persistence,
            "The regression test could not be stored.",
            $"Upserting the regression for finding {finding.FindingId} produced no row.");
    }

    /// <summary>
    /// Records one executed replay verdict against its stored test: appends the run row, advances
    /// the cadence schedule, and lands an audited event either way. A FAILED replay is recorded as
    /// a confirmation that the original issue returned - it never silently flips the finding's
    /// triage status, because status changes stay explicit operator decisions.
    /// </summary>
    public static async Task<RegressionTestRunRecord> RecordRunOutcomeAsync(
        ActDatabase db,
        RegressionTestRecord test,
        RegressionRunResult result,
        string actor,
        CorrelationId correlation)
    {
        ArgumentNullException.ThrowIfNull(db);
        ArgumentNullException.ThrowIfNull(test);
        ArgumentNullException.ThrowIfNull(result);

        var state = result.Passed ? VerificationState.Tested : VerificationState.Confirmed;
        var run = await db.RecordTestRunAsync(test.RegressionTestId, result.RanUtc, state, result.DetailSafe)
            .ConfigureAwait(false);
        await db.AppendAuditAsync(new AuditDraft(
            Actor: actor,
            Action: "regression.run_recorded",
            ObjectType: "regression_test",
            ObjectId: test.RegressionTestId.ToString(),
            Result: (result.Passed ? "PASS" : "FAIL - invariant violated") + "; " + result.DetailSafe,
            Correlation: correlation)).ConfigureAwait(false);
        return run;
    }

    /// <summary>
    /// Enables or disables one stored test from an operator surface and audits the decision.
    /// Disabling pauses the cadence while keeping the row and its full run history.
    /// </summary>
    public static async Task SetEnabledAsync(
        ActDatabase db,
        Guid regressionTestId,
        bool enabled,
        string actor,
        CorrelationId correlation)
    {
        ArgumentNullException.ThrowIfNull(db);
        var test = await db.GetRegressionTestAsync(regressionTestId).ConfigureAwait(false)
            ?? throw ActException.FailClosed(ErrorCategory.Persistence,
                "The regression test to enable or disable does not exist.",
                $"No stored regression test '{regressionTestId}'.");
        await db.SetRegressionTestEnabledAsync(regressionTestId, enabled).ConfigureAwait(false);
        await db.AppendAuditAsync(new AuditDraft(
            Actor: actor,
            Action: enabled ? "regression.test_enabled" : "regression.test_disabled",
            ObjectType: "regression_test",
            ObjectId: regressionTestId.ToString(),
            Result: "'" + test.Name + "' " + (enabled ? "returned to" : "paused from") + " its "
                + FormatCadence(test.Cadence) + " verification cadence",
            Correlation: correlation)).ConfigureAwait(false);
    }

    /// <summary>Renders a cadence as a short human phrase ("every 7 day(s)").</summary>
    public static string FormatCadence(TimeSpan cadence)
    {
        if (cadence.TotalDays >= 1 && cadence.TotalDays == Math.Floor(cadence.TotalDays))
        {
            return "every " + cadence.TotalDays.ToString("0", System.Globalization.CultureInfo.InvariantCulture) + " day(s)";
        }

        if (cadence.TotalHours >= 1 && cadence.TotalHours == Math.Floor(cadence.TotalHours))
        {
            return "every " + cadence.TotalHours.ToString("0", System.Globalization.CultureInfo.InvariantCulture) + " hour(s)";
        }

        return "every " + cadence.TotalMinutes.ToString("0", System.Globalization.CultureInfo.InvariantCulture) + " minute(s)";
    }

    /// <summary>
    /// Upserts by finding identity: the first capture creates the durable test; later captures of
    /// the same finding refresh name, description, severity, and recipe while preserving the
    /// operator's cadence, enabled flag, and run history.
    /// </summary>
    private static async Task<RegressionTestRecord?> UpsertAsync(
        ActDatabase db,
        Guid assessmentId,
        Finding finding,
        GeneratedRegression generated,
        string actor,
        CorrelationId correlation,
        TimeSpan? cadence = null)
    {
        var existing = await db.GetRegressionTestForFindingAsync(finding.FindingId).ConfigureAwait(false);
        var recipeJson = RegressionRunner.Serialize(generated);
        if (existing is { } keep)
        {
            var refreshed = keep with
            {
                Name = generated.Title,
                Description = generated.ExpectedOutcomeSummary,
                SuggestedSeverity = finding.TechnicalSeverity,
                RecipeJson = recipeJson
            };
            await db.SaveRegressionTestAsync(refreshed).ConfigureAwait(false);
            await db.AppendAuditAsync(new AuditDraft(
                Actor: actor,
                Action: "regression.test_updated",
                ObjectType: "regression_test",
                ObjectId: keep.RegressionTestId.ToString(),
                Result: "recipe refreshed from finding " + finding.FindingId,
                Correlation: correlation)).ConfigureAwait(false);
            return refreshed;
        }

        var createdUtc = DateTimeOffset.UtcNow;
        var effectiveCadence = cadence ?? DefaultCadence;
        var created = new RegressionTestRecord(
            generated.RegressionTestId,
            assessmentId,
            finding.FindingId,
            generated.Title,
            generated.ExpectedOutcomeSummary,
            finding.TechnicalSeverity,
            effectiveCadence,
            Enabled: true,
            createdUtc,
            LastRunUtc: null,
            NextRunUtc: default,
            RecipeJson: recipeJson);
        await db.SaveRegressionTestAsync(created).ConfigureAwait(false);
        await db.AppendAuditAsync(new AuditDraft(
            Actor: actor,
            Action: "regression.test_created",
            ObjectType: "regression_test",
            ObjectId: created.RegressionTestId.ToString(),
            Result: "'" + generated.Title + "' from finding " + finding.FindingId
                + "; cadence " + FormatCadence(effectiveCadence),
            Correlation: correlation)).ConfigureAwait(false);
        return created;
    }
}
