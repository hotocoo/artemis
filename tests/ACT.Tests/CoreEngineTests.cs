
using ACT.Contracts;
using ACT.Core;
using Xunit;

namespace ACT.Tests;

public class CronScheduleTests
{
    [Fact]
    public void EveryFiveMinutesAdvancesToNextMultiple()
    {
        Assert.True(CronSchedule.TryParse("*/5 * * * *", out var s1));
        var next = s1.NextOccurrence(new DateTimeOffset(2025, 1, 1, 0, 0, 0, TimeSpan.Zero));
        Assert.Equal(new DateTimeOffset(2025, 1, 1, 0, 5, 0, TimeSpan.Zero), next);
    }

    [Fact]
    public void DailyAtTwoThirtyRollsToNextDay()
    {
        Assert.True(CronSchedule.TryParse("30 2 * * *", out var s2));
        var after = new DateTimeOffset(2025, 6, 15, 23, 10, 0, TimeSpan.Zero);
        Assert.Equal(new DateTimeOffset(2025, 6, 16, 2, 30, 0, TimeSpan.Zero), s2.NextOccurrence(after));
    }

    [Fact]
    public void WeekdayOnlySkipsWeekend()
    {
        Assert.True(CronSchedule.TryParse("0 9 * * 1-5", out var s3));
        var saturdayNoon = new DateTimeOffset(2025, 6, 14, 12, 0, 0, TimeSpan.Zero);
        var mondayNine = new DateTimeOffset(2025, 6, 16, 9, 0, 0, TimeSpan.Zero);
        Assert.Equal(mondayNine, s3.NextOccurrence(saturdayNoon));
    }

    [Fact]
    public void EveryFiveMinutesMatchesExactly()
    {
        Assert.True(CronSchedule.TryParse("*/5 * * * *", out var s));
        Assert.True(s.Matches(new DateTimeOffset(2030, 3, 4, 10, 55, 0, TimeSpan.Zero)));
        Assert.False(s.Matches(new DateTimeOffset(2030, 3, 4, 10, 54, 0, TimeSpan.Zero)));
    }

    [Fact]
    public void DomDowOrRuleAppliesWhenBothRestricted()
    {
        // 00:00 on the 1st OR Mondays
        Assert.True(CronSchedule.TryParse("0 0 1 * 1", out var s));
        var monday = new DateTimeOffset(2030, 3, 4, 0, 0, 0, TimeSpan.Zero); // Monday March 4th
        var first = new DateTimeOffset(2030, 4, 1, 0, 0, 0, TimeSpan.Zero);
        var tuesdayNotFirst = new DateTimeOffset(2030, 3, 5, 0, 0, 0, TimeSpan.Zero);
        Assert.True(s.Matches(monday));
        Assert.True(s.Matches(first));
        Assert.False(s.Matches(tuesdayNotFirst));
    }

    [Fact]
    public void InvalidExpressionsAreRejected()
    {
        Assert.False(CronSchedule.TryParse("* * * *", out _));
        Assert.False(CronSchedule.TryParse("61 * * * *", out _));
        Assert.False(CronSchedule.TryParse("* 25 * * *", out _));
        Assert.False(CronSchedule.TryParse("* * 0 * *", out _));
    }
}

/// <summary>
/// Zone-independent due-selection checks: every fixture picks instants whose relationship
/// holds under any host time zone, because the ticker converts stored UTC to local itself.
/// </summary>
public class ScheduleTickerTests
{
    private static ScheduleDefinition MakeSchedule(string cron, DateTimeOffset? lastRunUtc) => new(
        ScheduleId: Guid.NewGuid(), Name: "unit-schedule", ScopeId: Guid.NewGuid(),
        CronExpression: cron, Trigger: ScheduleTriggerKind.Scheduled,
        Enabled: true, CreatedUtc: DateTimeOffset.UtcNow, LastRunUtc: lastRunUtc);

    [Fact]
    public void NeverRanSchedule_IsImmediatelyDue()
    {
        var decisions = ScheduleTicker.Evaluate([MakeSchedule("*/5 * * * *", null)], DateTimeOffset.Now);
        Assert.Single(decisions);
        Assert.Equal(ScheduleDueState.Due, decisions[0].State);
    }

    [Fact]
    public void DailySchedule_RanToday_IsNotDueUntilNextMidnight()
    {
        // Ran one minute ago; a daily expression cannot fire again this soon in any zone.
        var decisions = ScheduleTicker.Evaluate(
            [MakeSchedule("0 0 * * *", DateTimeOffset.Now.AddMinutes(-1))], DateTimeOffset.Now);
        Assert.Equal(ScheduleDueState.NotDue, decisions[0].State);
    }

    [Fact]
    public void DailySchedule_LastRanTwoDaysAgo_IsPastDue()
    {
        // Whatever the zone, a daily schedule missed twice must fire on the next tick.
        var decisions = ScheduleTicker.Evaluate(
            [MakeSchedule("0 0 * * *", DateTimeOffset.Now.AddDays(-2))], DateTimeOffset.Now);
        Assert.Equal(ScheduleDueState.Due, decisions[0].State);
    }

    [Fact]
    public void UnparseableExpression_IsReportedNotThrown()
    {
        var decisions = ScheduleTicker.Evaluate([MakeSchedule("61 * * * *", null)], DateTimeOffset.Now);
        Assert.Single(decisions);
        Assert.Equal(ScheduleDueState.InvalidExpression, decisions[0].State);
    }

    [Fact]
    public void InputOrder_IsPreservedAcrossDecisions()
    {
        var first = MakeSchedule("0 0 * * *", null);
        var second = MakeSchedule("not-a-cron", null);
        var third = MakeSchedule("*/10 * * * *", DateTimeOffset.Now.AddMinutes(-1));

        var decisions = ScheduleTicker.Evaluate([first, second, third], DateTimeOffset.Now);

        Assert.Equal(3, decisions.Count);
        Assert.Equal(first.ScheduleId, decisions[0].Schedule.ScheduleId);
        Assert.Equal(ScheduleDueState.Due, decisions[0].State);
        Assert.Equal(second.ScheduleId, decisions[1].Schedule.ScheduleId);
        Assert.Equal(ScheduleDueState.InvalidExpression, decisions[1].State);
        Assert.Equal(third.ScheduleId, decisions[2].Schedule.ScheduleId);
        Assert.Equal(ScheduleDueState.NotDue, decisions[2].State);
    }
}

public class FindingDeduplicatorTests
{
    private static Finding MakeFinding(string target, string resource, string findingClass, Severity severity = Severity.Low)
    {
        return FindingFactory.Create(
            Guid.NewGuid(), CheckId.From("ACT-TEST-001"), target, CheckCategory.Http,
            "T: " + resource, "D", severity, ConfidenceLevel.High, false,
            BusinessImpactLevel.Limited, "why", "how",
            new RemediationGuidance("fix", [], []),
            new FingerprintComponents(CheckId.From("ACT-TEST-001"), target, resource, findingClass));
    }

    [Fact]
    public void SameFingerprintMergesAndRefreshesLastSeen()
    {
        var first = MakeFinding("http://a.test/", "/x", "class-a");
        var second = MakeFinding("http://a.test/", "/x", "class-a");
        var dedup = new FindingDeduplicator();

        var m1 = dedup.Merge(first);
        var m2 = dedup.Merge(second);

        Assert.False(m1.WasDuplicate);
        Assert.True(m2.WasDuplicate);
        Assert.Equal(m1.Finding.FindingId, m2.Finding.FindingId);
        Assert.Single(dedup.Snapshot());
    }

    [Fact]
    public void DifferentResourceCreatesDistinctFinding()
    {
        var dedup = new FindingDeduplicator();
        dedup.Merge(MakeFinding("http://a.test/", "/x", "c"));
        dedup.Merge(MakeFinding("http://a.test/", "/y", "c"));
        Assert.Equal(2, dedup.Snapshot().Count);
    }
}

public class OrchestratorSelectionTests
{
    private sealed class AllowAllGate : ICheckGate
    {
        public GateDecision Evaluate(ScopeDefinition scope, SecurityCheckMetadata metadata) => GateDecision.Allow();
    }

    private sealed class DenyAllGate : ICheckGate
    {
        public GateDecision Evaluate(ScopeDefinition scope, SecurityCheckMetadata metadata) =>
            GateDecision.Deny("POLICY_DENIED", "Denied by test policy.");
    }

    private sealed class NoopCheck : ISecurityCheck
    {
        public NoopCheck(string id, CheckCategory category, params TargetTypeKind[] targets)
        {
            Metadata = new SecurityCheckMetadata(
                CheckId.From(id), "n", "1.0.0", category, Severity.High, SafetyLevel.Passive,
                PermissionRequirement.None, new HashSet<ProtocolKind> { ProtocolKind.Tcp },
                new HashSet<TargetTypeKind>(targets),
                new NetworkBehaviorProfile(1, 2, true, false, false),
                [EvidenceKind.NetworkObservation], false, false, "test check");
        }

        public SecurityCheckMetadata Metadata { get; }

        public Task<SecurityCheckResult> ExecuteAsync(SecurityCheckContext context, CancellationToken cancellationToken) =>
            Task.FromResult(SecurityCheckResult.Empty(Metadata, DateTimeOffset.UtcNow, CheckExecutionStatus.Completed));
    }

    private static AssetRecord HostAsset(Guid assessmentId) => new(
        Guid.NewGuid(), assessmentId, AssetKind.Host, "h", "127.0.0.1", ["127.0.0.1"],
        DateTimeOffset.UtcNow, true);

    [Fact]
    public void BudgetExhaustionExcludesWork()
    {
        var scope = ScopeDefinitionForTest();
        var accountant = new BudgetAccountant(new ResourceBudget(1, 5, 1024, 1024, 1024, 1024,
            TimeSpan.FromSeconds(1), TimeSpan.FromHours(1), 1, 3));

        var asset = HostAsset(scope.AssessmentId);
        var ctx = new SecurityCheckContext(
            null!, asset, null, null);

        var checks = new ISecurityCheck[]
        {
            new NoopCheck("ACT-A-001", CheckCategory.Network, TargetTypeKind.Localhost),
            new NoopCheck("ACT-B-002", CheckCategory.Network, TargetTypeKind.Localhost),
            new NoopCheck("ACT-C-003", CheckCategory.Network, TargetTypeKind.Localhost),
        };

        var plan = new Orchestrator(new AllowAllGate()).BuildPlan(scope, checks, [ctx], accountant);

        Assert.Equal(2, plan.Work.Count);
        Assert.Contains(plan.Exclusions, e => e.ReasonCode == "BUDGET_EXHAUSTED");
    }

    [Fact]
    public void PolicyDenialExcludesEntireCheck()
    {
        var scope = ScopeDefinitionForTest();
        var accountant = new BudgetAccountant(BigBudget());
        var ctx = new SecurityCheckContext(null!, HostAsset(scope.AssessmentId), null, null);

        var plan = new Orchestrator(new DenyAllGate()).BuildPlan(
            scope, [new NoopCheck("ACT-D-004", CheckCategory.Network, TargetTypeKind.Localhost)], [ctx], accountant);

        Assert.Empty(plan.Work);
        Assert.All(plan.Exclusions, e => Assert.Equal("POLICY_DENIED", e.ReasonCode));
    }

    [Fact]
    public void TargetKindMismatchExcluded()
    {
        var scope = ScopeDefinitionForTest();
        var accountant = new BudgetAccountant(BigBudget());
        var ctx = new SecurityCheckContext(null!, HostAsset(scope.AssessmentId), null, null);

        var plan = new Orchestrator(new AllowAllGate()).BuildPlan(
            scope, [new NoopCheck("ACT-E-005", CheckCategory.Source, TargetTypeKind.LocalSourceRepository)], [ctx], accountant);

        Assert.Empty(plan.Work);
        Assert.Contains(plan.Exclusions, e => e.ReasonCode == "TARGET_TYPE_MISMATCH");
    }

    private static ResourceBudget BigBudget() => new(4, 1000, 1024, 1024, 1024, 1024,
        TimeSpan.FromSeconds(1), TimeSpan.FromHours(1), 2, 3);

    private static ScopeDefinition ScopeDefinitionForTest() => new(
        Guid.NewGuid(), Guid.NewGuid(), "op", "org", TargetTypeKind.Localhost,
        ["localhost"], [], [ProtocolKind.Tcp], [PortRange.Single(8080)],
        10, 2, TimeSpan.FromMinutes(10), 500,
        Enum.GetValues<CheckCategory>(), [], true,
        TimeSpan.FromDays(7), RedactionPolicy.Standard, "authorized for unit testing");

}

public class RegressionGeneratorTests
{
    [Fact]
    public void CrossTenantFindingProducesDenialRegression()
    {
        var fixtures = new AuthorizationFixtureSet(
            Principals:
            [
                new TestPrincipal("p-alpha", "tenant-alpha", "user", new Dictionary<string, string> { ["Authorization"] = "Bearer alpha" }),
                new TestPrincipal("p-beta", "tenant-beta", "user", new Dictionary<string, string> { ["Authorization"] = "Bearer beta" }),
            ],
            Objects:
            [
                new ObjectFixture("i-1001", "tenant-alpha", "/authz/items/{id}"),
            ],
            Expectations: []);

        var finding = FindingFactory.Create(
            Guid.NewGuid(), CheckId.From("ACT-AUTHZ-BOLA-001"), "lab", CheckCategory.Authorization,
            "Cross-tenant read allowed", "desc", Severity.Critical, ConfidenceLevel.High, true,
            BusinessImpactLevel.Severe, "why", "how",
            new RemediationGuidance("enforce tenant filter", [], []),
            new FingerprintComponents(CheckId.From("ACT-AUTHZ-BOLA-001"), "lab", "/authz/items/i-1001", "bola-read"));

        var regression = RegressionGenerator.TryGenerate(finding, fixtures, new Uri("http://127.0.0.1:47390"));

        Assert.NotNull(regression);
        Assert.NotNull(regression!.HttpExpectation);
        Assert.Equal(HttpMethodType.Get, regression.HttpExpectation.Method);
        Assert.True(regression.HttpExpectation.ExpectedStatusMin <= 403);
        Assert.True(regression.HttpExpectation.ExpectedStatusMax >= 403);
        Assert.Contains("/authz/items/i-1001", regression.HttpExpectation.Url.ToString());
        Assert.Equal("Bearer beta", regression.HttpExpectation.PrincipalHeaders["Authorization"]);
    }

    [Fact]
    public void NonAuthorizationFindingFallsBackToCheckReplay()
    {
        var finding = FindingFactory.Create(
            Guid.NewGuid(), CheckId.From("ACT-WEB-HSTS-001"), "https://x.test", CheckCategory.Tls,
            "Missing HSTS", "d", Severity.Medium, ConfidenceLevel.High, false,
            BusinessImpactLevel.Limited, "w", "t",
            new RemediationGuidance("add header", [], []),
            new FingerprintComponents(CheckId.From("ACT-WEB-HSTS-001"), "https://x.test", "/", "hsts-missing"));

        var regression = RegressionGenerator.TryGenerate(finding, AuthorizationFixtureSet.None, new Uri("https://x.test"));
        Assert.NotNull(regression);
        Assert.True(regression!.ReplayCheck);
        Assert.Null(regression.HttpExpectation);
    }

    [Fact]
    public void RoundTripSerializationPreservesExpectation()
    {
        var fixtures = new AuthorizationFixtureSet(
            [new TestPrincipal("pa", "ta", "u", new Dictionary<string, string> { ["X-Tenant"] = "tb" }),
             new TestPrincipal("pb", "tb", "u", new Dictionary<string, string>())],
            [new ObjectFixture("o1", "ta", "/items/{id}")],
            []);
        var finding = FindingFactory.Create(
            Guid.NewGuid(), CheckId.From("ACT-AUTHZ-X-002"), "l", CheckCategory.Authorization,
            "t", "d", Severity.High, ConfidenceLevel.High, false,
            BusinessImpactLevel.Significant, "w", "h",
            new RemediationGuidance("r", [], []),
            new FingerprintComponents(CheckId.From("ACT-AUTHZ-X-002"), "l", "/items/o1", "x"));
        var regression = RegressionGenerator.TryGenerate(finding, fixtures, new Uri("http://host/"))!;

        var json = RegressionRunner.Serialize(regression);
        var restored = RegressionRunner.Deserialize(json)!;

        Assert.Equal(regression.RegressionTestId, restored.RegressionTestId);
        Assert.NotNull(restored.HttpExpectation);
        Assert.Equal(regression.HttpExpectation!.Url, restored.HttpExpectation.Url);
    }
}
