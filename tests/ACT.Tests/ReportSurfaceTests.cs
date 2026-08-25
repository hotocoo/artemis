using ACT.Cli;
using ACT.Contracts;
using ACT.Persistence;
using ACT.Reporting;
using Xunit;

namespace ACT.Tests;

/// <summary>
/// The shared report surface end to end: every format renders from persisted rows only, each
/// generation lands exactly one audited event in the hash chain, artifacts write to disk on
/// request, and every refusal fails closed - unknown assessments, stripped scopes, unknown formats.
/// </summary>
public class ReportSurfaceTests
{
    private static readonly ReportFormat[] AllFormats =
        [ReportFormat.Json, ReportFormat.Csv, ReportFormat.Markdown, ReportFormat.Html, ReportFormat.Sarif];

    [Fact]
    public async Task Generate_AllFormatsRenderFromPersistedRowsAndAuditOnceEach()
    {
        var fixture = await PersistFixture.CreateAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessment = await CreatePairedAsync(db);
            var finding = await db.UpsertFindingAsync(
                MakeFinding("rendered-issue", Severity.High, assessmentId: assessment.AssessmentId));

            foreach (var format in AllFormats)
            {
                var report = await ReportOperations.GenerateAsync(
                    db, assessment.AssessmentId, format, "tester", CorrelationId.New());
                Assert.Equal(assessment.AssessmentId, report.Assessment.AssessmentId);
                Assert.Equal(format, report.Format);
                Assert.Equal(1, report.FindingCount);
                Assert.Null(report.WrittenPath);
                Assert.False(string.IsNullOrWhiteSpace(report.Content));
                // The observed issue itself must appear whatever the serialization.
                Assert.Contains(finding.Title, report.Content, StringComparison.Ordinal);
            }

            var json = await RenderedAsync(db, assessment, ReportFormat.Json);
            Assert.Contains("\n  \"", json, StringComparison.Ordinal); // deterministic pretty printing
            var markdown = await RenderedAsync(db, assessment, ReportFormat.Markdown);
            Assert.Contains("## Executive Summary", markdown, StringComparison.Ordinal);
            var html = await RenderedAsync(db, assessment, ReportFormat.Html);
            Assert.Contains("<html lang=\"en\">", html, StringComparison.Ordinal);
            var sarif = await RenderedAsync(db, assessment, ReportFormat.Sarif);
            Assert.Contains("\"version\": \"2.1.0\"", sarif, StringComparison.Ordinal);

            // Exactly one ledger entry per generation - nine so far - and the chain still holds.
            var events = await db.ReadRecentAuditAsync(100);
            Assert.Equal(9, events.Count(static e => e.Action == "report.generated"));
            Assert.All(events.Where(static e => e.Action == "report.generated"),
                static e => Assert.Equal("assessment", e.ObjectType));
            Assert.True(await db.VerifyChainAsync());
        }
    }

    [Fact]
    public async Task Generate_WritesFileUnderOutputDirectoryAndAuditsThePath()
    {
        var fixture = await PersistFixture.CreateAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var assessment = await CreatePairedAsync(db);
            var outDir = Path.Combine(Path.GetTempPath(), "act-report-tests", Guid.NewGuid().ToString("N"));

            var report = await ReportOperations.GenerateAsync(
                db, assessment.AssessmentId, ReportFormat.Csv, "tester", CorrelationId.New(), outDir);

            Assert.NotNull(report.WrittenPath);
            Assert.True(File.Exists(report.WrittenPath));
            Assert.Equal(report.Content, await File.ReadAllTextAsync(report.WrittenPath));
            Assert.EndsWith(".csv", report.WrittenPath, StringComparison.Ordinal);

            var events = await db.ReadRecentAuditAsync(5);
            var audited = Assert.Single(events, static e => e.Action == "report.generated");
            Assert.Contains("; written ", audited.Result, StringComparison.Ordinal);

            Directory.Delete(outDir, recursive: true);
        }
    }

    [Fact]
    public async Task Generate_FailsClosedOnUnknownAssessmentOrMissingScope()
    {
        var fixture = await PersistFixture.CreateAsync();
        await using (fixture)
        {
            var db = fixture.Database;

            await Assert.ThrowsAsync<ActException>(() =>
                ReportOperations.GenerateAsync(db, Guid.NewGuid(), ReportFormat.Json, "tester", CorrelationId.New()));

            // An assessment whose stored scope was stripped cannot honestly describe itself.
            var assessment = await CreatePairedAsync(db);
            await db.ClearConfigAsync("scope:" + assessment.AssessmentId.ToString("N"));
            await Assert.ThrowsAsync<ActException>(() =>
                ReportOperations.GenerateAsync(db, assessment.AssessmentId, ReportFormat.Json, "tester", CorrelationId.New()));

            var events = await db.ReadRecentAuditAsync(10);
            Assert.DoesNotContain(events, static e => e.Action == "report.generated");
        }
    }

    [Fact]
    public void FormatMappings_ParseCaseInsensitivelyMapFilesAndFailClosed()
    {
        Assert.True(ReportOperations.TryParseFormat("json", out var json));
        Assert.Equal(ReportFormat.Json, json);
        Assert.True(ReportOperations.TryParseFormat("CSV", out var csv));
        Assert.Equal(ReportFormat.Csv, csv);
        Assert.True(ReportOperations.TryParseFormat("Markdown", out var markdown));
        Assert.Equal(ReportFormat.Markdown, markdown);
        Assert.True(ReportOperations.TryParseFormat("html", out var html));
        Assert.Equal(ReportFormat.Html, html);
        Assert.True(ReportOperations.TryParseFormat("SARIF", out var sarif));
        Assert.Equal(ReportFormat.Sarif, sarif);

        foreach (var bogus in new[] { null, "", "xml", "exe", "2" })
        {
            Assert.False(ReportOperations.TryParseFormat(bogus, out _));
        }

        var expectedExtensions = new Dictionary<ReportFormat, string>
        {
            [ReportFormat.Json] = "json", [ReportFormat.Csv] = "csv",
            [ReportFormat.Markdown] = "md", [ReportFormat.Html] = "html", [ReportFormat.Sarif] = "sarif"
        };
        var assessmentId = Guid.NewGuid();
        foreach (var (format, extension) in expectedExtensions)
        {
            Assert.Equal(extension, ReportOperations.Extension(format));
            Assert.Equal(
                format is ReportFormat.Json or ReportFormat.Sarif ? "application/json"
                    : format == ReportFormat.Csv ? "text/csv"
                    : format == ReportFormat.Markdown ? "text/markdown"
                    : "text/html",
                ReportOperations.ContentType(format));
            var fileName = ReportOperations.FileName(assessmentId, format);
            Assert.StartsWith("artemis-report-", fileName, StringComparison.Ordinal);
            Assert.EndsWith("." + extension, fileName, StringComparison.Ordinal);
            Assert.Contains(assessmentId.ToString("N")[..8], fileName, StringComparison.Ordinal);
        }

        // Unknown enum values fail closed instead of guessing an extension or MIME type.
        Assert.Throws<ActException>(() => ReportOperations.Extension((ReportFormat)999));
        Assert.Throws<ActException>(() => ReportOperations.ContentType((ReportFormat)999));
    }

    private static async Task<string> RenderedAsync(ActDatabase db, AssessmentRecord assessment, ReportFormat format) =>
        (await ReportOperations.GenerateAsync(db, assessment.AssessmentId, format, "tester", CorrelationId.New())).Content;

    private static Finding MakeFinding(
        string classification,
        Severity severity = Severity.High,
        FindingStatus status = FindingStatus.New,
        Guid? assessmentId = null) =>
        FindingFactory.Create(
            assessmentId ?? Guid.NewGuid(),
            CheckId.From("CHK-TST"),
            "svc.local:8443",
            CheckCategory.Tls,
            "Title " + classification,
            "Description " + classification,
            severity,
            ConfidenceLevel.High,
            exploitabilityIndicator: false,
            BusinessImpactLevel.Limited,
            "why it matters",
            "technical explanation",
            new RemediationGuidance("Fix it.", ["step-one"], []),
            new FingerprintComponents(CheckId.From("CHK-TST"), "target.local", "resource", classification))
        with { Status = status };

    private static ScopeDefinition MakeScope(Guid scopeId, Guid assessmentId) => new(
        ScopeId: scopeId,
        AssessmentId: assessmentId,
        OperatorIdentity: "unit-test-operator",
        Organization: "unit-test-org",
        TargetType: TargetTypeKind.Localhost,
        AllowlistedTargets: ["localhost"],
        ExcludedTargets: [],
        PermittedProtocols: [ProtocolKind.Https],
        PermittedPorts: [PortRange.Single(8443)],
        RequestsPerSecond: 5,
        ConcurrencyLimit: 2,
        MaxRuntime: TimeSpan.FromMinutes(30),
        MaxRequests: 500,
        AllowedCategories: Enum.GetValues<CheckCategory>(),
        ProhibitedCategories: [],
        EmergencyStopEnabled: true,
        EvidenceRetentionPeriod: TimeSpan.FromDays(30),
        DataRedactionPolicy: RedactionPolicy.Standard,
        AuthorizationStatement: "I am authorized to assess these targets.");

    private static AssessmentRecord MakeAssessment() => new(
        Guid.NewGuid(),
        Guid.NewGuid(),
        "report-assessment",
        AssessmentRunState.Completed,
        DateTimeOffset.UtcNow,
        DateTimeOffset.UtcNow.AddMinutes(-5),
        DateTimeOffset.UtcNow,
        "unit-test-operator",
        "unit-test-org");

    /// <summary>
    /// Creates one assessment together with its matching scope definition, seeded exactly like
    /// 'artemis assessment start' seeds it: the scopes row plus the config-store copy reports read.
    /// </summary>
    private static async Task<AssessmentRecord> CreatePairedAsync(ActDatabase db)
    {
        var assessment = MakeAssessment();
        var scope = MakeScope(assessment.ScopeId, assessment.AssessmentId);
        await db.CreateAssessmentAsync(assessment, scope);
        await db.SetConfigAsync("scope:" + assessment.AssessmentId.ToString("N"), scope);
        return assessment;
    }
}
