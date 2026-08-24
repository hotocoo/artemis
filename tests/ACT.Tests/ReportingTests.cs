using System.Text;
using System.Text.Json;
using ACT.Contracts;
using ACT.Reporting;
using Xunit;

namespace ACT.Tests;

/// <summary>Covers every report formatter plus the assembler.</summary>
public class ReportFormattingTests
{
    private static readonly DateTimeOffset Stamp = new(2035, 1, 1, 12, 30, 0, TimeSpan.Zero);

    private static ScopeDefinition Scope() => new(
        ScopeId: Guid.NewGuid(),
        AssessmentId: Guid.NewGuid(),
        OperatorIdentity: "report-operator",
        Organization: "report-org",
        TargetType: TargetTypeKind.Hostname,
        AllowlistedTargets: ["localhost", "svc.internal"],
        ExcludedTargets: ["forbidden.internal"],
        PermittedProtocols: [ProtocolKind.Http, ProtocolKind.Https],
        PermittedPorts: [PortRange.Single(443), PortRange.Single(8080)],
        RequestsPerSecond: 5,
        ConcurrencyLimit: 2,
        MaxRuntime: TimeSpan.FromMinutes(30),
        MaxRequests: 500,
        AllowedCategories: [CheckCategory.Http, CheckCategory.Network],
        ProhibitedCategories: [],
        EmergencyStopEnabled: true,
        EvidenceRetentionPeriod: TimeSpan.FromDays(30),
        DataRedactionPolicy: RedactionPolicy.Standard,
        AuthorizationStatement: "Authorized by the asset owner.");

    private static AssessmentRecord Assessment() => new(
        Guid.NewGuid(),
        Guid.NewGuid(),
        "Edge Gateway Audit",
        AssessmentRunState.Completed,
        Stamp.AddHours(-1),
        Stamp.AddMinutes(-30),
        Stamp,
        "report-operator",
        "report-org");

    private static Finding Finding(
        string title,
        Severity severity = Severity.High,
        string check = "NET-OPEN-TLS",
        string target = "https://svc.internal/api",
        FindingStatus status = FindingStatus.New,
        string fingerprint = "",
        double priority = 50,
        Guid? regressionTestId = null) => new(
        Guid.NewGuid(),
        Guid.NewGuid(),
        CheckId.From(check),
        target,
        AssetReference: null,
        CheckCategory.Network,
        title,
        "TLS configuration weakness observed on the endpoint.",
        severity,
        ConfidenceLevel.High,
        ConfidenceScore: 0.9,
        ExploitabilityIndicator: severity >= Severity.High,
        BusinessImpactLevel.Limited,
        WhyItMatters: "Legacy TLS allows downgrade attacks.",
        TechnicalExplanation: "Server negotiates TLS 1.0.",
        new RemediationGuidance(
            "Disable legacy TLS versions.",
            ["Update server TLS policy.", "Retest the endpoint."],
            ["https://fixtures.example/internal-tls-guide"]),
        FirstSeenUtc: Stamp.AddDays(-1),
        LastSeenUtc: Stamp,
        status,
        new FindingFingerprint(fingerprint.Length > 0 ? fingerprint : ComputeFingerprint(check, target, title)),
        regressionTestId,
        CvssVector: null,
        CvssBaseScore: null)
        { PriorityScore = priority };

    private static string ComputeFingerprint(string check, string target, string findingClass) =>
        FindingFingerprinter.Fingerprint(new FingerprintComponents(CheckId.From(check), target, "", findingClass)).Hash;

    private static EvidenceItem Evidence(Finding finding) => new(
        Guid.NewGuid(),
        finding.FindingId,
        EvidenceKind.StatusCode,
        "status_code",
        "200",
        Stamp.AddMinutes(-5),
        finding.CheckId,
        CorrelationId.New(),
        new Dictionary<string, string>());

    private static FindingWithEvidence Item(Finding finding, params EvidenceItem[] evidence) =>
        new(finding, evidence);

    private static ReportInput Input(params FindingWithEvidence[] items) => ReportInput.Create(
        Assessment(),
        Scope(),
        items,
        metrics: new ScanMetricsRecord(Guid.NewGuid(), 120, 14, 1, items.Length, TimeSpan.FromMinutes(12), 45_678),
        coverage: new VerificationCoverage(Tested: 3, NotTested: 1, Inaccessible: 2, Inconclusive: 4, Confirmed: 5, Inferred: 6),
        limitations: "Only the primary interface was reachable during the window.",
        generatedUtc: Stamp);

    private static ReportAssembler Assembler() => new();

    private static async Task<string> Render(ReportInput input, ReportFormat format)
    {
        var text = await Assembler().RenderAsync(input, format, CancellationToken.None);
        Assert.False(string.IsNullOrEmpty(text));
        return text;
    }

    private static async Task<JsonDocument> RenderDocument(ReportInput input, ReportFormat format)
    {
        var text = await Render(input, format);
        return JsonDocument.Parse(text);
    }

    // ---------- CSV ----------

    [Fact]
    public async Task CsvHeaderMatchesContractColumnOrder()
    {
        var csv = await Render(Input(Item(Finding("Probe"))), ReportFormat.Csv);
        Assert.StartsWith("id,title,severity,confidence,status,target,category,first_seen,last_seen,fingerprint,priority_score\r\n", csv, StringComparison.Ordinal);
    }

    [Fact]
    public async Task CsvEscapesCommasQuotesAndNewlinesAndRoundTrips()
    {
        var hostileTitle = "He said \"run, now\"\nsecond,line";
        var input = Input(Item(Finding(hostileTitle, target: "host,with,commas")));
        var csv = await Render(input, ReportFormat.Csv);

        var rows = ParseCsv(csv);
        Assert.True(rows.Length == 2, "expected one header row plus one data row");
        Assert.True(rows[0].Length == 11, "header must carry all 11 contract columns");
        var dataRow = rows[1];
        Assert.True(dataRow.Length == 11, "data row must carry all 11 contract columns");
        Assert.Equal("id", rows[0][0]);
        Assert.Equal("title", rows[0][1]);
        Assert.Equal("fingerprint", rows[0][9]);
        Assert.Equal("priority_score", rows[0][10]);
        Assert.Equal(hostileTitle, dataRow[1]);
        Assert.Equal("host,with,commas", dataRow[5]);
    }

    [Fact]
    public async Task CsvQuotesOnlyWhenRfc4180RequiresIt()
    {
        var csv = await Render(Input(Item(Finding("Plain Title"))), ReportFormat.Csv);
        var dataLine = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries)[1];
        Assert.DoesNotContain("\"", dataLine, StringComparison.Ordinal);
    }

    // ---------- SARIF ----------

    [Fact]
    public async Task SarifHasRequiredKeysAndArtemisDriver()
    {
        var finding = Finding("Weak cipher suite", fingerprint: "abc123def456");
        using var doc = await RenderDocument(Input(Item(finding, Evidence(finding))), ReportFormat.Sarif);

        Assert.Equal("2.1.0", doc.RootElement.GetProperty("version").GetString());
        var run = doc.RootElement.GetProperty("runs")[0];
        Assert.Equal("Artemis", run.GetProperty("tool").GetProperty("driver").GetProperty("name").GetString());

        var result = run.GetProperty("results")[0];
        Assert.Equal(finding.CheckId.Value, result.GetProperty("ruleId").GetString());
        Assert.True(result.TryGetProperty("message", out var message));
        Assert.Contains(finding.Title, message.GetProperty("text").GetString(), StringComparison.Ordinal);
        Assert.Contains(finding.Description, message.GetProperty("text").GetString(), StringComparison.Ordinal);
        Assert.Equal("abc123def456", result.GetProperty("fingerprints").GetProperty("primaryLocation").GetString());
    }

    [Theory]
    [InlineData(Severity.Critical, "error")]
    [InlineData(Severity.High, "error")]
    [InlineData(Severity.Medium, "warning")]
    [InlineData(Severity.Low, "note")]
    [InlineData(Severity.Informational, "note")]
    public async Task SarifMapsSeverityToLevel(Severity severity, string expectedLevel)
    {
        using var doc = await RenderDocument(Input(Item(Finding("Level probe", severity))), ReportFormat.Sarif);
        var level = doc.RootElement.GetProperty("runs")[0].GetProperty("results")[0].GetProperty("level").GetString();
        Assert.Equal(expectedLevel, level);
    }

    [Fact]
    public async Task SarifNonUriTargetFallsBackToLogicalLocations()
    {
        using var doc = await RenderDocument(Input(Item(Finding("Open database port", target: "10.20.30.40:5432"))), ReportFormat.Sarif);
        var location = doc.RootElement.GetProperty("runs")[0].GetProperty("results")[0].GetProperty("locations")[0];

        Assert.False(location.TryGetProperty("physicalLocation", out _));
        Assert.Equal("10.20.30.40:5432", location.GetProperty("logicalLocations")[0].GetProperty("name").GetString());
    }

    [Fact]
    public async Task SarifUriTargetUsesArtifactLocationUri()
    {
        using var doc = await RenderDocument(Input(Item(Finding("Insecure endpoint"))), ReportFormat.Sarif);
        var location = doc.RootElement.GetProperty("runs")[0].GetProperty("results")[0].GetProperty("locations")[0];

        Assert.False(location.TryGetProperty("logicalLocations", out _));
        Assert.Equal("https://svc.internal/api", location.GetProperty("physicalLocation").GetProperty("artifactLocation").GetProperty("uri").GetString());
    }

    [Fact]
    public async Task SarifDedupesRulesByCheckId()
    {
        var input = Input(
            Item(Finding("Alpha", check: "NET-001")),
            Item(Finding("Beta", check: "NET-001")),
            Item(Finding("Gamma", check: "TLS-002")));
        using var doc = await RenderDocument(input, ReportFormat.Sarif);

        var driver = doc.RootElement.GetProperty("runs")[0].GetProperty("tool").GetProperty("driver");
        var rules = driver.GetProperty("rules");
        Assert.Equal(2, rules.GetArrayLength());

        foreach (var result in doc.RootElement.GetProperty("runs")[0].GetProperty("results").EnumerateArray())
        {
            var referenced = rules[result.GetProperty("ruleIndex").GetInt32()].GetProperty("id").GetString();
            Assert.Equal(referenced, result.GetProperty("ruleId").GetString());
        }
    }

    // ---------- Markdown ----------

    [Fact]
    public async Task MarkdownContainsAllRequiredSectionsInOrder()
    {
        var markdown = await Render(Input(Item(Finding("Section probe"))), ReportFormat.Markdown);

        Assert.Contains("## Executive Summary", markdown, StringComparison.Ordinal);
        Assert.Contains("## Risk Summary", markdown, StringComparison.Ordinal);
        Assert.Contains("## Technical Findings", markdown, StringComparison.Ordinal);
        Assert.Contains("## Remediation Plan", markdown, StringComparison.Ordinal);
        Assert.Contains("## Regression Coverage", markdown, StringComparison.Ordinal);
        Assert.Contains("## Assessment Scope", markdown, StringComparison.Ordinal);
        Assert.Contains("## Coverage & Limitations", markdown, StringComparison.Ordinal);
        Assert.Contains("### High", markdown, StringComparison.Ordinal);

        var positions = new[]
        {
            markdown.IndexOf("## Executive Summary", StringComparison.Ordinal),
            markdown.IndexOf("## Risk Summary", StringComparison.Ordinal),
            markdown.IndexOf("## Technical Findings", StringComparison.Ordinal),
            markdown.IndexOf("## Remediation Plan", StringComparison.Ordinal),
            markdown.IndexOf("## Regression Coverage", StringComparison.Ordinal),
            markdown.IndexOf("## Assessment Scope", StringComparison.Ordinal),
            markdown.IndexOf("## Coverage & Limitations", StringComparison.Ordinal),
        };
        Assert.All(positions, position => Assert.True(position >= 0));
        Assert.True(positions.SequenceEqual(positions.Order()), "sections should appear in contract order");

        Assert.Contains("tested 3, not tested 1, inaccessible 2, inconclusive 4, confirmed 5, inferred 6", markdown, StringComparison.Ordinal);
    }

    [Fact]
    public async Task MarkdownRemediationPlanOrdersByPriorityScore()
    {
        var lowPriority = Finding("Patch later", Severity.Low, priority: 10);
        var highPriority = Finding("Patch now", Severity.Critical, priority: 99);
        var markdown = await Render(Input(Item(lowPriority), Item(highPriority)), ReportFormat.Markdown);

        Assert.True(markdown.IndexOf("Patch now", StringComparison.Ordinal) < markdown.IndexOf("Patch later", StringComparison.Ordinal));
    }

    // ---------- HTML ----------

    [Fact]
    public async Task HtmlEscapesHostileTitlesAndStaysStandaloneHtml5()
    {
        var html = await Render(Input(Item(Finding("<script>alert('x')</script>"))), ReportFormat.Html);

        Assert.StartsWith("<!DOCTYPE html>", html, StringComparison.Ordinal);
        Assert.Contains("<html lang=\"en\">", html, StringComparison.Ordinal);
        Assert.Contains("charset=\"utf-8\"", html, StringComparison.Ordinal);
        Assert.EndsWith("</html>" + Environment.NewLine, html, StringComparison.Ordinal);

        Assert.DoesNotContain("<script>alert", html, StringComparison.Ordinal);
        Assert.Contains("&lt;script&gt;", html, StringComparison.Ordinal);
        Assert.Contains("alert(&#39;x&#39;)", html, StringComparison.Ordinal);

        foreach (var section in new[] { "Executive Summary", "Risk Summary", "Technical Findings", "Remediation Plan", "Regression Coverage", "Assessment Scope" })
        {
            Assert.Contains(section, html, StringComparison.Ordinal);
        }
    }

    // ---------- JSON ----------

    [Fact]
    public async Task JsonRenderIsDeterministicAcrossItemOrderAndRepeats()
    {
        var firstFinding = Finding("Alpha", check: "CHK-A");
        var alpha = Item(firstFinding, Evidence(firstFinding));
        var beta = Item(Finding("Beta", check: "CHK-B"));

        // One shared assessment/scope/metrics identity; only the item order flips.
        var assessment = Assessment();
        var scope = Scope();
        var metrics = new ScanMetricsRecord(assessment.AssessmentId, 120, 14, 1, 2, TimeSpan.FromMinutes(12), 45_678);
        var coverage = new VerificationCoverage(Tested: 3, NotTested: 1, Inaccessible: 2, Inconclusive: 4, Confirmed: 5, Inferred: 6);
        const string limitations = "Only the primary interface was reachable during the window.";

        var forward = ReportInput.Create(assessment, scope, [alpha, beta], metrics, coverage, limitations, Stamp);
        var backward = ReportInput.Create(assessment, scope, [beta, alpha], metrics, coverage, limitations, Stamp);

        var assembler = Assembler();
        var jsonA = await assembler.RenderAsync(forward, ReportFormat.Json, CancellationToken.None);
        var jsonB = await assembler.RenderAsync(forward, ReportFormat.Json, CancellationToken.None);
        var jsonReversed = await assembler.RenderAsync(backward, ReportFormat.Json, CancellationToken.None);

        Assert.Equal(jsonA, jsonB);
        Assert.Equal(jsonA, jsonReversed);
    }

    [Fact]
    public async Task JsonIsPrettyPrintedWithStringEnumsAndParsesBack()
    {
        var json = await Render(Input(Item(Finding("Gamma", Severity.Medium))), ReportFormat.Json);

        Assert.Contains("\n  \"", json, StringComparison.Ordinal);
        using var doc = JsonDocument.Parse(json);
        var findings = doc.RootElement.GetProperty("findings");
        Assert.Equal(1, findings.GetArrayLength());
        Assert.Equal("Medium", findings[0].GetProperty("severity").GetString());
        Assert.Equal("NET-OPEN-TLS", findings[0].GetProperty("checkId").GetString());
    }

    // ---------- Assembler ----------

    [Fact]
    public async Task AssembleFileWritesSlugifiedTimestampedFileWithRenderedContent()
    {
        var directory = Path.Combine(Path.GetTempPath(), "artemis-report-tests", Guid.NewGuid().ToString("N"));
        try
        {
            var input = Input(Item(Finding("Write probe")));
            var path = await Assembler().AssembleFileAsync(directory, input, ReportFormat.Csv, CancellationToken.None);

            var name = Path.GetFileName(path);
            Assert.StartsWith("edge-gateway-audit-", name, StringComparison.Ordinal);
            Assert.EndsWith("-20350101T123000Z.csv", name, StringComparison.Ordinal);
            Assert.True(File.Exists(path));

            var expected = await Assembler().RenderAsync(input, ReportFormat.Csv, CancellationToken.None);
            Assert.Equal(expected, await File.ReadAllTextAsync(path));
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(directory, recursive: true);
            }
        }
    }

    [Fact]
    public async Task AssemblerDispatchesEveryFormatWithCorrectMetadata()
    {
        var assembler = Assembler();
        var input = Input(Item(Finding("Dispatch probe")));

        var json = await assembler.RenderAsync(input, ReportFormat.Json, CancellationToken.None);
        Assert.StartsWith("{", json, StringComparison.Ordinal);
        Assert.Equal("application/json; charset=utf-8", new JsonReportFormatter().ContentType);
        Assert.Equal("json", new JsonReportFormatter().FileExtension);

        var csv = await assembler.RenderAsync(input, ReportFormat.Csv, CancellationToken.None);
        Assert.StartsWith("id,title,", csv, StringComparison.Ordinal);
        Assert.Equal("csv", new CsvReportFormatter().FileExtension);

        var markdown = await assembler.RenderAsync(input, ReportFormat.Markdown, CancellationToken.None);
        Assert.StartsWith("# ", markdown, StringComparison.Ordinal);
        Assert.Equal("md", new MarkdownReportFormatter().FileExtension);

        var html = await assembler.RenderAsync(input, ReportFormat.Html, CancellationToken.None);
        Assert.StartsWith("<!DOCTYPE html>", html, StringComparison.Ordinal);
        Assert.Equal("html", new HtmlReportFormatter().FileExtension);

        var sarif = await assembler.RenderAsync(input, ReportFormat.Sarif, CancellationToken.None);
        Assert.Contains("\"version\": \"2.1.0\"", sarif, StringComparison.Ordinal);
        Assert.Equal("sarif", new SarifReportFormatter().FileExtension);
    }

    /// <summary>Minimal RFC 4180 reader used only to prove round-tripping of hostile values.</summary>
    private static string[][] ParseCsv(string text)
    {
        var rows = new List<string[]>();
        var row = new List<string>();
        var field = new StringBuilder();
        var inQuotes = false;
        for (var index = 0; index < text.Length; index++)
        {
            var character = text[index];
            if (inQuotes)
            {
                if (character == '"')
                {
                    if (index + 1 < text.Length && text[index + 1] == '"')
                    {
                        field.Append('"');
                        index++;
                    }
                    else
                    {
                        inQuotes = false;
                    }
                }
                else
                {
                    field.Append(character);
                }
            }
            else if (character == '"')
            {
                inQuotes = true;
            }
            else if (character == ',')
            {
                row.Add(field.ToString());
                field.Clear();
            }
            else if (character == '\n')
            {
                row.Add(field.ToString());
                field.Clear();
                rows.Add([.. row]);
                row.Clear();
            }
            else if (character != '\r')
            {
                field.Append(character);
            }
        }

        if (field.Length > 0 || row.Count > 0)
        {
            row.Add(field.ToString());
            rows.Add([.. row]);
        }

        return [.. rows];
    }
}

/// <summary>Covers CI gate decisions.</summary>
public class ReportGateTests
{
    private static readonly DateTimeOffset Stamp = new(2035, 6, 1, 8, 0, 0, TimeSpan.Zero);

    private static ReportInput Input(params Finding[] findings) => ReportInput.Create(
        new AssessmentRecord(Guid.NewGuid(), Guid.NewGuid(), "Gate Run", AssessmentRunState.Completed, Stamp, null, null, "op", "org"),
        Scope(),
        findings.Select(f => new FindingWithEvidence(f, [])).ToList(),
        generatedUtc: Stamp);

    private static ScopeDefinition Scope() => new(
        Guid.NewGuid(), Guid.NewGuid(), "op", "org", TargetTypeKind.Hostname,
        ["localhost"], [], [ProtocolKind.Https], [PortRange.Single(443)],
        5, 2, TimeSpan.FromMinutes(10), 100,
        [CheckCategory.Network], [], true, TimeSpan.FromDays(7), RedactionPolicy.Standard,
        "Authorized.");

    private static Finding Finding(string fingerprint, Severity severity = Severity.High, FindingStatus status = FindingStatus.New) => new(
        Guid.NewGuid(), Guid.NewGuid(), CheckId.From("GATE-CHECK"), "gate-target",
        AssetReference: null, CheckCategory.Network, "Finding " + fingerprint,
        "description", severity, ConfidenceLevel.High, ConfidenceScore: 0.9,
        ExploitabilityIndicator: false, BusinessImpactLevel.Limited, "why", "technical",
        new RemediationGuidance("fix", [], []),
        Stamp, Stamp, status, new FindingFingerprint(fingerprint), RegressionTestId: null,
        CvssVector: null, CvssBaseScore: null)
    { PriorityScore = 50 };

    [Fact]
    public void NewHighFindingFailsTheBuild()
    {
        var current = Input(Finding("fp-new-high"));
        var decision = CiGate.Evaluate(new CiGateOptions(), [], current);

        Assert.True(decision.ShouldFailBuild);
        Assert.Single(decision.TriggeringFindings);
        Assert.Single(decision.Reasons);
        Assert.Contains("NEW:", decision.Reasons[0], StringComparison.Ordinal);
        Assert.Contains("fp-new-high", decision.Reasons[0], StringComparison.Ordinal);
    }

    [Fact]
    public void BaselineAcceptedFingerprintPassesEvenWhenHigh()
    {
        var current = Input(Finding("fp-new-high"));
        var options = new CiGateOptions { BaselineAcceptedFingerprints = ["fp-new-high"] };
        var decision = CiGate.Evaluate(options, [], current);

        Assert.False(decision.ShouldFailBuild);
        Assert.Empty(decision.TriggeringFindings);
        Assert.Empty(decision.Reasons);
    }

    [Fact]
    public void PreviouslySeenFingerprintDoesNotFail()
    {
        var seen = Finding("fp-seen");
        var current = Input(seen);
        var decision = CiGate.Evaluate(new CiGateOptions(), [seen], current);

        Assert.False(decision.ShouldFailBuild);
    }

    [Fact]
    public void ReobservedPreviouslyRemediatedFingerprintTriggersFailure()
    {
        var remediatedBefore = Finding("fp-old", status: FindingStatus.Remediated);
        var reobserved = Finding("fp-old");
        var decision = CiGate.Evaluate(new CiGateOptions(), [remediatedBefore], Input(reobserved));

        Assert.True(decision.ShouldFailBuild);
        Assert.Contains("REGRESSION:", decision.Reasons[0], StringComparison.Ordinal);
        Assert.Equal("fp-old", decision.TriggeringFindings.Single().Fingerprint.Hash);
    }

    [Fact]
    public void StatusRegressedNowTriggersFailureWithoutHistory()
    {
        var regressed = Finding("fp-regressed-unseen", Severity.Low, FindingStatus.Regressed);
        var decision = CiGate.Evaluate(new CiGateOptions(), [], Input(regressed));

        Assert.True(decision.ShouldFailBuild);
        Assert.Contains("REGRESSION:", decision.Reasons[0], StringComparison.Ordinal);
    }

    [Fact]
    public void FailOnRegressionsFalseIgnoresRegressions()
    {
        var regressed = Finding("fp-regressed-low", Severity.Low, FindingStatus.Regressed);
        var options = new CiGateOptions { FailOnRegressions = false };
        var decision = CiGate.Evaluate(options, [], Input(regressed));

        Assert.False(decision.ShouldFailBuild);
    }

    [Fact]
    public void NewFindingBelowThresholdPasses()
    {
        var informational = Finding("fp-info", Severity.Informational);
        var decision = CiGate.Evaluate(new CiGateOptions(), [], Input(informational));

        Assert.False(decision.ShouldFailBuild);
    }
}

/// <summary>Covers baseline drift detection.</summary>
public class ReportDriftTests
{
    private static readonly DateTimeOffset Stamp = new(2035, 9, 9, 9, 9, 0, TimeSpan.Zero);

    private static SecurityBaseline Baseline(params ServiceBaselineEntry[] entries) => new(
        Guid.NewGuid(), Guid.NewGuid(), "prod-baseline", entries, [], Stamp);

    private static ServiceObservation Observed(int port, ProtocolKind protocol = ProtocolKind.Tcp) => new(
        Guid.NewGuid(), Guid.NewGuid(), port, protocol,
        Banner: null, TlsNegotiated: false, Stamp, CheckId.From("NET-SCAN"));

    [Fact]
    public void ProhibitedPortObservedYieldsHighUnexpectedServiceExposed()
    {
        var baseline = Baseline(
            new ServiceBaselineEntry(443, ProtocolKind.Tcp, BaselineServiceStatus.Expected),
            new ServiceBaselineEntry(8080, ProtocolKind.Tcp, BaselineServiceStatus.Prohibited));
        var observations = new[] { Observed(443), Observed(8080) };

        var drift = DriftAnalyzer.Compare(baseline, observations);

        var exposed = Assert.Single(drift, d => d.Kind == "unexpected-service-exposed");
        Assert.Equal(Severity.High, exposed.SuggestedSeverity);
        Assert.StartsWith("Unexpected service exposed", exposed.Detail, StringComparison.Ordinal);
        Assert.Contains("8080", exposed.Detail, StringComparison.Ordinal);
        Assert.False(string.IsNullOrWhiteSpace(exposed.FingerprintSuffix));

        var repeat = DriftAnalyzer.Compare(baseline, observations);
        var repeated = Assert.Single(repeat, d => d.Kind == "unexpected-service-exposed");
        Assert.Equal(exposed.FingerprintSuffix, repeated.FingerprintSuffix);
    }

    [Fact]
    public void ExpectedPortMissingYieldsMediumExpectedServiceAbsent()
    {
        var baseline = Baseline(
            new ServiceBaselineEntry(443, ProtocolKind.Tcp, BaselineServiceStatus.Expected),
            new ServiceBaselineEntry(22, ProtocolKind.Tcp, BaselineServiceStatus.Expected));
        var observations = new[] { Observed(443) };

        var drift = DriftAnalyzer.Compare(baseline, observations);

        var absent = Assert.Single(drift);
        Assert.Equal("expected-service-absent", absent.Kind);
        Assert.Equal(Severity.Medium, absent.SuggestedSeverity);
        Assert.StartsWith("Expected service absent", absent.Detail, StringComparison.Ordinal);
        Assert.Contains("22", absent.Detail, StringComparison.Ordinal);
    }

    [Fact]
    public void BaselineMatchingObservationsProducesNoDrift()
    {
        var baseline = Baseline(new ServiceBaselineEntry(443, ProtocolKind.Tcp, BaselineServiceStatus.Expected));
        var drift = DriftAnalyzer.Compare(baseline, [Observed(443)]);

        Assert.Empty(drift);
    }
}
