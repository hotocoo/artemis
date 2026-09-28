
using ACT.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace ACT.SourceAnalysis;

/// <summary>
/// Local-only static analysis check: walks one operator-provided repository inside hard resource
/// limits and evaluates the declarative source rule set against every admitted file.
/// </summary>
public sealed class SourceAnalysisCheck : ISecurityCheck
{
    /// <summary>Stable identifier of this check.</summary>
    public const string CheckIdValue = "ACT-SRC-SCAN-001";

    private const int MaxLocationsPerFinding = 25;
    private const int SnippetMaxLength = 160;

    private readonly IEvidenceFactory _evidenceFactory;
    private readonly SourceRuleEngine _engine;
    private readonly RepositoryAnalysisLimits _limits;

    /// <summary>Creates the check; evidence items are produced through the injected factory.</summary>
    public SourceAnalysisCheck(
        IEvidenceFactory evidenceFactory,
        SourceRuleEngine? engine = null,
        RepositoryAnalysisLimits? limits = null,
        ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(evidenceFactory);
        _evidenceFactory = evidenceFactory;
        _engine = engine ?? new SourceRuleEngine();
        _limits = limits ?? RepositoryAnalysisLimits.Default;
        Logger = logger ?? NullLogger.Instance;
        Metadata = BuildMetadata();
        Metadata.Validate();
    }

    /// <summary>Self-describing metadata declared before execution.</summary>
    public SecurityCheckMetadata Metadata { get; }

    private ILogger Logger { get; }

    /// <summary>Runs the repository scan and returns deduplicated findings with location evidence.</summary>
    public async Task<SecurityCheckResult> ExecuteAsync(SecurityCheckContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);
        var started = DateTimeOffset.UtcNow;
        if (context.Asset.Kind is not (AssetKind.Repository or AssetKind.TestEnvironment))
        {
            return SecurityCheckResult.Empty(
                Metadata, started, CheckExecutionStatus.Skipped_NotApplicable,
                "The asset is not a local source repository.");
        }

        try
        {
            return await ExecuteCoreAsync(context, started, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (ActException ex)
        {
            Logger.LogWarning("Source analysis failed closed: {Reason}", ex.SafeMessage);
            return SecurityCheckResult.Empty(Metadata, started, CheckExecutionStatus.Failed_FailedClosed, ex.SafeMessage);
        }
    }

    private async Task<SecurityCheckResult> ExecuteCoreAsync(
        SecurityCheckContext context,
        DateTimeOffset started,
        CancellationToken cancellationToken)
    {
        var correlation = CorrelationId.New();
        var walker = new RepositoryWalker(context.Asset.CanonicalTarget, _limits);
        var repositoryName = Path.GetFileName(walker.RootPath);
        if (string.IsNullOrEmpty(repositoryName))
        {
            repositoryName = walker.RootPath;
        }

        var findings = new List<Finding>();
        var standaloneEvidence = new List<EvidenceItem>();
        var timedOutRules = new SortedSet<string>(StringComparer.Ordinal);
        long filesExamined = 0;

        // Cross-file flow needs callee summaries before caller files are evaluated. Keep only
        // compact function summaries, then stream source again for normal rule evaluation.
        var discoveredFiles = new List<FileContext>();
        await foreach (var entry in walker.WalkAsync(cancellationToken).ConfigureAwait(false))
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (entry is DiscoveredFile discovered)
                discoveredFiles.Add(discovered.File);
        }
        var flowCatalog = await _engine.CollectFunctionCatalogAsync(discoveredFiles, cancellationToken).ConfigureAwait(false);

        foreach (var file in discoveredFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();

            RuleScanResult scan;
            try
            {
                scan = await _engine.EvaluateAsync(
                    file,
                    file.EnumerateLinesAsync(cancellationToken),
                    cancellationToken,
                    flowCatalog).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                walker.Counters.IncrementIoErrors();
                continue;
            }

            filesExamined++;
            foreach (var timedOut in scan.TimedOutRuleIds)
            {
                timedOutRules.Add(timedOut);
            }

            foreach (var ruleGroup in scan.Matches.GroupBy(static match => match.Rule, ReferenceEqualityComparer.Instance))
            {
                EmitFinding(
                    ruleGroup.ToList(),
                    file,
                    repositoryName,
                    context.Assessment.AssessmentId,
                    correlation,
                    findings,
                    standaloneEvidence);
            }
        }

        CheckExecutionStatus status = timedOutRules.Count > 0
            ? CheckExecutionStatus.CompletedWithWarnings
            : CheckExecutionStatus.Completed;
        string? failureSummarySafe = timedOutRules.Count > 0
            ? $"{timedOutRules.Count} rule(s) were disabled on some files because evaluation exceeded the safety time budget."
            : null;

        return new SecurityCheckResult(
            Metadata.Id,
            status,
            started,
            DateTimeOffset.UtcNow,
            findings,
            standaloneEvidence,
            failureSummarySafe,
            RequestCount: 0,
            TargetsExamined: (int)Math.Min(filesExamined, int.MaxValue));
    }

    private void EmitFinding(
        IReadOnlyList<SourceRuleMatch> matches,
        FileContext file,
        string repositoryName,
        Guid assessmentId,
        CorrelationId correlation,
        ICollection<Finding> findingsSink,
        ICollection<EvidenceItem> evidenceSink)
    {
        var rule = matches[0].Rule;
        var recordedLocations = matches.Take(MaxLocationsPerFinding).ToList();
        var omitted = matches.Count - recordedLocations.Count;

        var description = string.Concat(
            matches.Count.ToString(System.Globalization.CultureInfo.InvariantCulture),
            " location(s) matched rule ", rule.RuleId, " in this file.");
        if (omitted > 0)
        {
            description += $" The first {recordedLocations.Count} locations are attached as evidence; {omitted} further occurrence(s) were omitted to bound result size.";
        }
        else
        {
            description += " Every matched location is attached as evidence with a trimmed line snippet.";
        }

        var finding = FindingFactory.Create(
            assessmentId,
            Metadata.Id,
            targetDisplay: file.RelativePath,
            category: CheckCategory.Source,
            title: rule.Title,
            description: description,
            severity: rule.Severity,
            confidence: rule.Confidence,
            exploitabilityIndicator: rule.ExploitabilityIndicator,
            businessImpact: ImpactFor(rule.Severity),
            whyItMatters: rule.WhyItMatters,
            technicalExplanation:
                "A static pattern associated with this finding class matched source text at the recorded line numbers. " +
                "Line numbers are excluded from the fingerprint so unrelated edits that shift lines do not create duplicate findings.",
            remediation: rule.Remediation,
            new FingerprintComponents(Metadata.Id, file.RelativePath, rule.FindingClass, "source"),
            assetReference: file.AbsolutePath);
        findingsSink.Add(finding);

        foreach (var match in recordedLocations)
        {
            var attributes = new Dictionary<string, string>
            {
                ["ruleId"] = rule.RuleId,
                ["findingClass"] = rule.FindingClass
            };
            var snippet = BuildSnippet(rule, match, attributes);
            evidenceSink.Add(_evidenceFactory.Create(
                finding.FindingId,
                EvidenceKind.SourceLocation,
                file.RelativePath + ":" + match.LineNumber.ToString(System.Globalization.CultureInfo.InvariantCulture),
                snippet,
                Metadata.Id,
                correlation,
                attributes));
        }
    }

    private static string BuildSnippet(SourceRule rule, SourceRuleMatch match, Dictionary<string, string> attributes)
    {
        var line = match.LineText.Trim();
        if (rule.RedactMatches && line.Contains(match.MatchedText, StringComparison.Ordinal))
        {
            var secretType = SecretTypeFor(match.MatchedText);
            attributes["secretType"] = secretType;
            // Never persist the raw secret value: replace it with its scrubber fingerprint.
            line = line.Replace(
                match.MatchedText,
                SecretScrubber.Fingerprint(secretType, match.MatchedText),
                StringComparison.Ordinal);
        }

        return line.Length <= SnippetMaxLength ? line : string.Concat(line.AsSpan(0, SnippetMaxLength), "...");
    }

    private static string SecretTypeFor(string matchedValue)
    {
        if (matchedValue.StartsWith("AKIA", StringComparison.Ordinal))
        {
            return "aws-access-key-id";
        }

        if (matchedValue.StartsWith("github_pat_", StringComparison.Ordinal))
        {
            return "github-personal-access-token";
        }

        if (matchedValue.StartsWith("ghp_", StringComparison.Ordinal)
            || matchedValue.StartsWith("gho_", StringComparison.Ordinal)
            || matchedValue.StartsWith("ghu_", StringComparison.Ordinal)
            || matchedValue.StartsWith("ghs_", StringComparison.Ordinal)
            || matchedValue.StartsWith("ghr_", StringComparison.Ordinal))
        {
            return "github-token";
        }

        if (matchedValue.StartsWith("xox", StringComparison.Ordinal))
        {
            return "slack-token";
        }

        if (matchedValue.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
        {
            return "private-key";
        }

        return "credential";
    }

    private static BusinessImpactLevel ImpactFor(Severity severity) => severity switch
    {
        Severity.Critical or Severity.High => BusinessImpactLevel.Significant,
        Severity.Medium => BusinessImpactLevel.Limited,
        _ => BusinessImpactLevel.Negligible
    };

    private static SecurityCheckMetadata BuildMetadata() => new(
        Id: CheckId.From(CheckIdValue),
        Name: "Repository source static analysis",
        Version: "1.0.0",
        Category: CheckCategory.Source,
        MaxEmittingSeverity: Severity.Critical,
        SafetyLevel: SafetyLevel.LocalOnly,
        RequiredPermissions: PermissionRequirement.ReadRepositoryFiles,
        RequiredProtocols: new HashSet<ProtocolKind>(),
        SupportedTargetTypes: new HashSet<TargetTypeKind>
        {
            TargetTypeKind.LocalSourceRepository,
            TargetTypeKind.TestEnvironment
        },
        NetworkBehavior: new NetworkBehaviorProfile(0, 0, false, false, false),
        EvidenceTypesProduced: [EvidenceKind.SourceLocation],
        SupportsRemediation: true,
        SupportsRegressionTest: true,
        Description:
            "Walks the operator-provided repository within declared size, depth, and volume limits and matches " +
            "declarative rules for committed secrets, weak cryptography, SQL and command injection sinks, unsafe " +
            "path composition, request-driven outbound requests, sensitive logging, disabled TLS validation, " +
            "permissive CORS, insecure cookies, dangerous deserialization, and insecure shipped defaults.");
}
