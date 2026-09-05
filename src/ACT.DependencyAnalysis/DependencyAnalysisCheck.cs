
using ACT.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace ACT.DependencyAnalysis;

/// <summary>
/// Local-only dependency audit check: inventories every supported manifest under a repository
/// root within declared limits and matches each pinned entry against the configured advisory feed.
/// </summary>
public sealed class DependencyAnalysisCheck : ISecurityCheck
{
    /// <summary>Stable identifier of this check.</summary>
    public const string CheckIdValue = "ACT-DEP-AUDIT-001";

    private readonly ISecurityAdvisoryProvider _advisoryProvider;
    private readonly IEvidenceFactory _evidenceFactory;
    private readonly ILogger _logger;

    /// <summary>Creates the check; advisory data comes exclusively from the injected provider.</summary>
    public DependencyAnalysisCheck(
        ISecurityAdvisoryProvider advisoryProvider,
        IEvidenceFactory evidenceFactory,
        ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(advisoryProvider);
        ArgumentNullException.ThrowIfNull(evidenceFactory);
        _advisoryProvider = advisoryProvider;
        _evidenceFactory = evidenceFactory;
        _logger = logger ?? NullLogger.Instance;
        Metadata = BuildMetadata();
        Metadata.Validate();
    }

    /// <inheritdoc/>
    public SecurityCheckMetadata Metadata { get; }

    /// <summary>Inventories manifests under the repository root and reports vulnerable dependencies.</summary>
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
            _logger.LogWarning("Dependency analysis failed closed: {Reason}", ex.SafeMessage);
            return SecurityCheckResult.Empty(Metadata, started, CheckExecutionStatus.Failed_FailedClosed, ex.SafeMessage);
        }
    }

    private async Task<SecurityCheckResult> ExecuteCoreAsync(
        SecurityCheckContext context,
        DateTimeOffset started,
        CancellationToken cancellationToken)
    {
        var correlation = CorrelationId.New();
        var walker = new RepositoryWalkerAdapter();
        var repositoryName = Path.GetFileName(walker.RootPathOf(context.Asset.CanonicalTarget));
        if (string.IsNullOrEmpty(repositoryName))
        {
            repositoryName = context.Asset.CanonicalTarget;
        }

        var parser = new ManifestParser();
        var matcher = new VulnerabilityMatcher(_advisoryProvider, _logger);
        var budget = context.Assessment.Budget;

        var findings = new List<Finding>();
        var standaloneEvidence = new List<EvidenceItem>();
        var warnings = 0;
        var manifestsExamined = 0;

        var discovery = new ManifestDiscovery();
        await foreach (var discovered in discovery.DiscoverAsync(
                           context.Asset.CanonicalTarget,
                           new DiscoveryLimits(),
                           cancellationToken).ConfigureAwait(false))
        {
            cancellationToken.ThrowIfCancellationRequested();
            var manifest = await parser.ParseFileAsync(discovered.AbsolutePath, cancellationToken).ConfigureAwait(false);

            manifestsExamined++;

            // CMake git dependencies have no canonical advisory feed; evaluate supply-chain
            // hygiene (transport security, mutability of the pinned reference) directly.
            if (manifest.Ecosystem == DependencyEcosystem.CMake)
            {
                EmitCMakeSupplyChainFindings(manifest, repositoryName, context.Assessment.AssessmentId, correlation, findings, standaloneEvidence);
                continue;
            }

            var report = await matcher.MatchAsync(manifest, budget, cancellationToken).ConfigureAwait(false);
            warnings += report.Warnings.Count;
            foreach (var warningText in report.Warnings.Take(5))
            {
                _logger.LogDebug("Dependency audit warning: {Warning}", warningText);
            }

            foreach (var vulnerability in report.Vulnerabilities)
            {
                EmitFinding(vulnerability, repositoryName, context.Assessment.AssessmentId, correlation, findings, standaloneEvidence);
            }
        }

        var status = warnings > 0 ? CheckExecutionStatus.CompletedWithWarnings : CheckExecutionStatus.Completed;
        return new SecurityCheckResult(
            Metadata.Id,
            status,
            started,
            DateTimeOffset.UtcNow,
            findings,
            standaloneEvidence,
            warnings > 0 ? $"{warnings} dependency entr(ies) could not be fully evaluated against the advisory feed." : null,
            RequestCount: 0,
            TargetsExamined: manifestsExamined);
    }

    private void EmitFinding(
        VulnerableDependency vulnerability,
        string repositoryName,
        Guid assessmentId,
        CorrelationId correlation,
        ICollection<Finding> findingsSink,
        ICollection<EvidenceItem> evidenceSink)
    {
        var entry = vulnerability.Dependency;
        var advisory = vulnerability.Advisory;
        var severity = advisory.Severity ?? Severity.Medium;
        var versionDisplay = entry.Version ?? "unpinned";

        List<string> remediationSteps;
        string fixSentence;
        if (advisory.FixedVersion is { } fixedVersion)
        {
            remediationSteps =
            [
                $"Upgrade {entry.Name} to {fixedVersion} or later.",
                "Re-run the assessment to confirm the fixed version resolved the advisory."
            ];
            fixSentence = $" Fixed in {fixedVersion}.";
        }
        else
        {
            remediationSteps =
            [
                "Review the advisory for an upgrade or mitigation path.",
                "Re-run the assessment after applying the change."
            ];
            fixSentence = " No fixed version is recorded.";
        }

        var finding = FindingFactory.Create(
            assessmentId,
            Metadata.Id,
            targetDisplay: entry.Name + "@" + versionDisplay,
            category: CheckCategory.Dependency,
            title: $"Vulnerable dependency {entry.Name}@{versionDisplay}",
            description: $"Advisory {advisory.AdvisoryId} affects this package in range {advisory.AffectedRangeExpression}." + fixSentence,
            severity: severity,
            confidence: ConfidenceLevel.High,
            exploitabilityIndicator: true,
            businessImpact: ImpactFor(severity),
            whyItMatters:
                "Known-vulnerable package versions carry publicly documented attack techniques that automated attackers apply without modification.",
            technicalExplanation:
                $"The pinned version was matched against advisory {advisory.AdvisoryId} from feed '{advisory.SourceFeed}'.",
            remediation: new RemediationGuidance(
                $"Update {entry.Name} to remove exposure to {advisory.AdvisoryId}.",
                remediationSteps,
                []),
            fingerprintComponents: new FingerprintComponents(
                Metadata.Id,
                repositoryName,
                entry.SourceFile + "|" + entry.Name + "@" + versionDisplay + "|" + advisory.AdvisoryId,
                "VulnerableDependency"),
            assetReference: entry.SourceFile);
        findingsSink.Add(finding);

        var attributes = new Dictionary<string, string>
        {
            ["ecosystem"] = advisory.Ecosystem,
            ["advisoryId"] = advisory.AdvisoryId,
            ["affectedRange"] = advisory.AffectedRangeExpression
        };
        if (advisory.FixedVersion is not null)
        {
            attributes["fixedVersion"] = advisory.FixedVersion!;
        }

        evidenceSink.Add(_evidenceFactory.Create(
            finding.FindingId,
            EvidenceKind.DependencyMetadata,
            "dependency",
            advisory.Ecosystem + ":" + entry.Name + "@" + versionDisplay + " (" + entry.SourceFile + ")",
            Metadata.Id,
            correlation,
            attributes));
    }

    /// <summary>
    /// Emits supply-chain hygiene findings for CMake dependencies: insecure (http://) fetch
    /// transport and mutable branch references. These are independent of advisory matching.
    /// </summary>
    private void EmitCMakeSupplyChainFindings(
        DependencyManifest manifest,
        string repositoryName,
        Guid assessmentId,
        CorrelationId correlation,
        ICollection<Finding> findingsSink,
        ICollection<EvidenceItem> evidenceSink)
    {
        foreach (var entry in manifest.Entries)
        {
            // 1. Insecure transport: dependency fetched over unencrypted HTTP.
            if (entry.SourceUrl is { } url && url.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
            {
                var httpFinding = FindingFactory.Create(
                    assessmentId,
                    Metadata.Id,
                    targetDisplay: entry.Name + "@" + (entry.Version ?? "unpinned"),
                    category: CheckCategory.Dependency,
                    title: $"CMake dependency {entry.Name} fetched over unencrypted HTTP",
                    description: $"The CMake build fetches {entry.Name} from an insecure http:// URL, exposing the dependency to tampering and interception in transit.",
                    severity: Severity.High,
                    confidence: ConfidenceLevel.High,
                    exploitabilityIndicator: true,
                    businessImpact: BusinessImpactLevel.Severe,
                    whyItMatters: "Fetching build dependencies over unencrypted transport allows man-in-the-middle attackers to substitute malicious code before it is compiled.",
                    technicalExplanation: $"CMakeLists.txt declares {entry.Name} with GIT_REPOSITORY {url}.",
                    remediation: new RemediationGuidance(
                        "Use an https:// URL for the dependency source.",
                        ["Change the GIT_REPOSITORY URL to https://.", "Re-run the assessment to confirm the transport is secure."],
                        []),
                    fingerprintComponents: new FingerprintComponents(
                        Metadata.Id,
                        repositoryName,
                        entry.SourceFile + "|cmake-http|" + entry.Name,
                        "CMakeInsecureTransport"),
                    assetReference: entry.SourceFile);
                findingsSink.Add(httpFinding);

                evidenceSink.Add(_evidenceFactory.Create(
                    httpFinding.FindingId,
                    EvidenceKind.DependencyMetadata,
                    "dependency",
                    "CMake:" + entry.Name + " (" + entry.SourceFile + ")",
                    Metadata.Id,
                    correlation,
                    new Dictionary<string, string>
                    {
                        ["ecosystem"] = "CMake",
                        ["risk"] = "insecure-transport",
                        ["url"] = url
                    }));
            }

            // 2. Mutable branch reference: dependency pinned to a branch that can change.
            if (entry.Version is { } version && IsMutableBranchTag(version))
            {
                var branchFinding = FindingFactory.Create(
                    assessmentId,
                    Metadata.Id,
                    targetDisplay: entry.Name + "@" + version,
                    category: CheckCategory.Dependency,
                    title: $"CMake dependency {entry.Name} pinned to a mutable branch",
                    description: $"The CMake build pins {entry.Name} to branch '{version}', which can change without notice and silently alter the compiled dependency.",
                    severity: Severity.Medium,
                    confidence: ConfidenceLevel.Medium,
                    exploitabilityIndicator: false,
                    businessImpact: BusinessImpactLevel.Significant,
                    whyItMatters: "Branch-based dependency pinning is mutable; upstream changes or a compromised branch propagate into the build without a version bump.",
                    technicalExplanation: $"CMakeLists.txt declares {entry.Name} with GIT_TAG {version}.",
                    remediation: new RemediationGuidance(
                        "Pin the dependency to an immutable version tag or commit.",
                        ["Replace the branch reference with a version tag or commit SHA.", "Re-run the assessment to confirm the dependency is immutably pinned."],
                        []),
                    fingerprintComponents: new FingerprintComponents(
                        Metadata.Id,
                        repositoryName,
                        entry.SourceFile + "|cmake-branch|" + entry.Name,
                        "CMakeMutableBranch"),
                    assetReference: entry.SourceFile);
                findingsSink.Add(branchFinding);

                evidenceSink.Add(_evidenceFactory.Create(
                    branchFinding.FindingId,
                    EvidenceKind.DependencyMetadata,
                    "dependency",
                    "CMake:" + entry.Name + "@" + version + " (" + entry.SourceFile + ")",
                    Metadata.Id,
                    correlation,
                    new Dictionary<string, string>
                    {
                        ["ecosystem"] = "CMake",
                        ["risk"] = "mutable-branch",
                        ["tag"] = version
                    }));
            }
        }
    }

    /// <summary>True when the GIT_TAG is a well-known mutable branch rather than an immutable version or commit.</summary>
    private static bool IsMutableBranchTag(string tag)
    {
        var lowered = tag.Trim().ToLowerInvariant();
        return lowered is "master" or "main" or "develop" or "dev" or "trunk" or "next" or "head";
    }

    private static BusinessImpactLevel ImpactFor(Severity severity) => severity switch
    {
        Severity.Critical or Severity.High => BusinessImpactLevel.Severe,
        Severity.Medium => BusinessImpactLevel.Significant,
        _ => BusinessImpactLevel.Limited
    };

    private static SecurityCheckMetadata BuildMetadata() => new(
        Id: CheckId.From(CheckIdValue),
        Name: "Dependency vulnerability audit",
        Version: "1.0.0",
        Category: CheckCategory.Dependency,
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
        EvidenceTypesProduced: [EvidenceKind.DependencyMetadata],
        SupportsRemediation: true,
        SupportsRegressionTest: true,
        Description:
            "Inventories supported dependency manifests (NuGet .csproj / packages.lock.json, npm package-lock.json, " +
            "PyPI requirements.txt, Cargo Cargo.toml, CMake CMakeLists.txt, Go go.mod, Maven pom.xml, Gradle " +
            "build.gradle / build.gradle.kts) inside the repository within declared resource limits and " +
            "matches every pinned version against the operator-configured advisory feed.");
}

/// <summary>Resolves canonical repository roots for checks without coupling to concrete scope types.</summary>
internal sealed class RepositoryWalkerAdapter
{
    /// <summary>Returns the normalized full path of the repository root.</summary>
    public string RootPathOf(string canonicalTarget)
    {
        if (string.IsNullOrWhiteSpace(canonicalTarget))
        {
            throw ActException.FailClosed(
                ErrorCategory.Scope,
                "The repository asset does not carry a local path.",
                "DependencyAnalysisCheck received an empty canonical target.");
        }

        return Path.GetFullPath(canonicalTarget);
    }
}

