using System.Text.Json;
using ACT.Contracts;
using ACT.DependencyAnalysis;
using ACT.Persistence;
using ACT.Remediation;
using ACT.SourceAnalysis;
using ACT.Web.Checks;
using Microsoft.Extensions.DependencyInjection;

namespace ACT.Cli;

/// <summary>
/// artemis remediate - fixes a finding on the spot and verifies the fix. Web findings are
/// corrected through a local remediation proxy; dependency findings by upgrading the pinned
/// version in the manifest; source findings by applying a rule-specific code fix. Every fix is
/// proven, not promised: the outcome is only "Remediated" when the correction is verified.
/// </summary>
public static class RemediationCommands
{
    public static async Task<int> Run(IServiceProvider services, string[] args)
    {
        if (args.Length == 0)
        {
            PrintUsage();
            return ExitCodes.UsageError;
        }

        if (args[0] is "--list" or "list")
        {
            return await ListRemediableAsync(services);
        }

        var findingRef = args[0];
        string? baseUrlArg = null, repoArg = null;
        for (var i = 1; i < args.Length - 1; i++)
        {
            if (args[i] == "--base-url") baseUrlArg = args[i + 1];
            if (args[i] == "--repo") repoArg = args[i + 1];
        }

        var db = services.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();

        var all = await db.ListFindingsAsync(null, null, null, 100000);
        var (resolved, prefixMatches) = FindingCommands.FindingIdentifier.Resolve(all, findingRef);
        if (resolved is null)
        {
            Console.Error.WriteLine(prefixMatches > 1
                ? $"error: finding reference '{findingRef}' matches {prefixMatches} findings; use a longer prefix or the finding id"
                : "error: finding not found: " + findingRef);
            return ExitCodes.RuntimeFailure;
        }

        var checkId = resolved.CheckId.Value;

        // Dependency findings: upgrade the manifest to the advisory's fixed version.
        if (checkId == DependencyAnalysisCheck.CheckIdValue)
        {
            if (repoArg is null)
            {
                Console.Error.WriteLine("error: --repo PATH is required to remediate a dependency finding");
                return ExitCodes.UsageError;
            }
            return await RemediateDependencyAsync(services, resolved, repoArg);
        }

        // Source findings: apply a rule-specific code fix.
        if (checkId == SourceAnalysisCheck.CheckIdValue)
        {
            if (repoArg is null)
            {
                Console.Error.WriteLine("error: --repo PATH is required to remediate a source finding");
                return ExitCodes.UsageError;
            }
            return await RemediateSourceAsync(services, resolved, repoArg);
        }

        // Web findings: correct through the remediation proxy.
        if (baseUrlArg is null)
        {
            Console.Error.WriteLine("error: --base-url URL is required to remediate a web finding");
            return ExitCodes.UsageError;
        }
        var check = ResolveWebCheck(checkId);
        if (check is null)
        {
            Console.Error.WriteLine("error: no executable check found for " + checkId);
            return ExitCodes.RuntimeFailure;
        }

        var upstream = new Uri(baseUrlArg);
        var engine = new RemediationEngine();
        var result = await engine.RemediateAsync(resolved, check, upstream, CancellationToken.None);

        var webDetail = new
        {
            findingId = result.FindingId,
            kind = "web",
            outcome = result.Outcome.ToString(),
            remediatedEndpoint = result.RemediatedEndpoint,
            detail = result.Detail,
            findingsBefore = result.FindingsBefore,
            findingsAfter = result.FindingsAfter
        };
        var webOk = result.Outcome == RemediationOutcome.Remediated;
        var webHuman = $"""
            Remediation: {result.Outcome}
            Finding: {resolved.Title}
            {result.Detail}
            """;
        if (result.RemediatedEndpoint is not null)
        {
            webHuman += $"Corrected endpoint: {result.RemediatedEndpoint}" + Environment.NewLine;
        }
        var webCode = await OutputWriter.WriteAsync(services, webHuman, JsonSerializer.Serialize(webDetail, JsonOpts.Indented));
        return webOk ? webCode : ExitCodes.RuntimeFailure;
    }

    /// <summary>Upgrades the vulnerable dependency in the manifest to the advisory's fixed version.</summary>
    private static async Task<int> RemediateDependencyAsync(IServiceProvider services, Finding finding, string repoRoot)
    {
        var manifestRef = finding.AssetReference ?? "";
        var manifestPath = DependencyRemediator.ResolveManifestPath(repoRoot, manifestRef);
        var packageName = finding.TargetDisplay.Split('@')[0];
        var fixedVersion = ExtractFixedVersion(finding);

        if (fixedVersion is null)
        {
            var payload = new { findingId = finding.FindingId, kind = "dependency", outcome = "NotRemediable",
                detail = "No fixed version is recorded for this advisory; upgrade manually per the guidance." };
            await OutputWriter.WriteAsync(services, "No fixed version recorded; upgrade manually.", JsonSerializer.Serialize(payload, JsonOpts.Indented));
            return ExitCodes.RuntimeFailure;
        }

        var result = await DependencyRemediator.UpdateVersionAsync(manifestPath, packageName, fixedVersion, CancellationToken.None);
        var detail = new
        {
            findingId = finding.FindingId,
            kind = "dependency",
            outcome = result.Updated ? "Remediated" : "Failed",
            manifest = result.ManifestPath,
            package = result.PackageName,
            previousVersion = result.PreviousVersion,
            newVersion = result.NewVersion,
            detail = result.Detail
        };
        var human = $"""
            Remediation: {(result.Updated ? "Remediated" : "Failed")}
            Finding: {finding.Title}
            {result.Detail}
            """;
        var code = await OutputWriter.WriteAsync(services, human, JsonSerializer.Serialize(detail, JsonOpts.Indented));
        return result.Updated ? code : ExitCodes.RuntimeFailure;
    }

    /// <summary>Applies a rule-specific fix to the source file.</summary>
    private static async Task<int> RemediateSourceAsync(IServiceProvider services, Finding finding, string repoRoot)
    {
        var filePath = finding.AssetReference ?? "";
        var fullPath = DependencyRemediator.ResolveManifestPath(repoRoot, filePath);
        var ruleId = ExtractRuleId(finding);

        if (ruleId is null)
        {
            var payload = new { findingId = finding.FindingId, kind = "source", outcome = "NotRemediable",
                detail = "Could not determine the source rule for this finding." };
            await OutputWriter.WriteAsync(services, "Could not determine the source rule.", JsonSerializer.Serialize(payload, JsonOpts.Indented));
            return ExitCodes.RuntimeFailure;
        }

        var result = await SourceRemediator.FixAsync(fullPath, ruleId, CancellationToken.None);
        var detail = new
        {
            findingId = finding.FindingId,
            kind = "source",
            outcome = result.Updated ? "Remediated" : "NotRemediable",
            file = result.FilePath,
            rule = result.RuleId,
            locationsFixed = result.LocationsFixed,
            detail = result.Detail
        };
        var human = $"""
            Remediation: {(result.Updated ? "Remediated" : "Not applied")}
            Finding: {finding.Title}
            {result.Detail}
            """;
        var code = await OutputWriter.WriteAsync(services, human, JsonSerializer.Serialize(detail, JsonOpts.Indented));
        return result.Updated ? code : ExitCodes.RuntimeFailure;
    }

    /// <summary>Extracts the fixed version from a dependency finding's remediation steps.</summary>
    private static string? ExtractFixedVersion(Finding finding)
    {
        foreach (var step in finding.Remediation.Steps)
        {
            var match = System.Text.RegularExpressions.Regex.Match(step, @"to\s+([0-9][^\s]+)\s+or later");
            if (match.Success)
            {
                return match.Groups[1].Value;
            }
        }
        return null;
    }

    /// <summary>Extracts the source rule id from a source finding's description.</summary>
    private static string? ExtractRuleId(Finding finding)
    {
        var match = System.Text.RegularExpressions.Regex.Match(finding.Description, @"rule\s+([A-Z]+-[A-Z]+-\d+)");
        if (match.Success) return match.Groups[1].Value;
        return null;
    }

    /// <summary>Lists the findings that have an executable remediation.</summary>
    private static async Task<int> ListRemediableAsync(IServiceProvider services)
    {
        var db = services.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();
        var findings = await db.ListFindingsAsync(null, null, null, 100000);
        var remediable = findings
            .Where(f => IsRemediable(f))
            .GroupBy(f => f.CheckId.Value)
            .Select(g => new { check = g.Key, count = g.Count() })
            .OrderBy(x => x.check, StringComparer.Ordinal)
            .ToList();

        var human = string.Join(Environment.NewLine,
            remediable.Select(r => $"{r.check,-24} {r.count} remediable finding(s)"));
        if (remediable.Count == 0)
        {
            human = "No remediable findings currently stored.";
        }

        return await OutputWriter.WriteAsync(services, human, JsonSerializer.Serialize(remediable, JsonOpts.Indented));
    }

    private static bool IsRemediable(Finding finding)
    {
        var checkId = finding.CheckId.Value;
        if (checkId == DependencyAnalysisCheck.CheckIdValue)
        {
            return ExtractFixedVersion(finding) is not null;
        }
        if (checkId == SourceAnalysisCheck.CheckIdValue)
        {
            var ruleId = ExtractRuleId(finding);
            return ruleId is "SRC-CRYPTO-002" or "SRC-TLS-008" or "SRC-COOKIE-010";
        }
        return ResolveWebCheck(checkId) is not null && RemediationPlanner.PlanFor(finding) is not null;
    }

    /// <summary>Resolves an executable web check instance from its stable id.</summary>
    private static ISecurityCheck? ResolveWebCheck(string checkId) => checkId switch
    {
        "ACT-WEB-HSTS-001" => new HstsCheck(),
        "ACT-WEB-CSP-001" => new CspCheck(),
        "ACT-WEB-SECHEADERS-002" => new SecurityHeadersCheck(),
        "ACT-WEB-COOKIE-001" => new CookieFlagCheck(),
        "ACT-WEB-CORS-001" => new CorsCheck(),
        "ACT-WEB-TLSREDIRECT-001" => new TlsRedirectCheck(),
        "ACT-WEB-MIXEDCONTENT-001" => new MixedContentCheck(),
        "ACT-WEB-CACHECTRL-001" => new CacheControlCheck(),
        _ => null
    };

    private static void PrintUsage()
    {
        Console.Error.WriteLine("usage: artemis remediate FINDING_ID --base-url URL [--json]");
        Console.Error.WriteLine("       artemis remediate FINDING_ID --repo PATH [--json]");
        Console.Error.WriteLine("       artemis remediate --list [--json]");
    }
}
