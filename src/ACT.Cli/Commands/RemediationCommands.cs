using System.Text.Json;
using ACT.Contracts;
using ACT.Persistence;
using ACT.Remediation;
using ACT.Web.Checks;
using Microsoft.Extensions.DependencyInjection;

namespace ACT.Cli;

/// <summary>
/// artemis remediate - fixes a finding on the spot through a local remediation proxy and verifies
/// the fix by re-running the originating check. This is the "find and fix" capability: the
/// vulnerable target's responses are corrected in place and the correction is proven, not promised.
/// </summary>
public static class RemediationCommands
{
    public static async Task<int> Run(IServiceProvider services, string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("usage: artemis remediate FINDING_ID --base-url URL [--json]");
            Console.Error.WriteLine("       artemis remediate --list [--json]");
            return ExitCodes.UsageError;
        }

        if (args[0] == "--list" || args[0] == "list")
        {
            return await ListRemediableAsync(services);
        }

        if (args.Length < 1)
        {
            Console.Error.WriteLine("usage: artemis remediate FINDING_ID --base-url URL [--json]");
            return ExitCodes.UsageError;
        }

        var findingRef = args[0];
        string? baseUrlArg = null;
        for (var i = 1; i < args.Length - 1; i++)
        {
            if (args[i] == "--base-url")
            {
                baseUrlArg = args[i + 1];
            }
        }

        if (baseUrlArg is null)
        {
            Console.Error.WriteLine("error: --base-url is required to remediate against the live target");
            return ExitCodes.UsageError;
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

        var check = ResolveCheck(resolved.CheckId.Value);
        if (check is null)
        {
            Console.Error.WriteLine("error: no executable check found for " + resolved.CheckId.Value);
            return ExitCodes.RuntimeFailure;
        }

        var upstream = new Uri(baseUrlArg);
        var engine = new RemediationEngine();
        var result = await engine.RemediateAsync(resolved, check, upstream, CancellationToken.None);

        var detail = new
        {
            findingId = result.FindingId,
            outcome = result.Outcome.ToString(),
            remediatedEndpoint = result.RemediatedEndpoint,
            detail = result.Detail,
            findingsBefore = result.FindingsBefore,
            findingsAfter = result.FindingsAfter,
            appliedUtc = result.AppliedUtc,
            verifiedUtc = result.VerifiedUtc
        };

        var ok = result.Outcome == RemediationOutcome.Remediated;
        var human = $"""
            Remediation: {result.Outcome}
            Finding: {resolved.Title}
            {result.Detail}
            """;
        if (result.RemediatedEndpoint is not null)
        {
            human += $"Corrected endpoint: {result.RemediatedEndpoint}" + Environment.NewLine;
        }

        // A verified remediation is a success; anything else is reported but not a crash.
        return await OutputWriter.WriteAsync(services, human, JsonSerializer.Serialize(detail, JsonOpts.Indented))
            is var code && ok ? code : (ok ? code : ExitCodes.RuntimeFailure);
    }

    /// <summary>Lists the finding classes that have an executable remediation.</summary>
    private static async Task<int> ListRemediableAsync(IServiceProvider services)
    {
        var db = services.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();
        var findings = await db.ListFindingsAsync(null, null, null, 100000);
        var remediable = findings
            .Where(f => RemediationPlanner.PlanFor(f) is not null)
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

    /// <summary>Resolves an executable check instance from its stable id.</summary>
    private static ISecurityCheck? ResolveCheck(string checkId) => checkId switch
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
}
