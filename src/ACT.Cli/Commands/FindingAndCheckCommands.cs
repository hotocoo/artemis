
using System.Text.Json;
using ACT.Contracts;
using ACT.Persistence;
using Microsoft.Extensions.DependencyInjection;

namespace ACT.Cli;

/// <summary>artemis check list - prints the built-in catalog.</summary>
public static class CheckCommand
{
    public static async Task<int> Run(IServiceProvider services, string[] args)
    {
        if (args.Length == 0 || args[0] != "list")
        {
            Console.Error.WriteLine("usage: artemis check list [--json]");
            return ExitCodes.UsageError;
        }

        var catalog = CheckRegistry.Catalog()
            .OrderBy(m => m.Category).ThenBy(m => m.Id.Value, StringComparer.Ordinal)
            .Select(m => new
            {
                id = m.Id.Value,
                name = m.Name,
                version = m.Version,
                category = m.Category.ToString(),
                safetyLevel = m.SafetyLevel.ToString(),
                maxSeverity = m.MaxEmittingSeverity.ToString(),
                requestsPerTarget = $"{m.NetworkBehavior.MinRequestsPerTarget}-{m.NetworkBehavior.MaxRequestsPerTarget}",
                supportsRegression = m.SupportsRegressionTest
            })
            .ToList();

        return await OutputWriter.WriteAsync(services,
            string.Join(Environment.NewLine, catalog.Select(c =>
                $"{c.id,-24} {c.category,-13} {c.safetyLevel,-20} {c.name}")),
            JsonSerializer.Serialize(catalog, JsonOpts.Indented));
    }
}

/// <summary>artemis finding list|show.</summary>
public static class FindingCommands
{
    public static async Task<int> Run(IServiceProvider services, string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("usage: artemis finding list [--assessment ID] [--status STATUS]");
            Console.Error.WriteLine("       artemis finding show FINDING_ID");
            Console.Error.WriteLine("       artemis finding triage FINDING_ID --status STATUS [--note TEXT] [--actor ID]");
            return ExitCodes.UsageError;
        }

        if (args[0] == "triage")
        {
            return await TriageAsync(services, args[1..]);
        }

        var db = services.GetRequiredService<ActDatabase>();
        // Read commands own their readiness: no host runs migrations on their behalf, and the
        // database refuses every query until InitializeAsync has completed at least once.
        await db.InitializeAsync();
        var globals = services.GetRequiredService<GlobalOptions>();

        if (args[0] == "list")
        {
            Guid? assessment = null;
            FindingStatus? status = null;
            for (var i = 1; i < args.Length - 1; i++)
            {
                if (args[i] == "--assessment" && Guid.TryParse(args[i + 1], out var a)) assessment = a;
                if (args[i] == "--status" && Enum.TryParse<FindingStatus>(args[i + 1], true, out var s)) status = s;
            }
            var findings = await db.ListFindingsAsync(assessment, status, null, 500);
            var rows = findings
                .OrderByDescending(f => f.PriorityScore)
                .ThenBy(f => f.Title, StringComparer.Ordinal)
                .ToList();

            var human = string.Join(Environment.NewLine, rows.Select(f =>
                $"[{f.TechnicalSeverity,-13}] p{f.PriorityScore,5:0} {f.Status,-12} {f.FindingId} {f.Fingerprint.Hash[..12]} {f.Title} ({f.TargetDisplay})"));
            return await OutputWriter.WriteAsync(services,
                human.Length == 0 ? "no findings stored" : human,
                JsonSerializer.Serialize(rows.Select(f => new
                {
                    f.FindingId,
                    title = f.Title,
                    severity = f.TechnicalSeverity.ToString(),
                    confidence = f.Confidence.ToString(),
                    priorityScore = Math.Round(f.PriorityScore, 1),
                    status = f.Status.ToString(),
                    category = f.Category.ToString(),
                    target = f.TargetDisplay,
                    fingerprint = f.Fingerprint.Hash,
                    firstSeenUtc = f.FirstSeenUtc,
                    lastSeenUtc = f.LastSeenUtc
                }), JsonOpts.Indented));
        }

        if (args[0] == "show")
        {
            if (args.Length < 2)
            {
                Console.Error.WriteLine("usage: artemis finding show FINDING_ID");
                return ExitCodes.UsageError;
            }

            var all = await db.ListFindingsAsync(null, null, null, 100000);
            var (resolved, prefixMatches) = FindingIdentifier.Resolve(all, args[1]);
            if (resolved is null)
            {
                Console.Error.WriteLine(prefixMatches > 1
                    ? $"error: fingerprint prefix '{args[1]}' matches {prefixMatches} findings; use a longer prefix or the finding id"
                    : "error: finding not found: " + args[1]);
                return ExitCodes.RuntimeFailure;
            }
            var finding = resolved;
            var detail = new
            {
                finding.FindingId,
                title = finding.Title,
                description = finding.Description,
                severity = finding.TechnicalSeverity.ToString(),
                confidence = finding.Confidence.ToString(),
                confidenceScore = finding.ConfidenceScore,
                exploitabilityIndicator = finding.ExploitabilityIndicator,
                businessImpact = finding.BusinessImpact.ToString(),
                whyItMatters = finding.WhyItMatters,
                technicalExplanation = finding.TechnicalExplanation,
                remediation = new { summary = finding.Remediation.Summary, steps = finding.Remediation.Steps, references = finding.Remediation.References },
                target = finding.TargetDisplay,
                check = finding.CheckId.Value,
                status = finding.Status.ToString(),
                fingerprint = finding.Fingerprint.Hash,
                cvss = new { vector = finding.CvssVector, baseScore = finding.CvssBaseScore },
                firstSeenUtc = finding.FirstSeenUtc,
                lastSeenUtc = finding.LastSeenUtc
            };
            var human = $"""
                {finding.Title}
                Severity: {finding.TechnicalSeverity}  Confidence: {finding.Confidence} ({finding.ConfidenceScore:0.00})  Priority: {finding.PriorityScore:0}
                Status:   {finding.Status}   Category: {finding.Category}
                Target:   {finding.TargetDisplay}

                {finding.Description}

                Why it matters:
                  {finding.WhyItMatters}

                Remediation:
                  {finding.Remediation.Summary}
                """ + Environment.NewLine +
                string.Join(Environment.NewLine, finding.Remediation.Steps.Select(st => "  - " + st));
            return await OutputWriter.WriteAsync(services, human,
                JsonSerializer.Serialize(detail, JsonOpts.Indented));
        }

        Console.Error.WriteLine("error: unknown finding subcommand '" + args[0] + "'");
        Console.Error.WriteLine("usage: artemis finding list [--assessment ID] [--status STATUS]");
        Console.Error.WriteLine("       artemis finding show FINDING_ID");
        Console.Error.WriteLine("       artemis finding triage FINDING_ID --status STATUS [--note TEXT] [--actor ID]");
        return ExitCodes.UsageError;
    }

    /// <summary>
    /// Resolves an operator-supplied finding identifier: a GUID, a full fingerprint hash, or a
    /// fingerprint prefix that matches exactly one stored finding. Ambiguous prefixes are their
    /// own outcome so a shortened id can never silently address the wrong finding.
    /// </summary>
    public static class FindingIdentifier
    {
        public sealed record Resolution(Finding? Finding, int PrefixMatchCount);

        public static Resolution Resolve(IReadOnlyList<Finding> findings, string identifier)
        {
            if (Guid.TryParse(identifier, out var id))
            {
                return new(findings.FirstOrDefault(f => f.FindingId == id), 0);
            }

            var exact = findings.FirstOrDefault(f =>
                f.Fingerprint.Hash.Equals(identifier, StringComparison.OrdinalIgnoreCase));
            if (exact is not null)
            {
                return new(exact, 0);
            }

            var prefixMatches = findings
                .Where(f => f.Fingerprint.Hash.StartsWith(identifier, StringComparison.OrdinalIgnoreCase))
                .ToList();
            return new(prefixMatches.Count == 1 ? prefixMatches[0] : null, prefixMatches.Count);
        }
    }

    /// <summary>
    /// The operator path into the audited triage lifecycle: records a status decision with actor
    /// and note on the row itself and in the hash-chained audit log. Illegal transitions fail
    /// closed with the list of allowed targets so the operator is never left guessing.
    /// </summary>
    private static async Task<int> TriageAsync(IServiceProvider services, string[] args)
    {
        var db = services.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();

        Guid? findingId = null;
        FindingStatus? status = null;
        string? note = null;
        string? actor = null;

        if (args.Length > 0 && !args[0].StartsWith('-'))
        {
            var all = await db.ListFindingsAsync(null, null, null, 100000);
            var (resolved, prefixMatches) = FindingIdentifier.Resolve(all, args[0]);
            if (resolved is null)
            {
                Console.Error.WriteLine(prefixMatches > 1
                    ? $"error: fingerprint prefix '{args[0]}' matches {prefixMatches} findings; use a longer prefix or the finding id"
                    : "error: finding not found: " + args[0]);
                return ExitCodes.RuntimeFailure;
            }

            findingId = resolved.FindingId;
        }

        for (var i = 1; i < args.Length - 1; i++)
        {
            switch (args[i])
            {
                case "--status":
                    if (Enum.TryParse<FindingStatus>(args[i + 1], ignoreCase: true, out var parsedStatus)
                        && Enum.IsDefined(parsedStatus))
                    {
                        status = parsedStatus;
                    }

                    break;
                case "--note": note = args[i + 1]; break;
                case "--actor": actor = args[i + 1]; break;
            }
        }

        if (findingId is null || status is null)
        {
            Console.Error.WriteLine("usage: artemis finding triage FINDING_ID --status STATUS [--note TEXT] [--actor ID]");
            Console.Error.WriteLine("       statuses: " + string.Join(", ", Enum.GetValues<FindingStatus>()));
            return ExitCodes.UsageError;
        }

        try
        {
            var (updated, triage) = await db.TriageFindingAsync(
                findingId.Value, status.Value, actor ?? "operator-cli", note, CorrelationId.New());

            return await OutputWriter.WriteAsync(services,
                "triaged " + updated.FindingId + ": " + updated.Status + " (by " + triage.TriagedBy + ")",
                JsonSerializer.Serialize(new
                {
                    findingId = updated.FindingId,
                    status = updated.Status.ToString(),
                    actor = triage.TriagedBy,
                    note = triage.Note,
                    triagedUtc = triage.TriagedUtc
                }, JsonOpts.Indented));
        }
        catch (ActException ex)
        {
            Console.Error.WriteLine("error: " + ex.SafeMessage);
            return ExitCodes.RuntimeFailure;
        }
    }
}

internal static class JsonOpts
{
    public static JsonSerializerOptions Indented { get; } = new() { WriteIndented = true };
}
