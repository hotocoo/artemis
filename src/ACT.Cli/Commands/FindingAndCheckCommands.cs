
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
            Console.Error.WriteLine("usage: artemis finding list [--assessment ID] [--status STATUS] | finding show FINDING_ID");
            return ExitCodes.UsageError;
        }

        var db = services.GetRequiredService<ActDatabase>();
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
                $"[{f.TechnicalSeverity,-13}] p{f.PriorityScore,5:0} {f.Status,-12} {f.Fingerprint.Hash[..12]} {f.Title} ({f.TargetDisplay})"));
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

        if (args[0] == "show" && args.Length > 1 && Guid.TryParse(args[1], out var id))
        {
            var all = await db.ListFindingsAsync(null, null, null, 100000);
            var finding = all.FirstOrDefault(f => f.FindingId == id);
            if (finding is null)
            {
                Console.Error.WriteLine("error: finding not found: " + id);
                return ExitCodes.RuntimeFailure;
            }
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

        Console.Error.WriteLine("usage: artemis finding show FINDING_ID");
        return ExitCodes.UsageError;
    }
}

internal static class JsonOpts
{
    public static JsonSerializerOptions Indented { get; } = new() { WriteIndented = true };
}
