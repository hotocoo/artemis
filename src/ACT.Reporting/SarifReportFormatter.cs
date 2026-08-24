using System.Text.Json;
using System.Text.Json.Serialization;
using ACT.Contracts;

namespace ACT.Reporting;

/// <summary>Renders the report as a SARIF 2.1.0 log for CI systems and code scanning surfaces.</summary>
public sealed class SarifReportFormatter : IReportFormatter
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    /// <inheritdoc />
    public string ContentType => "application/sarif+json; charset=utf-8";

    /// <inheritdoc />
    public string FileExtension => "sarif";

    /// <inheritdoc />
    public Task<string> RenderAsync(ReportInput input, CancellationToken cancellationToken)
    {
        ReportRendering.EnsureValid(input);
        cancellationToken.ThrowIfCancellationRequested();
        var items = ReportRendering.OrderedItems(input);

        var ruleIds = items
            .Select(static i => i.Finding.CheckId.Value)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static id => id, StringComparer.Ordinal)
            .ToList();
        var ruleIndexById = new Dictionary<string, int>(ruleIds.Count, StringComparer.Ordinal);
        for (var index = 0; index < ruleIds.Count; index++)
        {
            ruleIndexById[ruleIds[index]] = index;
        }

        var rules = ruleIds.Select(static id => new SarifRule(id, id)).ToList();
        var results = new List<SarifResult>(items.Count);
        foreach (var item in items)
        {
            var finding = item.Finding;
            results.Add(new SarifResult(
                RuleId: finding.CheckId.Value,
                RuleIndex: ruleIndexById[finding.CheckId.Value],
                Level: MapLevel(finding.TechnicalSeverity),
                Message: new SarifMessage(finding.Title + ": " + finding.Description),
                Fingerprints: new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["primaryLocation"] = finding.Fingerprint.Hash,
                },
                Locations: [BuildLocation(finding.TargetDisplay)]));
        }

        var log = new SarifLog(
            Version: "2.1.0",
            Runs: [new SarifRun(new SarifTool(new SarifDriver("Artemis", input.ToolVersion, rules)), results)]);
        return Task.FromResult(JsonSerializer.Serialize(log, Options));
    }

    /// <summary>Maps severity to the SARIF level vocabulary.</summary>
    internal static string MapLevel(Severity severity) => severity switch
    {
        Severity.Critical or Severity.High => "error",
        Severity.Medium => "warning",
        _ => "note",
    };

    private static SarifLocation BuildLocation(string target)
    {
        if (Uri.TryCreate(target, UriKind.Absolute, out var parsed)
            && (parsed.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                || parsed.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)))
        {
            return new SarifLocation(new SarifPhysicalLocation(new SarifArtifactLocation(target)), null);
        }

        return new SarifLocation(null, [new SarifLogicalLocation(target)]);
    }
}

internal sealed record SarifLog(
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("runs")] IReadOnlyList<SarifRun> Runs);

internal sealed record SarifRun(
    [property: JsonPropertyName("tool")] SarifTool Tool,
    [property: JsonPropertyName("results")] IReadOnlyList<SarifResult> Results);

internal sealed record SarifTool([property: JsonPropertyName("driver")] SarifDriver Driver);

internal sealed record SarifDriver(
    [property: JsonPropertyName("name")] string Name,
    [property: JsonPropertyName("version")] string Version,
    [property: JsonPropertyName("rules")] IReadOnlyList<SarifRule> Rules);

internal sealed record SarifRule(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("name")] string Name);

internal sealed record SarifMessage([property: JsonPropertyName("text")] string Text);

internal sealed record SarifResult(
    [property: JsonPropertyName("ruleId")] string RuleId,
    [property: JsonPropertyName("ruleIndex")] int RuleIndex,
    [property: JsonPropertyName("level")] string Level,
    [property: JsonPropertyName("message")] SarifMessage Message,
    [property: JsonPropertyName("fingerprints")] IReadOnlyDictionary<string, string> Fingerprints,
    [property: JsonPropertyName("locations")] IReadOnlyList<SarifLocation> Locations);

internal sealed record SarifLocation(
    [property: JsonPropertyName("physicalLocation")] SarifPhysicalLocation? Physical,
    [property: JsonPropertyName("logicalLocations")] IReadOnlyList<SarifLogicalLocation>? Logical);

internal sealed record SarifPhysicalLocation(
    [property: JsonPropertyName("artifactLocation")] SarifArtifactLocation Artifact);

internal sealed record SarifArtifactLocation([property: JsonPropertyName("uri")] string Uri);

internal sealed record SarifLogicalLocation([property: JsonPropertyName("name")] string Name);
