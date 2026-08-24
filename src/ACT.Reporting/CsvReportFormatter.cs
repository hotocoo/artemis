using System.Text;
using ACT.Contracts;

namespace ACT.Reporting;

/// <summary>Renders findings as an RFC 4180 compliant CSV table.</summary>
public sealed class CsvReportFormatter : IReportFormatter
{
    private const string HeaderRow =
        "id,title,severity,confidence,status,target,category,first_seen,last_seen,fingerprint,priority_score";

    /// <inheritdoc />
    public string ContentType => "text/csv; charset=utf-8";

    /// <inheritdoc />
    public string FileExtension => "csv";

    /// <inheritdoc />
    public Task<string> RenderAsync(ReportInput input, CancellationToken cancellationToken)
    {
        ReportRendering.EnsureValid(input);
        cancellationToken.ThrowIfCancellationRequested();
        var builder = new StringBuilder(capacity: 1024);
        builder.Append(HeaderRow).Append("\r\n");
        foreach (var item in ReportRendering.OrderedItems(input))
        {
            var finding = item.Finding;
            AppendField(builder, finding.FindingId.ToString());
            builder.Append(',');
            AppendField(builder, finding.Title);
            builder.Append(',');
            AppendField(builder, finding.TechnicalSeverity.ToString());
            builder.Append(',');
            AppendField(builder, finding.Confidence.ToString());
            builder.Append(',');
            AppendField(builder, finding.Status.ToString());
            builder.Append(',');
            AppendField(builder, finding.TargetDisplay);
            builder.Append(',');
            AppendField(builder, finding.Category.ToString());
            builder.Append(',');
            AppendField(builder, ReportRendering.UtcText(finding.FirstSeenUtc));
            builder.Append(',');
            AppendField(builder, ReportRendering.UtcText(finding.LastSeenUtc));
            builder.Append(',');
            AppendField(builder, finding.Fingerprint.Hash);
            builder.Append(',');
            AppendField(builder, ReportRendering.ScoreText(finding.PriorityScore));
            builder.Append("\r\n");
        }

        return Task.FromResult(builder.ToString());
    }

    /// <summary>Appends one field, quoting and doubling quotes per RFC 4180 when required.</summary>
    private static void AppendField(StringBuilder builder, string value)
    {
        if (value.Contains(',') || value.Contains('"') || value.Contains('\r') || value.Contains('\n'))
        {
            builder.Append('"').Append(value.Replace("\"", "\"\"", StringComparison.Ordinal)).Append('"');
            return;
        }

        builder.Append(value);
    }
}
