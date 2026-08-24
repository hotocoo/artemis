using System.Collections.Frozen;
using System.Globalization;
using System.Security;
using System.Text;
using ACT.Contracts;

namespace ACT.Reporting;

/// <summary>Output formats the assembler can render.</summary>
public enum ReportFormat
{
    /// <summary>Pretty, deterministic JSON.</summary>
    Json,

    /// <summary>RFC 4180 CSV table of findings.</summary>
    Csv,

    /// <summary>GitHub-flavored Markdown document.</summary>
    Markdown,

    /// <summary>Standalone styled HTML5 document.</summary>
    Html,

    /// <summary>SARIF 2.1.0 log for CI systems.</summary>
    Sarif
}

/// <summary>Renders reports through registered formatters and writes finished report files.</summary>
public sealed class ReportAssembler
{
    private readonly FrozenDictionary<ReportFormat, IReportFormatter> _formatters;

    /// <summary>Creates the assembler with built-in formatters, optionally overriding individual entries.</summary>
    public ReportAssembler(IReadOnlyDictionary<ReportFormat, IReportFormatter>? formatters = null)
    {
        var map = new Dictionary<ReportFormat, IReportFormatter>
        {
            [ReportFormat.Json] = new JsonReportFormatter(),
            [ReportFormat.Csv] = new CsvReportFormatter(),
            [ReportFormat.Markdown] = new MarkdownReportFormatter(),
            [ReportFormat.Html] = new HtmlReportFormatter(),
            [ReportFormat.Sarif] = new SarifReportFormatter(),
        };
        if (formatters is not null)
        {
            foreach (var pair in formatters)
            {
                map[pair.Key] = pair.Value;
            }
        }

        _formatters = map.ToFrozenDictionary();
    }

    /// <summary>Resolves the formatter registered for a format; fails closed when none is registered.</summary>
    public IReportFormatter Formatter(ReportFormat format) =>
        _formatters.TryGetValue(format, out var formatter)
            ? formatter
            : throw ActException.FailClosed(
                ErrorCategory.Report,
                "No renderer is available for the requested report format.",
                "No IReportFormatter registered for ReportFormat." + format + ".");

    /// <summary>Renders a full report document in the requested format.</summary>
    public async Task<string> RenderAsync(ReportInput input, ReportFormat format, CancellationToken cancellationToken) =>
        await Formatter(format).RenderAsync(input, cancellationToken).ConfigureAwait(false);

    /// <summary>
    /// Renders a report and writes it under <paramref name="directory"/> as a slugified
    /// assessment-name + UTC-timestamp filename; returns the full written path.
    /// </summary>
    public async Task<string> AssembleFileAsync(
        string directory,
        ReportInput input,
        ReportFormat format,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        var formatter = Formatter(format);
        var content = await RenderAsync(input, format, cancellationToken).ConfigureAwait(false);
        var fullPath = Path.Combine(directory, BuildFileName(input.Assessment.Name, input.GeneratedUtc, formatter.FileExtension));
        try
        {
            Directory.CreateDirectory(directory);
            await File.WriteAllTextAsync(fullPath, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false), cancellationToken).ConfigureAwait(false);
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or SecurityException or NotSupportedException)
        {
            throw ActException.FailClosed(
                ErrorCategory.Report,
                "The assembled report file could not be written.",
                "Writing '" + fullPath + "' failed: " + error.Message,
                error);
        }

        return Path.GetFullPath(fullPath);
    }

    /// <summary>Builds the slugified assessment-name plus UTC-timestamp file name.</summary>
    internal static string BuildFileName(string assessmentName, DateTimeOffset generatedUtc, string extension)
    {
        var stamp = generatedUtc.ToUniversalTime().ToString("yyyyMMdd'T'HHmmss'Z'", CultureInfo.InvariantCulture);
        return Slugify(assessmentName) + "-" + stamp + "." + extension;
    }

    /// <summary>Reduces a name to lowercase ASCII alphanumerics joined by single hyphens.</summary>
    internal static string Slugify(string name)
    {
        var builder = new StringBuilder(name.Length);
        var pendingHyphen = false;
        foreach (var character in name.Trim().ToLowerInvariant())
        {
            if (char.IsAsciiLetterOrDigit(character))
            {
                if (pendingHyphen && builder.Length > 0)
                {
                    builder.Append('-');
                }

                pendingHyphen = false;
                builder.Append(character);
            }
            else
            {
                pendingHyphen = builder.Length > 0;
            }
        }

        return builder.Length == 0 ? "report" : builder.ToString();
    }
}
