namespace ACT.Reporting;

/// <summary>Renders one complete assessment report in a specific output format.</summary>
public interface IReportFormatter
{
    /// <summary>MIME content type of the produced documents.</summary>
    string ContentType { get; }

    /// <summary>File extension without the leading dot.</summary>
    string FileExtension { get; }

    /// <summary>Renders the full report document for the supplied input.</summary>
    Task<string> RenderAsync(ReportInput input, CancellationToken cancellationToken);
}
