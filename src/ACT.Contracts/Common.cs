
namespace ACT.Contracts;

/// <summary>Categorizes every error the product can raise. Used for fail-closed routing and safe user messages.</summary>
public enum ErrorCategory
{
    Configuration,
    Scope,
    Network,
    Authorization,
    Parser,
    SecurityCheck,
    Persistence,
    Report,
    ExternalFeed,
    Llm,
    Internal
}

/// <summary>
/// Base exception for all product errors. Carries a machine-readable category, a safe user-facing
/// message, and detailed diagnostics that must only reach logs, never the UI.
/// </summary>
public class ActException : Exception
{
    public ErrorCategory Category { get; }
    /// <summary>Safe message suitable for display. Must never contain secrets or raw target content.</summary>
    public string SafeMessage { get; }
    /// <summary>Detailed diagnostics for logs only.</summary>
    public string DiagnosticDetail { get; }

    public ActException(ErrorCategory category, string safeMessage, string diagnosticDetail,
        Exception? innerException = null)
        : base(safeMessage, innerException)
    {
        Category = category;
        SafeMessage = safeMessage;
        DiagnosticDetail = diagnosticDetail;
    }

    public static ActException FailClosed(ErrorCategory category, string safeMessage, string diagnosticDetail,
        Exception? innerException = null)
        => new(category, safeMessage + " The operation failed closed.", diagnosticDetail, innerException);
}

/// <summary>A stable, strongly-typed identifier for a built-in or plugin security check.</summary>
public readonly record struct CheckId(string Value)
{
    public override string ToString() => Value;
    public static CheckId From(string value) => new(value.Trim().ToUpperInvariant());
}

/// <summary>Correlation identifier threaded through logs, evidence, and audit entries.</summary>
public readonly record struct CorrelationId(Guid Value)
{
    public static CorrelationId New() => new(Guid.NewGuid());
    public override string ToString() => Value.ToString("N");
}

/// <summary>Result of an operation that either succeeded or failed closed with a categorized reason.</summary>
public sealed record OperationOutcome(bool Succeeded, string? ReasonCode, string? SafeMessage)
{
    public static OperationOutcome Ok() => new(true, null, null);
    public static OperationOutcome Rejected(string reasonCode, string safeMessage) => new(false, reasonCode, safeMessage);
}
