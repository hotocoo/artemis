
namespace ACT.Contracts;

/// <summary>Kinds of structured evidence the engine collects.</summary>
public enum EvidenceKind
{
    HttpRequestMetadata,
    HttpResponseMetadata,
    StatusCode,
    HttpHeaders,
    TlsMetadata,
    CertificateMetadata,
    DnsObservation,
    NetworkObservation,
    SourceLocation,
    DependencyMetadata,
    ConfigurationLocation,
    TestFixture,
    ExpectedResult,
    ActualResult,
    ToolVersion,
    CheckVersion,
    TargetScopeReference,
    TimingObservation,
    PolicyDecision
}

/// <summary>
/// One structured evidence item attached to a finding. Values are redacted before persistence.
/// JSON-serializable payload only; never credential material.
/// </summary>
public sealed record EvidenceItem(
    Guid EvidenceId,
    Guid FindingId,
    EvidenceKind Kind,
    string Key,
    string RedactedValue,
    DateTimeOffset CapturedAtUtc,
    CheckId CollectedBy,
    CorrelationId Correlation,
    IReadOnlyDictionary<string, string> Attributes);

/// <summary>Builds typed evidence items with automatic secret redaction applied at construction time.</summary>
public interface IEvidenceFactory
{
    /// <summary>Creates an evidence item, applying the configured redaction policy to the value.</summary>
    EvidenceItem Create(Guid findingId, EvidenceKind kind, string key, string value,
        CheckId collectedBy, CorrelationId correlation, IReadOnlyDictionary<string, string>? attributes = null);
}

/// <summary>Applies deterministic secret/token redaction before anything is persisted.</summary>
public interface IEvidenceRedactor
{
    /// <summary>Returns value with recognized secrets replaced by stable fingerprints.</summary>
    string Redact(string value);

    /// <summary>True when the header name is on the always-redact list (authorization, cookie, set-cookie, api keys).</summary>
    bool IsSensitiveHeader(string headerName);
}
