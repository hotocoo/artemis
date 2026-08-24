using System.Globalization;
using ACT.Contracts;

namespace ACT.Evidence;

/// <summary>
/// Evidence factory that applies redaction at construction time and stamps every item with
/// DateTimeOffset.UtcNow as its capture time. Sensitive-header keys are redacted wholesale so
/// opaque values (cookies, API keys) can never survive persistence.
/// </summary>
public sealed class EvidenceFactory : IEvidenceFactory
{
    private readonly IEvidenceRedactor _redactor;

    /// <summary>Creates the factory; a redactor is required.</summary>
    public EvidenceFactory(IEvidenceRedactor redactor)
    {
        _redactor = redactor ?? throw new ArgumentNullException(nameof(redactor));
    }

    /// <inheritdoc />
    public EvidenceItem Create(Guid findingId, EvidenceKind kind, string key, string value,
        CheckId collectedBy, CorrelationId correlation, IReadOnlyDictionary<string, string>? attributes = null)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            throw new ArgumentException("An evidence key is required.", nameof(key));
        }

        ArgumentNullException.ThrowIfNull(value);

        var redactedValue = _redactor switch
        {
            StandardEvidenceRedactor standard => standard.RedactHeaderValue(key, value),
            _ when _redactor.IsSensitiveHeader(key) => "REDACTED(len=" + value.Length.ToString(CultureInfo.InvariantCulture) + ")",
            _ => _redactor.Redact(value)
        };

        return new EvidenceItem(
            EvidenceId: Guid.NewGuid(),
            FindingId: findingId,
            Kind: kind,
            Key: key.Trim(),
            RedactedValue: redactedValue,
            CapturedAtUtc: DateTimeOffset.UtcNow,
            CollectedBy: collectedBy,
            Correlation: correlation,
            Attributes: Freeze(attributes));
    }

    private static IReadOnlyDictionary<string, string> Freeze(IReadOnlyDictionary<string, string>? attributes) =>
        attributes is null || attributes.Count == 0
            ? new Dictionary<string, string>()
            : attributes.ToDictionary(static pair => pair.Key, static pair => pair.Value, StringComparer.Ordinal);
}
