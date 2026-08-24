
using System.Text;
using System.Text.Json;
using ACT.Contracts;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace ACT.DependencyAnalysis;

/// <summary>
/// Wraps any advisory provider with a persistent retrieval-metadata sidecar so that freshness
/// survives restarts and staleness is always reported honestly, never silently hidden.
/// </summary>
public sealed class CachingFeedProvider : ISecurityAdvisoryProvider
{
    private readonly ISecurityAdvisoryProvider _inner;
    private readonly string _sidecarPath;
    private readonly int _staleAfterDays;
    private readonly SemaphoreSlim _sidecarGate = new(1, 1);
    private readonly ILogger _logger;

    /// <summary>Creates a caching wrapper around the given provider.</summary>
    public CachingFeedProvider(ISecurityAdvisoryProvider inner, string cacheDirectory,
        int staleAfterDays = FeedDefaults.StaleAfterDays, ILogger? logger = null)
    {
        ArgumentNullException.ThrowIfNull(inner);
        if (string.IsNullOrWhiteSpace(cacheDirectory))
        {
            throw ActException.FailClosed(
                ErrorCategory.Configuration,
                "A cache directory is required for feed caching.",
                "CachingFeedProvider received an empty cache directory.");
        }

        _inner = inner;
        _staleAfterDays = staleAfterDays > 0 ? staleAfterDays : FeedDefaults.StaleAfterDays;
        _logger = logger ?? NullLogger.Instance;
        _sidecarPath = Path.Combine(cacheDirectory, "feed-" + Sanitize(inner.Name) + ".meta.json");
    }

    /// <inheritdoc/>
    public string Name => _inner.Name;

    /// <inheritdoc/>
    public async Task<AdvisoryLookupResult> QueryAsync(
        string ecosystem,
        string packageName,
        string version,
        CancellationToken cancellationToken)
    {
        var result = await _inner.QueryAsync(ecosystem, packageName, version, cancellationToken).ConfigureAwait(false);
        if (result.Freshness.IsCurrent)
        {
            await TryPersistRefreshAsync(result.Freshness.LastUpdatedUtc, result.Freshness.Note, cancellationToken).ConfigureAwait(false);
        }

        return result;
    }

    /// <inheritdoc/>
    public async Task<FeedFreshness> GetFreshnessAsync(CancellationToken cancellationToken)
    {
        var innerFreshness = await _inner.GetFreshnessAsync(cancellationToken).ConfigureAwait(false);
        var sidecarTimestamp = TryReadSidecarTimestamp();

        DateTimeOffset? effective = innerFreshness.LastUpdatedUtc;
        if (sidecarTimestamp is { } persisted && (effective is not { } innerTime || persisted > innerTime))
        {
            effective = persisted;
        }

        var isCurrent = effective is { } stamp
                        && DateTimeOffset.UtcNow - stamp <= TimeSpan.FromDays(_staleAfterDays);
        var note = $"{innerFreshness.Note} Persisted retrieval record: {(sidecarTimestamp is { } t ? t.ToString("O") : "none")}.";
        return new FeedFreshness(isCurrent, effective, note);
    }

    /// <summary>Absolute path of the metadata sidecar file.</summary>
    public string SidecarPath => _sidecarPath;

    private async Task TryPersistRefreshAsync(DateTimeOffset? lastUpdatedUtc, string note, CancellationToken ct)
    {
        try
        {
            await _sidecarGate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(_sidecarPath)!);
                var payload = JsonSerializer.Serialize(new SidecarDocument(
                    _inner.Name,
                    (lastUpdatedUtc ?? DateTimeOffset.UtcNow).ToString("O"),
                    note));
                var temporary = _sidecarPath + ".tmp";
                await File.WriteAllTextAsync(temporary, payload, Encoding.UTF8, ct).ConfigureAwait(false);
                File.Move(temporary, _sidecarPath, overwrite: true);
            }
            finally
            {
                _sidecarGate.Release();
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            // Cache bookkeeping failure must never break the query itself.
            _logger.LogDebug("Feed sidecar write failed for {Path}: {Detail}", _sidecarPath, ex.Message);
        }
    }

    private DateTimeOffset? TryReadSidecarTimestamp()
    {
        try
        {
            if (!File.Exists(_sidecarPath))
            {
                return null;
            }

            using var document = JsonDocument.Parse(File.ReadAllBytes(_sidecarPath));
            if (document.RootElement.TryGetProperty("lastSuccessfulRefreshUtc", out var property)
                && property.ValueKind == JsonValueKind.String
                && property.GetString() is { } text
                && DateTimeOffset.TryParse(text, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var parsed))
            {
                return parsed;
            }

            return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            return null;
        }
    }

    private static string Sanitize(string name)
    {
        var builder = new StringBuilder(name.Length);
        foreach (var character in name)
        {
            builder.Append(char.IsAsciiLetterOrDigit(character) ? character : '-');
        }

        return builder.ToString();
    }

    private sealed record SidecarDocument(string ProviderName, string LastSuccessfulRefreshUtc, string Note);
}

