
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ACT.Contracts;

namespace ACT.DependencyAnalysis;

/// <summary>
/// Serves vulnerability advisories from a locally managed JSON snapshot file. When an expected
/// SHA-256 is configured, the snapshot must match exactly or loading fails closed.
/// </summary>
public sealed class OfflineFileAdvisoryProvider : ISecurityAdvisoryProvider
{
    private static readonly string[] SupportedEcosystems =
    [
        "NuGet",
        "npm",
        "PyPI",
        "crates.io"
    ];

    private readonly string _path;
    private readonly string? _expectedSha256;
    private readonly int _staleAfterDays;
    private readonly SemaphoreSlim _loadGate = new(1, 1);
    private Snapshot? _snapshot;

    /// <summary>Creates the provider; the snapshot loads lazily on first use.</summary>
    public OfflineFileAdvisoryProvider(string path, string? expectedSha256 = null, int staleAfterDays = 7)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw ActException.FailClosed(
                ErrorCategory.Configuration,
                "An advisory snapshot path is required for offline feed sources.",
                "OfflineFileAdvisoryProvider received an empty path.");
        }

        _path = path;
        _expectedSha256 = string.IsNullOrWhiteSpace(expectedSha256) ? null : expectedSha256.Trim();
        _staleAfterDays = staleAfterDays > 0 ? staleAfterDays : FeedDefaults.StaleAfterDays;
    }

    /// <inheritdoc/>
    public string Name => "offline-file:" + Path.GetFileName(_path);

    /// <inheritdoc/>
    public async Task<AdvisoryLookupResult> QueryAsync(
        string ecosystem,
        string packageName,
        string version,
        CancellationToken cancellationToken)
    {
        var snapshot = await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false);

        SnapshotPackage? matched = null;
        foreach (var package in snapshot.Packages)
        {
            if (package.Name.Equals(packageName, StringComparison.OrdinalIgnoreCase)
                && EcosystemMatches(package.Ecosystem, ecosystem))
            {
                matched = package;
                break;
            }
        }

        var now = DateTimeOffset.UtcNow;
        var advisories = new List<AdvisoryRecord>();
        foreach (var raw in matched?.Advisories ?? [])
        {
            RangeSpec range;
            try
            {
                range = RangeSpec.Parse(raw.AffectedRange);
            }
            catch (ActException)
            {
                continue;
            }

            if (!range.Satisfied(version))
            {
                continue;
            }

            advisories.Add(new AdvisoryRecord(
                raw.Id,
                ecosystem,
                packageName,
                raw.AffectedRange,
                raw.FixedVersion,
                AdvisorySeverityMapper.Map(raw.Severity),
                Name,
                now,
                ComputeMetadataHash(raw.Id, raw.AffectedRange, raw.FixedVersion)));
        }

        return new AdvisoryLookupResult(ecosystem, packageName, version, advisories, ComputeFreshness(snapshot));
    }

    /// <inheritdoc/>
    public async Task<FeedFreshness> GetFreshnessAsync(CancellationToken cancellationToken) =>
        ComputeFreshness(await EnsureLoadedAsync(cancellationToken).ConfigureAwait(false));

    private FeedFreshness ComputeFreshness(Snapshot snapshot)
    {
        var age = DateTimeOffset.UtcNow - snapshot.UpdatedAtUtc;
        var isCurrent = age <= TimeSpan.FromDays(_staleAfterDays);
        var note = isCurrent
            ? $"Snapshot retrieved {snapshot.UpdatedAtUtc:O} is inside the {_staleAfterDays}-day freshness window."
            : $"Snapshot retrieved {snapshot.UpdatedAtUtc:O} is older than {_staleAfterDays} day(s); results are stale.";
        return new FeedFreshness(isCurrent, snapshot.UpdatedAtUtc, note);
    }

    private async Task<Snapshot> EnsureLoadedAsync(CancellationToken cancellationToken)
    {
        if (_snapshot is not null)
        {
            return _snapshot;
        }

        await _loadGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            _snapshot ??= await LoadCoreAsync(cancellationToken).ConfigureAwait(false);
            return _snapshot;
        }
        finally
        {
            _loadGate.Release();
        }
    }

    private async Task<Snapshot> LoadCoreAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(_path))
        {
            throw ActException.FailClosed(
                ErrorCategory.ExternalFeed,
                "The offline advisory snapshot file does not exist.",
                $"Snapshot missing at '{_path}'.");
        }

        byte[] bytes;
        try
        {
            bytes = await File.ReadAllBytesAsync(_path, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw ActException.FailClosed(
                ErrorCategory.ExternalFeed,
                "The offline advisory snapshot could not be read.",
                $"Snapshot '{_path}' read failure: {ex.GetType().Name}: {ex.Message}",
                ex);
        }

        VerifyIntegrity(bytes);

        JsonDocument document;
        try
        {
            await using var content = new MemoryStream(bytes).ConfigureAwait(false);
            document = await JsonDocument.ParseAsync(content, cancellationToken: cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (JsonException ex)
        {
            throw ActException.FailClosed(
                ErrorCategory.ExternalFeed,
                "The offline advisory snapshot is not valid JSON.",
                $"Snapshot '{_path}' failed JSON parse: {ex.Message}",
                ex);
        }

        using (document)
        {
            return ParseSnapshot(document.RootElement);
        }
    }

    private void VerifyIntegrity(byte[] bytes)
    {
        if (_expectedSha256 is null)
        {
            return;
        }

        var actual = Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
        if (!string.Equals(actual, _expectedSha256.ToLowerInvariant(), StringComparison.Ordinal))
        {
            throw ActException.FailClosed(
                ErrorCategory.ExternalFeed,
                "The advisory snapshot failed its integrity verification and was rejected.",
                $"Snapshot '{_path}' expected sha256 {_expectedSha256} but computed {actual}.");
        }
    }

    private static bool EcosystemMatches(string snapshotEcosystem, string requestedEcosystem)
    {
        foreach (var supported in SupportedEcosystems)
        {
            if (supported.Equals(requestedEcosystem, StringComparison.OrdinalIgnoreCase))
            {
                return snapshotEcosystem.Equals(requestedEcosystem, StringComparison.OrdinalIgnoreCase);
            }
        }

        return snapshotEcosystem.Equals(requestedEcosystem, StringComparison.OrdinalIgnoreCase);
    }

    private Snapshot ParseSnapshot(JsonElement root)
    {
        var updatedAtText = root.TryGetProperty("updatedAt", out var updatedElement) && updatedElement.ValueKind == JsonValueKind.String
            ? updatedElement.GetString()
            : null;
        if (updatedAtText is null
            || !DateTimeOffset.TryParse(updatedAtText, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AssumeUniversal, out var updatedAt))
        {
            throw ActException.FailClosed(
                ErrorCategory.ExternalFeed,
                "The advisory snapshot has no usable retrieval timestamp.",
                $"Snapshot '{_path}' lacks a valid ISO 'updatedAt' value.");
        }

        var packages = new List<SnapshotPackage>();
        if (root.TryGetProperty("packages", out var packagesElement) && packagesElement.ValueKind == JsonValueKind.Array)
        {
            foreach (var packageElement in packagesElement.EnumerateArray())
            {
                var name = TryGetString(packageElement, "name");
                var ecosystem = TryGetString(packageElement, "ecosystem");
                if (name is null || ecosystem is null)
                {
                    continue;
                }

                var advisories = new List<SnapshotAdvisory>();
                if (packageElement.TryGetProperty("advisories", out var advisoriesElement) && advisoriesElement.ValueKind == JsonValueKind.Array)
                {
                    foreach (var advisoryElement in advisoriesElement.EnumerateArray())
                    {
                        var id = TryGetString(advisoryElement, "id");
                        var affectedRange = TryGetString(advisoryElement, "affectedRange");
                        if (id is null || affectedRange is null)
                        {
                            continue;
                        }

                        advisories.Add(new SnapshotAdvisory(
                            id,
                            TryGetString(advisoryElement, "severity"),
                            affectedRange,
                            TryGetString(advisoryElement, "fixedVersion")));
                    }
                }

                packages.Add(new SnapshotPackage(ecosystem, name, advisories));
            }
        }

        return new Snapshot(updatedAt, packages);
    }

    private static string? TryGetString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;

    private static string ComputeMetadataHash(string id, string affectedRange, string? fixedVersion)
    {
        var canonical = $"{id}|{affectedRange}|{fixedVersion ?? string.Empty}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)).AsSpan(0, 8)).ToLowerInvariant();
    }

    private sealed record Snapshot(DateTimeOffset UpdatedAtUtc, IReadOnlyList<SnapshotPackage> Packages);

    private sealed record SnapshotPackage(string Ecosystem, string Name, IReadOnlyList<SnapshotAdvisory> Advisories);

    private sealed record SnapshotAdvisory(string Id, string? Severity, string AffectedRange, string? FixedVersion);
}

