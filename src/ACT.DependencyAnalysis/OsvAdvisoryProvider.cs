
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using ACT.Contracts;

namespace ACT.DependencyAnalysis;

/// <summary>
/// Queries a single-package OSV-style endpoint injected via <see cref="Uri"/> from configuration
/// only. Transport failures degrade gracefully to empty results flagged as not current.
/// </summary>
public sealed class OsvAdvisoryProvider : ISecurityAdvisoryProvider, IDisposable
{
    private readonly Uri _endpoint;
    private readonly int _staleAfterDays;
    private readonly HttpClient _client;
    private DateTimeOffset? _lastSuccessfulQueryUtc;

    /// <summary>Creates the provider against one configured OSV query endpoint.</summary>
    public OsvAdvisoryProvider(Uri endpoint, int staleAfterDays = FeedDefaults.StaleAfterDays)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (endpoint.Scheme is not ("http" or "https"))
        {
            throw ActException.FailClosed(
                ErrorCategory.Configuration,
                "The OSV feed endpoint must use HTTP or HTTPS.",
                $"OsvAdvisoryProvider received scheme '{endpoint.Scheme}'.");
        }

        _endpoint = endpoint;
        _staleAfterDays = staleAfterDays > 0 ? staleAfterDays : FeedDefaults.StaleAfterDays;
        _client = new HttpClient(new SocketsHttpHandler
        {
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            AutomaticDecompression = DecompressionMethods.All
        })
        {
            Timeout = TimeSpan.FromSeconds(30)
        };
    }

    /// <inheritdoc/>
    public string Name => "osv:" + _endpoint.Host;

    /// <inheritdoc/>
    public async Task<AdvisoryLookupResult> QueryAsync(
        string ecosystem,
        string packageName,
        string version,
        CancellationToken cancellationToken)
    {
        var body = JsonSerializer.SerializeToUtf8Bytes(new QueryBody(
            new PackageRef(packageName, ecosystem), version));

        try
        {
            using var content = new ByteArrayContent(body);
            content.Headers.TryAddWithoutValidation("Content-Type", "application/json");
            using var response = await _client.PostAsync(_endpoint, content, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return Degraded(ecosystem, packageName, version, $"OSV query returned HTTP {(int)response.StatusCode}; no advisories can be claimed current.");
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
            using var document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken).ConfigureAwait(false);
            var advisories = ParseVulns(document.RootElement, ecosystem, packageName, version);

            // Only a fully successful round trip may advance the freshness marker.
            _lastSuccessfulQueryUtc = DateTimeOffset.UtcNow;
            return new AdvisoryLookupResult(ecosystem, packageName, version, advisories, Freshness());
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Degraded(ecosystem, packageName, version, "OSV query timed out; no advisories can be claimed current.");
        }
        catch (HttpRequestException)
        {
            return Degraded(ecosystem, packageName, version, "OSV endpoint unreachable (transport failure); results are degraded.");
        }
        catch (JsonException)
        {
            return Degraded(ecosystem, packageName, version, "OSV response was unparseable; results are degraded.");
        }
    }

    /// <inheritdoc/>
    public Task<FeedFreshness> GetFreshnessAsync(CancellationToken cancellationToken) =>
        Task.FromResult(Freshness());

    private FeedFreshness Freshness()
    {
        if (_lastSuccessfulQueryUtc is not { } last)
        {
            return new FeedFreshness(false, null, "No successful advisory refresh has completed yet; data cannot be presented as current.");
        }

        var isCurrent = DateTimeOffset.UtcNow - last <= TimeSpan.FromDays(_staleAfterDays);
        return new FeedFreshness(isCurrent, last, isCurrent
            ? $"Last successful refresh {last:O} is within the {_staleAfterDays}-day window."
            : $"Last successful refresh {last:O} exceeds the {_staleAfterDays}-day window.");
    }

    private AdvisoryLookupResult Degraded(string ecosystem, string packageName, string version, string note) =>
        new(ecosystem, packageName, version, [], new FeedFreshness(false, _lastSuccessfulQueryUtc, note));

    private List<AdvisoryRecord> ParseVulns(JsonElement root, string ecosystem, string packageName, string version)
    {
        var records = new List<AdvisoryRecord>();
        if (!root.TryGetProperty("vulns", out var vulns) || vulns.ValueKind != JsonValueKind.Array)
        {
            return records;
        }

        var retrievedAt = DateTimeOffset.UtcNow;
        foreach (var vuln in vulns.EnumerateArray())
        {
            var id = TryGetString(vuln, "id");
            if (id is null)
            {
                continue;
            }

            string? rangeExpression = null;
            string? fixedVersion = null;
            if (vuln.TryGetProperty("affected", out var affected) && affected.ValueKind == JsonValueKind.Array)
            {
                foreach (var affectedEntry in affected.EnumerateArray())
                {
                    if (!AffectedMatchesPackage(affectedEntry, packageName, ecosystem))
                    {
                        continue;
                    }

                    var (expression, fixedIn) = BuildRangeExpression(affectedEntry, version);
                    if (expression is not null)
                    {
                        rangeExpression = expression;
                        fixedVersion = fixedIn;
                        break;
                    }
                }
            }

            if (rangeExpression is null)
            {
                continue;
            }

            var severityText =
                (vuln.TryGetProperty("database_specific", out var dbSpecific)
                 && dbSpecific.ValueKind == JsonValueKind.Object
                 && dbSpecific.TryGetProperty("severity", out var sev) && sev.ValueKind == JsonValueKind.String)
                    ? sev.GetString()
                    : null;

            records.Add(new AdvisoryRecord(
                id,
                ecosystem,
                packageName,
                rangeExpression,
                fixedVersion,
                AdvisorySeverityMapper.Map(severityText),
                Name,
                retrievedAt,
                ComputeMetadataHash(id, rangeExpression, fixedVersion)));
        }

        return records;
    }

    private static bool AffectedMatchesPackage(JsonElement affectedEntry, string packageName, string ecosystem)
    {
        if (!affectedEntry.TryGetProperty("package", out var package) || package.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        var name = TryGetString(package, "name");
        var entryEcosystem = TryGetString(package, "ecosystem");
        return name is not null && name.Equals(packageName, StringComparison.OrdinalIgnoreCase)
               && entryEcosystem is not null && entryEcosystem.Equals(ecosystem, StringComparison.OrdinalIgnoreCase);
    }

    private static (string? Expression, string? FixedVersion) BuildRangeExpression(JsonElement affectedEntry, string version)
    {
        if (!affectedEntry.TryGetProperty("ranges", out var ranges) || ranges.ValueKind != JsonValueKind.Array)
        {
            // Fall back to explicit enumerated versions when present.
            if (affectedEntry.TryGetProperty("versions", out var versions) && versions.ValueKind == JsonValueKind.Array)
            {
                foreach (var listed in versions.EnumerateArray())
                {
                    if (listed.ValueKind == JsonValueKind.String && listed.GetString() == version)
                    {
                        return ("=" + version, null);
                    }
                }
            }

            return (null, null);
        }

        foreach (var range in ranges.EnumerateArray())
        {
            var rangeType = TryGetString(range, "type");
            if (rangeType is "GIT" or null)
            {
                continue;
            }

            string? introduced = null;
            string? fixedIn = null;
            if (range.TryGetProperty("events", out var events) && events.ValueKind == JsonValueKind.Array)
            {
                foreach (var eventEntry in events.EnumerateArray())
                {
                    if (eventEntry.ValueKind != JsonValueKind.Object)
                    {
                        continue;
                    }

                    if (introduced is null && eventEntry.TryGetProperty("introduced", out var intro))
                    {
                        var introValue = intro.ValueKind == JsonValueKind.String ? intro.GetString() : null;
                        introduced = string.IsNullOrEmpty(introValue) || introValue == "0" ? null : introValue;
                    }

                    fixedIn ??= eventEntry.TryGetProperty("fixed", out var fix) && fix.ValueKind == JsonValueKind.String ? fix.GetString() : null;
                }
            }

            var expression = (introduced, fixedIn) switch
            {
                ({ } i, { } f) => $">={i},<{f}",
                ({ } i, null) => $">={i}",
                (null, { } f) => $"<{f}",
                _ => null
            };

            if (expression is not null)
            {
                return (expression, fixedIn);
            }
        }

        return (null, null);
    }

    private static string? TryGetString(JsonElement element, string propertyName) =>
        element.TryGetProperty(propertyName, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString()
            : null;

    private static string ComputeMetadataHash(string id, string rangeExpression, string? fixedVersion)
    {
        var canonical = $"{id}|{rangeExpression}|{fixedVersion ?? string.Empty}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)).AsSpan(0, 8)).ToLowerInvariant();
    }

    /// <inheritdoc/>
    public void Dispose() => _client.Dispose();

    private sealed record QueryBody(PackageRef Package, string Version);

    private sealed record PackageRef(string Name, string Ecosystem);
}

