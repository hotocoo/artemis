using System.Text.Json;
using ACT.Contracts;
using ACT.Persistence;
using Microsoft.Extensions.DependencyInjection;

namespace ACT.Cli;

/// <summary>artemis asset list - the discovered asset and service inventory, read-only.</summary>
public static class AssetCommands
{
    public static async Task<int> Run(IServiceProvider services, string[] args)
    {
        if (args.Length == 0 || args[0] != "list")
        {
            Console.Error.WriteLine("usage: artemis asset list [--assessment ID] [--json]");
            return ExitCodes.UsageError;
        }

        Guid? assessment = null;
        for (var i = 1; i < args.Length - 1; i++)
        {
            if (args[i] == "--assessment" && Guid.TryParse(args[i + 1], out var parsed)) assessment = parsed;
        }

        var db = services.GetRequiredService<ActDatabase>();
        // Read commands own their readiness: no host runs migrations on their behalf.
        await db.InitializeAsync();
        var assets = await db.ListAssetsAsync(assessment, 500);
        // One joined query grouped here keeps the CLI from issuing per-asset reads.
        var byAsset = (await db.ListServicesAsync(assessment, 100_000))
            .GroupBy(s => s.AssetId)
            .ToDictionary(group => group.Key, group => group.ToList());

        var rows = assets.Select(asset =>
            {
                var observed = byAsset.TryGetValue(asset.AssetId, out var found) ? found : [];
                return (Asset: asset, Observed: (IReadOnlyList<ServiceObservation>)observed);
            })
            .ToList();

        return await OutputWriter.WriteAsync(services,
            rows.Count == 0 ? "no assets discovered" : string.Join(Environment.NewLine, rows.Select(FormatRow)),
            JsonSerializer.Serialize(rows.Select(ToJson), JsonOpts.Indented));
    }

    /// <summary>One human-readable line per asset; out-of-scope discoveries stay permanently visible.</summary>
    private static string FormatRow((AssetRecord Asset, IReadOnlyList<ServiceObservation> Observed) row)
    {
        var asset = row.Asset;
        var ips = asset.ObservedIps.Count > 0 ? "ips=" + string.Join(",", asset.ObservedIps) + " " : "";
        var ports = row.Observed.Count > 0
            ? "services=" + string.Join(",", row.Observed
                .OrderByDescending(s => s.TlsNegotiated).ThenBy(s => s.Port)
                .Select(ServiceLabel))
            : "services=none";
        var scopeTag = asset.WithinScope ? "in-scope     " : "OUT-OF-SCOPE ";
        return "[" + asset.Kind + "] " + scopeTag + asset.CanonicalTarget
            + " (" + asset.DisplayName + ") " + ips + ports;
    }

    private static string ServiceLabel(ServiceObservation service) =>
        service.Port + "/" + service.Protocol + (service.TlsNegotiated ? "+tls" : "");

    private static object ToJson((AssetRecord Asset, IReadOnlyList<ServiceObservation> Observed) row) => new
    {
        row.Asset.AssetId,
        kind = row.Asset.Kind.ToString(),
        name = row.Asset.DisplayName,
        canonicalTarget = row.Asset.CanonicalTarget,
        observedIps = row.Asset.ObservedIps,
        withinScope = row.Asset.WithinScope,
        discoveredUtc = row.Asset.DiscoveredAtUtc,
        services = row.Observed.Select(s => new
        {
            s.ServiceId,
            s.Port,
            protocol = s.Protocol.ToString(),
            banner = s.Banner,
            tlsNegotiated = s.TlsNegotiated,
            observedUtc = s.ObservedAtUtc,
            sourceCheck = s.SourceCheck.Value
        })
    };
}
