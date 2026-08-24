using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using ACT.Contracts;

namespace ACT.Lab;

/// <summary>Synthetic tenants, items, products, and jobs backing the lab's authorization and injection fixtures.</summary>
public static class LabData
{
    /// <summary>First synthetic tenant owning items i-1001 and i-1002.</summary>
    public const string TenantAlpha = "tenant-alpha";

    /// <summary>Second synthetic tenant owning item i-2001.</summary>
    public const string TenantBeta = "tenant-beta";

    private static readonly (string Id, string Owner)[] SeededItems =
    [
        ("i-1001", TenantAlpha),
        ("i-1002", TenantAlpha),
        ("i-2001", TenantBeta),
    ];

    private static readonly ConcurrentDictionary<string, string> ItemOwners = new(ItemOwnersSeed());

    private static readonly ConcurrentDictionary<string, DateTimeOffset> CreatedJobs = new();

    private static readonly string[] BenignFileNames = ["a.txt", "b.txt"];

    /// <summary>Synthetic product catalog used by the SQL-shaped fixtures (never a real database).</summary>
    public static IReadOnlyList<SyntheticProduct> Products { get; } =
    [
        new SyntheticProduct("SKU-1001", "SYNTHETIC alpha widget"),
        new SyntheticProduct("SKU-1002", "SYNTHETIC beta gadget"),
        new SyntheticProduct("SKU-1003", "SYNTHETIC gamma sprocket"),
        new SyntheticProduct("SKU-2001", "SYNTHETIC delta bracket"),
        new SyntheticProduct("SKU-2002", "SYNTHETIC epsilon bearing"),
        new SyntheticProduct("SKU-3001", "SYNTHETIC zeta valve"),
    ];

    /// <summary>Filesystem sandbox root served by the traversal fixture; populated by SeedAsync.</summary>
    public static string DataRoot { get; private set; } = string.Empty;

    /// <summary>Looks up the owning tenant of a synthetic item id.</summary>
    public static bool TryGetItemOwner(string itemId, [NotNullWhen(true)] out string? owner) =>
        ItemOwners.TryGetValue(itemId, out owner);

    /// <summary>Registers a synthetic queued job and returns its identifier.</summary>
    public static string CreateJob()
    {
        var jobId = Guid.NewGuid().ToString("N");
        CreatedJobs[jobId] = DateTimeOffset.UtcNow;
        return jobId;
    }

    /// <summary>Number of synthetic jobs queued since the last reset.</summary>
    public static int JobCount => CreatedJobs.Count;

    /// <summary>Restores every mutable fixture collection to its seeded state.</summary>
    public static void Reset()
    {
        ItemOwners.Clear();
        foreach (var (id, owner) in SeededItems)
        {
            ItemOwners[id] = owner;
        }

        CreatedJobs.Clear();
    }

    /// <summary>Creates the labdata sandbox under the content root with benign fixture files; fails closed.</summary>
    public static async Task SeedAsync(string contentRootPath, CancellationToken cancellationToken)
    {
        try
        {
            DataRoot = Path.Combine(contentRootPath, "labdata");
            Directory.CreateDirectory(DataRoot);
            foreach (var fileName in BenignFileNames)
            {
                await File.WriteAllTextAsync(
                    Path.Combine(DataRoot, fileName),
                    $"benign synthetic lab fixture ({fileName})\n",
                    cancellationToken);
            }
        }
        catch (Exception failure) when (failure is IOException or UnauthorizedAccessException or ArgumentException)
        {
            throw ActException.FailClosed(
                ErrorCategory.Configuration,
                "Preparing the lab's synthetic data directory failed.",
                $"LabData seed under '{contentRootPath}' failed: {failure.Message}",
                failure);
        }
    }

    private static Dictionary<string, string> ItemOwnersSeed() =>
        SeededItems.ToDictionary(static item => item.Id, static item => item.Owner, StringComparer.Ordinal);
}

/// <summary>One synthetic product row used by the SQL-shaped fixtures.</summary>
public sealed record SyntheticProduct(string Sku, string Name);
