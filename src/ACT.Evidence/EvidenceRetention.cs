using ACT.Contracts;

namespace ACT.Evidence;

/// <summary>Pure retention helpers for evidence items.</summary>
public static class EvidenceRetention
{
    /// <summary>
    /// Returns true when the item's age exceeds the retention period. Items exactly at the
    /// boundary are still retained; a non-positive period expires everything immediately.
    /// </summary>
    public static bool IsExpired(EvidenceItem item, TimeSpan retention, DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(item);
        return nowUtc - item.CapturedAtUtc > retention;
    }
}
