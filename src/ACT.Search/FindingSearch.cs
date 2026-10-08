using ACT.Contracts;

namespace ACT.Search;

public record FindingSearchQuery(
    string? Keyword,
    Severity? MinSeverity,
    Severity? MaxSeverity,
    string? CheckId,
    string? Asset,
    string? Status,
    string? AssignedTo,
    DateTimeOffset? CreatedAfter,
    DateTimeOffset? CreatedBefore,
    int Page,
    int PageSize,
    string? SortBy,
    bool SortDescending);

public record FindingSearchResult(
    IReadOnlyList<Finding> Findings,
    int TotalCount,
    int Page,
    int PageSize);

public class FindingSearchService
{
    public FindingSearchResult Search(IReadOnlyList<Finding> findings, FindingSearchQuery query)
    {
        var filtered = findings.AsEnumerable();

        if (!string.IsNullOrEmpty(query.Keyword))
        {
            var keyword = query.Keyword.ToLowerInvariant();
            filtered = filtered.Where(f =>
                f.Title.ToLowerInvariant().Contains(keyword) ||
                f.Description.ToLowerInvariant().Contains(keyword) ||
                f.FindingId.ToString().ToLowerInvariant().Contains(keyword));
        }

        if (query.MinSeverity.HasValue)
        {
            filtered = filtered.Where(f => f.TechnicalSeverity >= query.MinSeverity.Value);
        }

        if (query.MaxSeverity.HasValue)
        {
            filtered = filtered.Where(f => f.TechnicalSeverity <= query.MaxSeverity.Value);
        }

        if (!string.IsNullOrEmpty(query.CheckId))
        {
            filtered = filtered.Where(f => f.CheckId.Value == query.CheckId);
        }

        if (!string.IsNullOrEmpty(query.Asset))
        {
            filtered = filtered.Where(f => f.AssetReference == query.Asset);
        }

        if (!string.IsNullOrEmpty(query.Status))
        {
            filtered = filtered.Where(f => f.Status.ToString() == query.Status);
        }

        if (query.CreatedAfter.HasValue)
        {
            filtered = filtered.Where(f => f.FirstSeenUtc >= query.CreatedAfter.Value);
        }

        if (query.CreatedBefore.HasValue)
        {
            filtered = filtered.Where(f => f.FirstSeenUtc <= query.CreatedBefore.Value);
        }

        // Sort
        filtered = query.SortBy switch
        {
            "severity" => query.SortDescending
                ? filtered.OrderByDescending(f => f.TechnicalSeverity)
                : filtered.OrderBy(f => f.TechnicalSeverity),
            "created" => query.SortDescending
                ? filtered.OrderByDescending(f => f.FirstSeenUtc)
                : filtered.OrderBy(f => f.FirstSeenUtc),
            "title" => query.SortDescending
                ? filtered.OrderByDescending(f => f.Title)
                : filtered.OrderBy(f => f.Title),
            _ => filtered.OrderByDescending(f => f.TechnicalSeverity).ThenBy(f => f.Title)
        };

        var totalCount = filtered.Count();
        var page = filtered
            .Skip(query.Page * query.PageSize)
            .Take(query.PageSize)
            .ToArray();

        return new FindingSearchResult(page, totalCount, query.Page, query.PageSize);
    }
}
