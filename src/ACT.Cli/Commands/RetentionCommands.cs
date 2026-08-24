
using System.Text;
using System.Text.Json;
using ACT.Contracts;
using ACT.Persistence;
using Microsoft.Extensions.DependencyInjection;

namespace ACT.Cli;

/// <summary>artemis retention status|sweep - evidence lifecycle against scope-configured windows.</summary>
public static class RetentionCommands
{
    public static async Task<int> Run(IServiceProvider services, string[] args)
    {
        if (args.Length == 0)
        {
            return Usage();
        }

        var db = services.GetRequiredService<ActDatabase>();
        await db.InitializeAsync();

        return args[0] switch
        {
            "status" => await StatusAsync(services, db),
            "sweep" => await SweepAsync(services, db, args[1..]),
            _ => Usage()
        };

        static int Usage()
        {
            Console.Error.WriteLine("usage: artemis retention status");
            Console.Error.WriteLine("       artemis retention sweep [--dry-run] [--secure]");
            Console.Error.WriteLine();
            Console.Error.WriteLine("Each scope's own EvidenceRetentionPeriod governs its evidence; evidence exactly at");
            Console.Error.WriteLine("the boundary is retained. --secure additionally truncates the write-ahead log after a");
            Console.Error.WriteLine("sweep so freed pages stop surviving in sidecar journals.");
            return ExitCodes.UsageError;
        }
    }

    private static async Task<int> StatusAsync(IServiceProvider services, ActDatabase db)
    {
        var preview = await new RetentionSweeper(db).PreviewAsync();
        var pending = preview.Sum(row => row.ExpiredCount);

        var text = new StringBuilder();
        text.AppendLine(string.Format("{0,-38} {1,-14} {2,-22} {3}",
            "SCOPE", "WINDOW", "CUTOFF (UTC)", "EXPIRED EVIDENCE"));
        foreach (var row in preview)
        {
            text.AppendLine(string.Format("{0,-38} {1,-14} {2,-22} {3}",
                row.ScopeId.ToString(),
                DescribeWindow(row.RetentionPeriod),
                row.CutoffUtc.ToString("yyyy-MM-dd HH:mm:ss"),
                row.ExpiredCount));
        }

        text.AppendLine();
        text.AppendLine(pending > 0
            ? $"{pending} evidence item(s) past their configured window. Run 'artemis retention sweep' to remove them."
            : "No evidence is past its configured retention window.");

        var json = JsonSerializer.Serialize(new
        {
            scopes = preview.Select(row => new
            {
                scopeId = row.ScopeId,
                retentionPeriod = row.RetentionPeriod.ToString(),
                cutoffUtc = row.CutoffUtc,
                expiredCount = row.ExpiredCount
            }),
            pendingTotal = pending
        }, JsonOpts.Indented);
        return await OutputWriter.WriteAsync(services, text.ToString(), json);
    }

    private static async Task<int> SweepAsync(IServiceProvider services, ActDatabase db, string[] args)
    {
        var dryRun = args.Contains("--dry-run");
        var secureWipe = args.Contains("--secure");
        var sweeper = new RetentionSweeper(db);

        if (dryRun)
        {
            var preview = await sweeper.PreviewAsync();
            var wouldDelete = preview.Sum(row => row.ExpiredCount);
            var dryText = new StringBuilder();
            dryText.AppendLine($"dry run: {wouldDelete} evidence item(s) would be removed across {preview.Count} scope(s)");
            foreach (var row in preview.Where(row => row.ExpiredCount > 0))
            {
                dryText.AppendLine($"  {row.ScopeId} (window {DescribeWindow(row.RetentionPeriod)}): {row.ExpiredCount}");
            }

            var dryJson = JsonSerializer.Serialize(new
            {
                dryRun = true,
                secureWipe,
                wouldDeleteTotal = wouldDelete,
                scopes = preview.Select(row => new
                {
                    scopeId = row.ScopeId,
                    retentionPeriod = row.RetentionPeriod.ToString(),
                    cutoffUtc = row.CutoffUtc,
                    expiredCount = row.ExpiredCount
                })
            }, JsonOpts.Indented);
            return await OutputWriter.WriteAsync(services, dryText.ToString(), dryJson);
        }

        var result = await sweeper.SweepAsync(secureWipe);
        await db.AppendAuditAsync(new AuditDraft(
            Actor: "operator",
            Action: "evidence.retention_swept",
            ObjectType: "evidence",
            ObjectId: "retention:" + Guid.NewGuid().ToString("N"),
            Result: $"{result.TotalDeleted} deleted (secureWipe={result.SecureWipe})",
            Correlation: CorrelationId.New()));

        var text = new StringBuilder();
        text.AppendLine($"sweep complete: {result.TotalDeleted} evidence item(s) removed"
            + (result.SecureWipe ? ", write-ahead log truncated" : ""));
        foreach (var scope in result.Scopes.Where(scope => scope.DeletedCount > 0))
        {
            text.AppendLine($"  {scope.ScopeId} (window {DescribeWindow(scope.RetentionPeriod)}): {scope.DeletedCount}");
        }

        var json = JsonSerializer.Serialize(new
        {
            sweptAtUtc = result.SweptAtUtc,
            deletedTotal = result.TotalDeleted,
            secureWipe = result.SecureWipe,
            scopes = result.Scopes.Select(scope => new
            {
                scopeId = scope.ScopeId,
                retentionPeriod = scope.RetentionPeriod.ToString(),
                deletedCount = scope.DeletedCount
            })
        }, JsonOpts.Indented);
        return await OutputWriter.WriteAsync(services, text.ToString(), json);
    }

    private static string DescribeWindow(TimeSpan period) =>
        period >= TimeSpan.FromDays(1)
            ? (period.Days == 1 ? "1 day" : period.Days + " days")
            : period.ToString();
}
