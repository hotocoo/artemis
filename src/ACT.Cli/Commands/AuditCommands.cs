using System.Text;
using System.Text.Json;
using ACT.Persistence;
using Microsoft.Extensions.DependencyInjection;

namespace ACT.Cli;

/// <summary>
/// artemis audit verify|list|export - read access to the tamper-evident audit ledger. The chain
/// proves history has not been rewritten; these commands make that proof usable from a terminal.
/// </summary>
public static class AuditCommands
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
            "verify" => await VerifyAsync(services, db),
            "list" => await ListAsync(services, db, args[1..]),
            "export" => await ExportAsync(services, db, args[1..]),
            _ => Usage()
        };

        static int Usage()
        {
            Console.Error.WriteLine("usage: artemis audit verify [--json]");
            Console.Error.WriteLine("       artemis audit list [--limit N] [--action PREFIX] [--correlation ID] [--json]");
            Console.Error.WriteLine("       artemis audit export --format json|csv [--output PATH]");
            Console.Error.WriteLine();
            Console.Error.WriteLine("verify walks every hash link and reports the FIRST broken sequence; it exits 5");
            Console.Error.WriteLine("(gate failed) when verification fails so pipelines can refuse to ship. export");
            Console.Error.WriteLine("writes the complete ledger oldest-first for external archiving - keep a copy");
            Console.Error.WriteLine("outside this machine: only an external copy can expose loss of the newest rows.");
            return ExitCodes.UsageError;
        }
    }

    private static async Task<int> VerifyAsync(IServiceProvider services, ActDatabase db)
    {
        var verification = await db.VerifyChainDetailedAsync();
        var text = new StringBuilder();
        if (verification.Verified)
        {
            text.Append("hash chain verified over ").Append(verification.EventCount).Append(" audit event(s).");
        }
        else
        {
            text.AppendLine("HASH CHAIN VERIFICATION FAILED - the audit log may have been tampered with.");
            text.AppendLine("  first broken entry: sequence ").Append(verification.FirstBrokenSequence);
            text.AppendLine("  reason: ").Append(verification.Reason);
            text.AppendLine("  events verified before failure: ").Append(verification.EventCount);
            text.Append("Preserve this database as evidence and investigate before trusting any finding,");
            text.Append(" triage decision, or baseline derived from it.");
        }

        var json = JsonSerializer.Serialize(new
        {
            verified = verification.Verified,
            eventCount = verification.EventCount,
            firstBrokenSequence = verification.FirstBrokenSequence,
            reason = verification.Reason
        }, JsonOpts.Indented);

        // The verdict rides the exit code so CI can refuse to proceed on a broken chain without
        // parsing output, exactly like baseline compare does for drift.
        var write = await OutputWriter.WriteAsync(services, text.ToString(), json);
        return verification.Verified ? write : ExitCodes.GateFailed;
    }

    private static async Task<int> ListAsync(IServiceProvider services, ActDatabase db, string[] args)
    {
        var limit = 50;
        var limitText = FlagValue(args, "--limit");
        if (limitText is not null && (!int.TryParse(limitText, out limit) || limit <= 0))
        {
            Console.Error.WriteLine("error: --limit must be a positive integer");
            return ExitCodes.UsageError;
        }

        var actionPrefix = FlagValue(args, "--action")?.Trim() is { Length: > 0 } prefix ? prefix : null;

        Guid? correlation = null;
        var correlationText = FlagValue(args, "--correlation");
        if (correlationText is not null)
        {
            if (!Guid.TryParse(correlationText, out var parsed))
            {
                Console.Error.WriteLine("error: --correlation must be a correlation identifier");
                return ExitCodes.UsageError;
            }

            correlation = parsed;
        }

        IReadOnlyList<ACT.Contracts.AuditEvent> events;
        try
        {
            events = await db.ListAuditEventsAsync(limit, actionPrefix, correlation);
        }
        catch (ACT.Contracts.ActException ex)
        {
            Console.Error.WriteLine("error: " + ex.SafeMessage);
            return ExitCodes.RuntimeFailure;
        }

        var total = await db.CountAuditEventsAsync();
        var scope = Describe(actionPrefix, correlation);

        var text = new StringBuilder();
        text.AppendLine(string.Format("{0,-8} {1,-20} {2,-16} {3,-28} {4,-16} {5}",
            "SEQ", "TIME (UTC)", "ACTOR", "ACTION", "OBJECT", "RESULT"));
        foreach (var e in events)
        {
            text.AppendLine(string.Format("{0,-8} {1,-20} {2,-16} {3,-28} {4,-16} {5}",
                e.Sequence,
                e.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss"),
                Truncate(e.Actor, 16),
                Truncate(e.Action, 28),
                Truncate(e.ObjectType + ":" + e.ObjectId, 16),
                Truncate(e.Result, 60)));
        }

        text.AppendLine();
        text.AppendLine(events.Count == 0
            ? "no matching audit event(s)" + scope + "."
            : "showing " + events.Count + " of " + total + " stored event(s)" + scope + ", newest first.");

        var json = JsonSerializer.Serialize(new
        {
            totalEvents = total,
            returned = events.Count,
            actionPrefix,
            correlation,
            events = events.Select(e => new
            {
                sequence = e.Sequence,
                timestampUtc = e.TimestampUtc,
                actor = e.Actor,
                action = e.Action,
                objectType = e.ObjectType,
                objectId = e.ObjectId,
                result = e.Result,
                correlation = e.Correlation.ToString(),
                eventHash = e.EventHash
            })
        }, JsonOpts.Indented);
        return await OutputWriter.WriteAsync(services, text.ToString(), json);
    }

    private static async Task<int> ExportAsync(IServiceProvider services, ActDatabase db, string[] args)
    {
        var format = FlagValue(args, "--format")?.Trim().ToLowerInvariant();
        if (format is not ("json" or "csv"))
        {
            Console.Error.WriteLine("error: --format json|csv is required");
            return ExitCodes.UsageError;
        }

        // Page through the ledger so an operator can archive years of history on one command.
        const int pageSize = 1000;
        var all = new List<ACT.Contracts.AuditEvent>();
        while (true)
        {
            var page = await db.ListAuditEventsAsync(pageSize);
            if (page.Count == 0)
            {
                break;
            }

            all.AddRange(page);
            if (page.Count < pageSize)
            {
                break;
            }
        }

        // The ledger exports oldest-first: chronological order is what an external auditor reads.
        all.Reverse();

        string payload;
        if (format == "csv")
        {
            var csv = new StringBuilder();
            csv.AppendLine("sequence,timestamp_utc,actor,action,object_type,object_id,result,correlation,previous_hash,event_hash");
            foreach (var e in all)
            {
                csv.AppendLine(string.Join(',',
                    Csv(e.Sequence.ToString(System.Globalization.CultureInfo.InvariantCulture)),
                    Csv(e.TimestampUtc.ToString("O")),
                    Csv(e.Actor), Csv(e.Action), Csv(e.ObjectType), Csv(e.ObjectId), Csv(e.Result),
                    Csv(e.Correlation.ToString()), Csv(e.PreviousEventHash), Csv(e.EventHash)));
            }

            payload = csv.ToString();
        }
        else
        {
            payload = JsonSerializer.Serialize(new
            {
                exportedUtc = DateTimeOffset.UtcNow,
                eventCount = all.Count,
                events = all.Select(e => new
                {
                    sequence = e.Sequence,
                    timestampUtc = e.TimestampUtc,
                    actor = e.Actor,
                    action = e.Action,
                    objectType = e.ObjectType,
                    objectId = e.ObjectId,
                    result = e.Result,
                    correlation = e.Correlation.ToString(),
                    previousHash = e.PreviousEventHash,
                    eventHash = e.EventHash
                })
            }, JsonOpts.Indented);
        }

        var header = "exported " + all.Count + " audit event(s), oldest first";

        // The archive IS the artifact: every write path (file via --output, stdout redirect,
        // --json capture) must carry the pure JSON/CSV payload with no human preamble anywhere
        // near it - an external auditor's json.load or CSV reader sees exactly what was hashed.
        // The friendly summary goes to the console only.
        var write = await OutputWriter.WriteAsync(services, payload, payload);
        if (!string.IsNullOrWhiteSpace(services.GetRequiredService<GlobalOptions>().OutputPath)
            && !services.GetRequiredService<GlobalOptions>().Quiet)
        {
            Console.WriteLine(header);
        }

        return write;
    }

    private static string Describe(string? actionPrefix, Guid? correlation)
    {
        var parts = new List<string>();
        if (actionPrefix is not null)
        {
            parts.Add("action prefix '" + actionPrefix + "'");
        }

        if (correlation is not null)
        {
            parts.Add("correlation " + correlation);
        }

        return parts.Count > 0 ? " (" + string.Join(", ", parts) + ")" : "";
    }

    /// <summary>RFC 4180 field quoting: fields containing comma, quote, or newline get wrapped.</summary>
    private static string Csv(string field)
    {
        if (!field.Contains(',') && !field.Contains('"') && !field.Contains('\n') && !field.Contains('\r'))
        {
            return field;
        }

        return "\"" + field.Replace("\"", "\"\"") + "\"";
    }

    private static string? FlagValue(string[] args, string flag)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == flag)
            {
                return args[i + 1];
            }
        }

        return null;
    }

    private static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..(max - 3)] + "...";
}
