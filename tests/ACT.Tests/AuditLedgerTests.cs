using System.Globalization;
using System.Text.Json;
using ACT.Cli;
using ACT.Contracts;
using ACT.Persistence;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace ACT.Tests;

/// <summary>
/// The audit ledger's read side: chain verification names WHERE history stops being trustworthy,
/// filtered listing narrows without reordering, export archives chronologically, and the CLI
/// surfaces scriptable exit codes so pipelines can refuse to ship on a broken chain.
/// </summary>
public sealed class AuditLedgerTests
{
    // ---------- persistence ----------

    private static async Task AppendAsync(ActDatabase db, string action, string actor = "operator-a")
    {
        await db.AppendAuditAsync(new AuditDraft(
            Actor: actor,
            Action: action,
            ObjectType: "test",
            ObjectId: Guid.NewGuid().ToString("N"),
            Result: "ok",
            Correlation: CorrelationId.New()));
    }

    [Fact]
    public async Task Verify_IntactChainReportsFullCount()
    {
        var fixture = await PersistFixture.CreateAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            for (var i = 0; i < 5; i++)
            {
                await AppendAsync(db, i < 2 ? "finding.triaged" : "assessment.started");
            }

            var verification = await db.VerifyChainDetailedAsync();
            Assert.True(verification.Verified);
            Assert.Equal(5, verification.EventCount);
            Assert.Null(verification.FirstBrokenSequence);
            Assert.Null(verification.Reason);
            Assert.Equal(5, await db.CountAuditEventsAsync());
        }
    }

    [Fact]
    public async Task Verify_DetectsEditedPayloadAtExactSequence()
    {
        var fixture = await PersistFixture.CreateAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            for (var i = 0; i < 4; i++)
            {
                await AppendAsync(db, "finding.triaged");
            }

            // Rewrite history in place: the actor of entry 2 changes after the fact.
            await ExecAsync(fixture, "UPDATE audit_events SET actor = 'mallory' WHERE sequence = 2");

            var verification = await db.VerifyChainDetailedAsync();
            Assert.False(verification.Verified);
            Assert.Equal(2, verification.FirstBrokenSequence);
            Assert.Contains("content hash", verification.Reason);
        }
    }

    [Fact]
    public async Task Verify_DetectsDeletedMiddleRowAtItsSuccessor()
    {
        var fixture = await PersistFixture.CreateAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            for (var i = 0; i < 4; i++)
            {
                await AppendAsync(db, "schedule.run");
            }

            await ExecAsync(fixture, "DELETE FROM audit_events WHERE sequence = 2");

            var verification = await db.VerifyChainDetailedAsync();
            Assert.False(verification.Verified);
            // Entry 3 no longer chains to its visible predecessor - the break is named there.
            Assert.Equal(3, verification.FirstBrokenSequence);
            Assert.Contains("predecessor", verification.Reason);
        }
    }

    [Fact]
    public async Task Verify_HeadPointerExposesTailTruncation()
    {
        var fixture = await PersistFixture.CreateAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            for (var i = 0; i < 4; i++)
            {
                await AppendAsync(db, "evidence.retention_swept");
            }

            // Deleting the NEWEST rows leaves every surviving hash link intact - only the
            // recorded head proves rows are missing at all.
            await ExecAsync(fixture, "DELETE FROM audit_events WHERE sequence = 4");

            var verification = await db.VerifyChainDetailedAsync();
            Assert.False(verification.Verified);
            Assert.Equal(4, verification.FirstBrokenSequence);
            Assert.Contains("newest end", verification.Reason);

            // An operator who archived an external copy can compare counts against it; without
            // the recorded head (databases predating it) the prefix verifies honestly as far as
            // hashes reach.
            await ExecAsync(fixture, "DELETE FROM configurations WHERE key = 'audit.head'");
            var withoutHead = await db.VerifyChainDetailedAsync();
            Assert.True(withoutHead.Verified);
            Assert.Equal(3, withoutHead.EventCount);
        }
    }

    [Fact]
    public async Task List_FiltersNarrowWithoutReordering()
    {
        var fixture = await PersistFixture.CreateAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            var shared = Guid.NewGuid();
            await db.AppendAuditAsync(new AuditDraft("op-1", "finding.triaged", "finding", "f1", "Confirmed", new CorrelationId(shared)));
            await db.AppendAuditAsync(new AuditDraft("op-1", "baseline.created", "baseline", "b1", "ok", new CorrelationId(shared)));
            await db.AppendAuditAsync(new AuditDraft("op-2", "finding.regression_run", "regression", "r1", "held", CorrelationId.New()));
            await db.AppendAuditAsync(new AuditDraft("op-2", "finding.triaged", "finding", "f2", "FalsePositive", CorrelationId.New()));

            var byPrefix = await db.ListAuditEventsAsync(50, "finding.");
            // Prefixes match whole families: triaged AND regression_run events, newest first.
            Assert.Equal([4, 3, 1], byPrefix.Select(e => e.Sequence));

            var byCorrelation = await db.ListAuditEventsAsync(50, correlation: shared);
            Assert.Equal([2, 1], byCorrelation.Select(e => e.Sequence));

            var both = await db.ListAuditEventsAsync(50, "finding.", shared);
            Assert.Equal([1], both.Select(e => e.Sequence));

            var limited = await db.ListAuditEventsAsync(2);
            Assert.Equal([4, 3], limited.Select(e => e.Sequence));
        }
    }

    [Fact]
    public async Task List_RefusesAmbiguousFiltersFailClosed()
    {
        var fixture = await PersistFixture.CreateAsync();
        await using (fixture)
        {
            var db = fixture.Database;
            await Assert.ThrowsAsync<ActException>(() => db.ListAuditEventsAsync(0));
            await Assert.ThrowsAsync<ActException>(() => db.ListAuditEventsAsync(-5));
            await Assert.ThrowsAsync<ActException>(() => db.ListAuditEventsAsync(10, ""));
        }
    }

    // ---------- command surface ----------

    private static IServiceProvider BuildServices(PersistFixture fixture, GlobalOptions globals)
    {
        var services = new ServiceCollection();
        services.AddSingleton(fixture.Database);
        // Command handlers print through OutputWriter, which reads the parsed globals.
        services.AddSingleton(globals);
        return services.BuildServiceProvider();
    }

    /// <summary>Captures stdout around one command run so its printed payloads can be asserted.</summary>
    private static async Task<(string Output, int Exit)> RunCapturedAsync(
        IServiceProvider services, params string[] args)
    {
        var original = Console.Out;
        using var writer = new StringWriter();
        try
        {
            Console.SetOut(writer);
            var exit = await AuditCommands.Run(services, args);
            return (writer.ToString(), exit);
        }
        finally
        {
            Console.SetOut(original);
        }
    }

    private static async Task<PersistFixture> SeededDatabaseAsync(int events = 4)
    {
        var fixture = await PersistFixture.CreateAsync();
        for (var i = 0; i < events; i++)
        {
            await AppendAsync(fixture.Database, i % 2 == 0 ? "finding.triaged" : "baseline.created",
                i == 1 ? "doe, john" : "operator-a");
        }

        return fixture;
    }

    [Fact]
    public async Task Cli_VerifyExitsOkOnCleanChainAndNamesBreakWhenTampered()
    {
        var fixture = await SeededDatabaseAsync();
        await using (fixture)
        {
            var provider = BuildServices(fixture, new GlobalOptions { Json = true });

            var (cleanOutput, cleanExit) = await RunCapturedAsync(provider, "verify");
            Assert.Equal(ExitCodes.Ok, cleanExit);
            var clean = JsonDocument.Parse(cleanOutput).RootElement;
            Assert.True(clean.GetProperty("verified").GetBoolean());
            Assert.Equal(4, clean.GetProperty("eventCount").GetInt64());

            await ExecAsync(fixture, "UPDATE audit_events SET result = 'forged' WHERE sequence = 3");
            var (tamperedOutput, tamperedExit) = await RunCapturedAsync(provider, "verify");
            Assert.Equal(ExitCodes.GateFailed, tamperedExit);
            var tampered = JsonDocument.Parse(tamperedOutput).RootElement;
            Assert.False(tampered.GetProperty("verified").GetBoolean());
            Assert.Equal(3, tampered.GetProperty("firstBrokenSequence").GetInt64());
        }
    }

    [Fact]
    public async Task Cli_ListHonorsFiltersTotalsAndRefusesBadArguments()
    {
        var fixture = await SeededDatabaseAsync();
        await using (fixture)
        {
            var provider = BuildServices(fixture, new GlobalOptions { Json = true });

            var (output, exit) = await RunCapturedAsync(provider, "list", "--action", "finding.", "--limit", "10");
            Assert.Equal(ExitCodes.Ok, exit);
            var document = JsonDocument.Parse(output).RootElement;
            Assert.Equal(4, document.GetProperty("totalEvents").GetInt64());
            Assert.Equal(2, document.GetProperty("returned").GetInt64());
            Assert.All(document.GetProperty("events").EnumerateArray(),
                e => Assert.StartsWith("finding.", e.GetProperty("action").GetString()));

            Assert.Equal(ExitCodes.UsageError,
                await AuditCommands.Run(provider, ["list", "--limit", "zero"]));
            Assert.Equal(ExitCodes.UsageError,
                await AuditCommands.Run(provider, ["list", "--correlation", "not-a-guid"]));
        }
    }

    [Fact]
    public async Task Cli_ExportWritesCompleteChronologicalLedgerInBothFormats()
    {
        var directory = Path.Combine(Path.GetTempPath(), "act-audit-export", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var fixture = await SeededDatabaseAsync(events: 6);
            await using (fixture)
            {
                var csvPath = Path.Combine(directory, "ledger.csv");
                var csvProvider = BuildServices(fixture, new GlobalOptions
                {
                    Json = true,
                    Quiet = true,
                    OutputPath = csvPath
                });
                Assert.Equal(ExitCodes.Ok, await AuditCommands.Run(csvProvider, ["export", "--format", "csv"]));

                var csvLines = File.ReadAllLines(csvPath);
                Assert.Equal(7, csvLines.Length); // header + 6 events
                Assert.StartsWith("sequence,", csvLines[0]);
                // Oldest-first chronological order, with the comma-bearing actor correctly quoted.
                Assert.Equal("2", csvLines[2].Split(',')[0]);
                Assert.Contains('"' + "doe, john" + '"', csvLines[2], StringComparison.Ordinal);

                var jsonPath = Path.Combine(directory, "ledger.json");
                var jsonProvider = BuildServices(fixture, new GlobalOptions
                {
                    Json = true,
                    Quiet = true,
                    OutputPath = jsonPath
                });
                Assert.Equal(ExitCodes.Ok, await AuditCommands.Run(jsonProvider, ["export", "--format", "json"]));

                using var exported = JsonDocument.Parse(File.ReadAllText(jsonPath));
                Assert.Equal(6, exported.RootElement.GetProperty("eventCount").GetInt64());
                var sequences = exported.RootElement.GetProperty("events").EnumerateArray()
                    .Select(e => e.GetProperty("sequence").GetInt64())
                    .ToArray();
                Assert.Equal([1, 2, 3, 4, 5, 6], sequences);
            }
        }
        finally
        {
            try { Directory.Delete(directory, recursive: true); } catch (IOException) { }
        }
    }

    [Fact]
    public async Task Cli_RefusesAmbiguousInvocations()
    {
        var fixture = await PersistFixture.CreateAsync();
        await using (fixture)
        {
            var provider = BuildServices(fixture, new GlobalOptions());
            Assert.Equal(ExitCodes.UsageError, await AuditCommands.Run(provider, []));
            Assert.Equal(ExitCodes.UsageError, await AuditCommands.Run(provider, ["rewrite"]));
            Assert.Equal(ExitCodes.UsageError, await AuditCommands.Run(provider, ["export"]));
            Assert.Equal(ExitCodes.UsageError, await AuditCommands.Run(provider, ["export", "--format", "xlsx"]));
        }
    }

    // ---------- raw access ----------

    private static async Task ExecAsync(PersistFixture fixture, string sql)
    {
        await using var connection = new SqliteConnection("Data Source=" + fixture.DatabasePath);
        await connection.OpenAsync();
        var command = connection.CreateCommand();
        command.CommandText = sql;
        await command.ExecuteNonQueryAsync();
    }
}
