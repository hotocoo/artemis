using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using ACT.Contracts;
using Microsoft.Data.Sqlite;

namespace ACT.Persistence;

/// <summary>Frozen JSON settings used for every serialized payload stored in the database.</summary>
internal static class ActJson
{
    internal static readonly JsonSerializerOptions Options = Freeze();

    private static JsonSerializerOptions Freeze()
    {
        var options = new JsonSerializerOptions(JsonSerializerDefaults.Web)
        {
            Converters = { new JsonStringEnumConverter() }
        };
        // populateMissingResolver is required: Web defaults bind their resolver lazily and
        // MakeReadOnly() without it fails closed on first serialization.
        options.MakeReadOnly(populateMissingResolver: true);
        return options;
    }

    internal static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Options);

    internal static T Deserialize<T>(string json, string context)
    {
        try
        {
            return JsonSerializer.Deserialize<T>(json, Options)
                ?? throw Fail(context, "payload decoded to null.");
        }
        catch (JsonException ex)
        {
            throw Fail(context, ex.Message);
        }
    }

    private static ActException Fail(string context, string detail) =>
        ActException.FailClosed(ErrorCategory.Persistence,
            "Stored data could not be read.",
            "Column '" + context + "': " + detail);
}

/// <summary>UTC timestamps persisted in round-trippable ISO-8601 "O" form (always UTC, fixed width).</summary>
internal static class ActTime
{
    internal static string Write(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture);

    internal static DateTimeOffset Read(string value, string context) =>
        DateTimeOffset.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed)
            ? parsed
            : throw ActException.FailClosed(ErrorCategory.Persistence,
                "Stored data could not be read.",
                "Column '" + context + "': value is not a valid round-trip timestamp.");
}

/// <summary>Strict parsers for identifiers and enums read back from stored columns.</summary>
internal static class ActValues
{
    internal static Guid Guid(string raw, string context) =>
        System.Guid.TryParse(raw, out var parsed)
            ? parsed
            : throw ActException.FailClosed(ErrorCategory.Persistence,
                "Stored data could not be read.",
                "Column '" + context + "': value is not a valid identifier.");

    internal static TEnum Enum<TEnum>(string raw, string context) where TEnum : struct, Enum =>
        System.Enum.TryParse<TEnum>(raw, ignoreCase: true, out var parsed)
            ? parsed
            : throw ActException.FailClosed(ErrorCategory.Persistence,
                "Stored data could not be read.",
                "Column '" + context + "': value is not a valid " + typeof(TEnum).Name + ".");

    internal static TEnum Enum<TEnum>(long raw, string context) where TEnum : struct, Enum
    {
        // Convert to the enum's underlying type first: IsDefined rejects mismatched boxed widths.
        var converted = System.Enum.ToObject(typeof(TEnum), raw);
        return System.Enum.IsDefined(typeof(TEnum), converted)
            ? (TEnum)converted
            : throw ActException.FailClosed(ErrorCategory.Persistence,
                "Stored data could not be read.",
                "Column '" + context + "': value " + raw + " is not a defined " + typeof(TEnum).Name + ".");
    }
}

/// <summary>Typed accessors for SQLite rows read by column name.</summary>
internal static class Rows
{
    internal static string Str(this SqliteDataReader row, string column) =>
        row.GetString(row.GetOrdinal(column));

    internal static string? StrOrNull(this SqliteDataReader row, string column)
    {
        var ordinal = row.GetOrdinal(column);
        return row.IsDBNull(ordinal) ? null : row.GetString(ordinal);
    }

    internal static long IntOf(this SqliteDataReader row, string column) =>
        Convert.ToInt64(row.GetValue(row.GetOrdinal(column)), CultureInfo.InvariantCulture);

    internal static double RealOf(this SqliteDataReader row, string column) =>
        Convert.ToDouble(row.GetValue(row.GetOrdinal(column)), CultureInfo.InvariantCulture);

    internal static double? RealOrNull(this SqliteDataReader row, string column)
    {
        var ordinal = row.GetOrdinal(column);
        return row.IsDBNull(ordinal)
            ? null
            : Convert.ToDouble(row.GetValue(ordinal), CultureInfo.InvariantCulture);
    }

    internal static bool BoolOf(this SqliteDataReader row, string column) => row.IntOf(column) != 0;

    internal static DateTimeOffset TimeOf(this SqliteDataReader row, string column) =>
        ActTime.Read(row.Str(column), column);

    internal static DateTimeOffset? TimeOrNull(this SqliteDataReader row, string column)
    {
        var raw = row.StrOrNull(column);
        return raw is null ? null : ActTime.Read(raw, column);
    }

    internal static Guid GuidOf(this SqliteDataReader row, string column) =>
        ActValues.Guid(row.Str(column), column);

    internal static Guid? GuidOrNull(this SqliteDataReader row, string column)
    {
        var raw = row.StrOrNull(column);
        return raw is null ? null : ActValues.Guid(raw, column);
    }
}

/// <summary>The v1 database schema. Frozen: edits break deployed databases via checksum mismatch.</summary>
internal static class SchemaV1
{
    internal const int Version = 1;
    internal const string Name = "core-schema";

    internal static readonly string[] Statements =
    [
        """
        CREATE TABLE IF NOT EXISTS assessments (
            assessment_id     TEXT NOT NULL PRIMARY KEY,
            scope_id          TEXT NOT NULL,
            name              TEXT NOT NULL,
            state             TEXT NOT NULL,
            created_utc       TEXT NOT NULL,
            started_utc       TEXT,
            completed_utc     TEXT,
            operator_identity TEXT NOT NULL,
            organization      TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS scopes (
            scope_id        TEXT NOT NULL PRIMARY KEY,
            assessment_id   TEXT NOT NULL REFERENCES assessments(assessment_id),
            definition_json TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS assets (
            asset_id          TEXT NOT NULL PRIMARY KEY,
            assessment_id     TEXT NOT NULL REFERENCES assessments(assessment_id),
            kind              TEXT NOT NULL,
            display_name      TEXT NOT NULL,
            canonical_target  TEXT NOT NULL,
            observed_ips_json TEXT NOT NULL,
            discovered_utc    TEXT NOT NULL,
            within_scope      INTEGER NOT NULL,
            UNIQUE(assessment_id, canonical_target)
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_assets_assessment ON assets(assessment_id)",
        """
        CREATE TABLE IF NOT EXISTS services (
            service_id     TEXT NOT NULL PRIMARY KEY,
            asset_id       TEXT NOT NULL REFERENCES assets(asset_id),
            port           INTEGER NOT NULL,
            protocol       TEXT NOT NULL,
            banner         TEXT,
            tls_negotiated INTEGER NOT NULL,
            observed_utc   TEXT NOT NULL,
            source_check   TEXT NOT NULL,
            UNIQUE(asset_id, port)
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_services_asset ON services(asset_id)",
        """
        CREATE TABLE IF NOT EXISTS check_runs (
            check_run_id     TEXT NOT NULL PRIMARY KEY,
            assessment_id    TEXT NOT NULL REFERENCES assessments(assessment_id),
            check_id         TEXT NOT NULL,
            status           TEXT NOT NULL,
            started_utc      TEXT NOT NULL,
            completed_utc    TEXT NOT NULL,
            failure_summary  TEXT,
            request_count    INTEGER NOT NULL,
            targets_examined INTEGER NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS findings (
            finding_id                  TEXT NOT NULL PRIMARY KEY,
            assessment_id               TEXT NOT NULL REFERENCES assessments(assessment_id),
            check_id                    TEXT NOT NULL,
            target_display              TEXT NOT NULL,
            asset_reference             TEXT,
            category                    TEXT NOT NULL,
            title                       TEXT NOT NULL,
            description                 TEXT NOT NULL,
            severity                    INTEGER NOT NULL,
            confidence                  INTEGER NOT NULL,
            confidence_score            REAL NOT NULL,
            exploitability              INTEGER NOT NULL,
            business_impact             INTEGER NOT NULL,
            why_it_matters              TEXT NOT NULL,
            technical_explanation       TEXT NOT NULL,
            remediation_summary         TEXT NOT NULL,
            remediation_steps_json      TEXT NOT NULL,
            remediation_references_json TEXT NOT NULL,
            first_seen_utc              TEXT NOT NULL,
            last_seen_utc               TEXT NOT NULL,
            status                      TEXT NOT NULL,
            fingerprint                 TEXT NOT NULL,
            regression_test_id          TEXT,
            cvss_vector                 TEXT,
            cvss_base_score             REAL,
            priority_score              REAL NOT NULL,
            UNIQUE(assessment_id, fingerprint)
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_findings_status ON findings(status)",
        "CREATE INDEX IF NOT EXISTS ix_findings_fingerprint ON findings(fingerprint)",
        """
        CREATE TABLE IF NOT EXISTS evidence (
            evidence_id     TEXT NOT NULL PRIMARY KEY,
            finding_id      TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
            kind            TEXT NOT NULL,
            key             TEXT NOT NULL,
            redacted_value  TEXT NOT NULL,
            captured_utc    TEXT NOT NULL,
            collected_by    TEXT NOT NULL,
            correlation     TEXT NOT NULL,
            attributes_json TEXT NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_evidence_finding ON evidence(finding_id)",
        """
        CREATE TABLE IF NOT EXISTS regression_tests (
            regression_test_id TEXT NOT NULL PRIMARY KEY,
            finding_id         TEXT NOT NULL REFERENCES findings(finding_id),
            assessment_id      TEXT NOT NULL,
            name               TEXT NOT NULL,
            description        TEXT NOT NULL,
            suggested_severity INTEGER NOT NULL,
            cadence_seconds    REAL NOT NULL,
            enabled            INTEGER NOT NULL,
            created_utc        TEXT NOT NULL,
            last_run_utc       TEXT,
            next_run_utc       TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS test_runs (
            test_run_id        INTEGER PRIMARY KEY AUTOINCREMENT,
            regression_test_id TEXT NOT NULL REFERENCES regression_tests(regression_test_id),
            ran_utc            TEXT NOT NULL,
            result             TEXT NOT NULL,
            detail             TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS audit_events (
            sequence      INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp_utc TEXT NOT NULL,
            actor         TEXT NOT NULL,
            action        TEXT NOT NULL,
            object_type   TEXT NOT NULL,
            object_id     TEXT NOT NULL,
            result        TEXT NOT NULL,
            correlation   TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash    TEXT NOT NULL
        )
        """,
        "CREATE INDEX IF NOT EXISTS ix_audit_events_timestamp ON audit_events(timestamp_utc)",
        """
        CREATE TABLE IF NOT EXISTS configurations (
            key         TEXT NOT NULL PRIMARY KEY,
            value_json  TEXT NOT NULL,
            updated_utc TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS schedules (
            schedule_id     TEXT NOT NULL PRIMARY KEY,
            name            TEXT NOT NULL,
            scope_id        TEXT NOT NULL,
            cron_expression TEXT NOT NULL,
            trigger         TEXT NOT NULL,
            enabled         INTEGER NOT NULL,
            created_utc     TEXT NOT NULL,
            last_run_utc    TEXT
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS feeds (
            name             TEXT NOT NULL PRIMARY KEY,
            kind             TEXT NOT NULL,
            endpoint_or_path TEXT NOT NULL,
            enabled          INTEGER NOT NULL,
            updated_utc      TEXT NOT NULL
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS feed_versions (
            feed_name     TEXT NOT NULL REFERENCES feeds(name),
            retrieved_utc TEXT NOT NULL,
            metadata_hash TEXT NOT NULL,
            is_current    INTEGER NOT NULL,
            note          TEXT NOT NULL,
            PRIMARY KEY(feed_name, retrieved_utc)
        )
        """,
        """
        CREATE TABLE IF NOT EXISTS scan_metrics (
            assessment_id          TEXT NOT NULL PRIMARY KEY REFERENCES assessments(assessment_id),
            requests_sent          INTEGER NOT NULL,
            checks_executed        INTEGER NOT NULL,
            checks_failed          INTEGER NOT NULL,
            findings_emitted       INTEGER NOT NULL,
            total_duration_seconds REAL NOT NULL,
            bytes_received         INTEGER NOT NULL,
            updated_utc            TEXT NOT NULL
        )
        """,
    ];

    /// <summary>SHA-256 hex checksum of the complete v1 script; detects tampering with shipped DDL.</summary>
    internal static string Checksum() => MigrationScript.Checksum(string.Join(";\n", Statements));
}

/// <summary>Shared checksum rule for shipped migration scripts: SHA-256 hex over the exact DDL text.</summary>
internal static class MigrationScript
{
    internal static string Checksum(string script) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(script))).ToLowerInvariant();
}

/// <summary>
/// The complete ordered migration history a database must follow. New migrations append here and
/// nowhere else; existing entries are frozen forever.
/// </summary>
internal static class Migrations
{
    internal static readonly (int Version, string Name, string Checksum, string[] Statements)[] Ordered =
    [
        (SchemaV1.Version, SchemaV1.Name, SchemaV1.Checksum(), SchemaV1.Statements),
        (SchemaV2.Version, SchemaV2.Name, SchemaV2.Checksum(), SchemaV2.Statements),
    ];
}

/// <summary>
/// The v2 schema: operator triage columns on findings. Frozen once shipped - edits break deployed
/// databases via checksum mismatch, exactly like v1. Plain nullable columns keep every v1 row
/// valid without a rewrite; NULL simply means "never triaged".
/// </summary>
internal static class SchemaV2
{
    internal const int Version = 2;
    internal const string Name = "finding-triage";

    internal static readonly string[] Statements =
    [
        "ALTER TABLE findings ADD COLUMN triage_note TEXT",
        "ALTER TABLE findings ADD COLUMN triaged_by TEXT",
        "ALTER TABLE findings ADD COLUMN triaged_utc TEXT",
    ];

    /// <summary>SHA-256 hex checksum of the complete v2 script.</summary>
    internal static string Checksum() => MigrationScript.Checksum(string.Join(";\n", Statements));
}
