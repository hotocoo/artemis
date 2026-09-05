
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ACT.DependencyAnalysis;

/// <summary>
/// Renders a dependency inventory as a deterministic CycloneDX 1.5 document: identical manifests
/// always produce byte-identical output because there are no timestamps, the serial number is
/// hash-derived from component purls, and components are emitted in sorted purl order.
/// </summary>
public static class CycloneDxSbomGenerator
{
    /// <summary>Fixed CycloneDX bomFormat value.</summary>
    public const string BomFormat = "CycloneDX";

    /// <summary>The emitted CycloneDX specification version.</summary>
    public const string SpecVersion = "1.5";

    /// <summary>Default tool name recorded in metadata.</summary>
    public const string DefaultToolName = "Artemis";

    /// <summary>Renders the manifest as deterministic UTF-8 JSON bytes.</summary>
    public static byte[] ToJson(DependencyManifest manifest, string toolVersion, string? toolName = null)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentException.ThrowIfNullOrWhiteSpace(toolVersion);
        var name = string.IsNullOrWhiteSpace(toolName) ? DefaultToolName : toolName;

        var components = BuildComponents(manifest);
        using var buffer = new MemoryStream();
        using var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = false });
        writer.WriteStartObject();
        writer.WriteString("bomFormat", BomFormat);
        writer.WriteString("specVersion", SpecVersion);
        writer.WriteString("serialNumber", "urn:uuid:" + DeriveUuid(components));
        writer.WriteNumber("version", 1);

        writer.WriteStartObject("metadata");
        writer.WriteStartObject("tools");
        writer.WriteStartArray("components");
        writer.WriteStartObject();
        writer.WriteString("type", "application");
        writer.WriteString("name", name);
        writer.WriteString("version", toolVersion);
        writer.WriteEndObject();
        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.WriteEndObject();

        writer.WriteStartArray("components");
        foreach (var component in components)
        {
            writer.WriteStartObject();
            writer.WriteString("type", "library");
            if (component.Purl is not null)
            {
                writer.WriteString("bom-ref", component.Purl);
            }

            writer.WriteString("name", component.Name);
            if (component.Version is not null)
            {
                writer.WriteString("version", component.Version);
                writer.WriteString("purl", component.Purl!);
            }

            writer.WriteEndObject();
        }

        writer.WriteEndArray();
        writer.WriteEndObject();
        writer.Flush();

        return buffer.ToArray();
    }

    private static IReadOnlyList<SbomComponent> BuildComponents(DependencyManifest manifest)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var components = new List<SbomComponent>();
        foreach (var entry in manifest.Entries)
        {
            var key = entry.Version is null ? "name-only:" + entry.Name : entry.Name + "@" + entry.Version;
            if (!seen.Add(key))
            {
                continue;
            }

            components.Add(new SbomComponent(entry.Name, entry.Version, BuildPurl(manifest.Ecosystem, entry)));
        }

        return components
            .OrderBy(static c => c.Purl is null ? 1 : 0)
            .ThenBy(static c => c.Purl ?? "\uFFFF" + c.Name.ToLowerInvariant(), StringComparer.Ordinal)
            .ToList();
    }

    private static string? BuildPurl(DependencyEcosystem ecosystem, DependencyEntry entry) =>
        entry.Version is null
            ? null
            : "pkg:" + EcosystemSegment(ecosystem) + "/" + NamePathSegment(ecosystem, entry.Name) + "@" + Uri.EscapeDataString(entry.Version);

    /// <summary>
    /// Per the package-url specification, the path component is ecosystem-specific:
    /// Maven and Gradle split groupId:artifactId on ":" and rejoin with "/", Go uses the
    /// import path verbatim (its "/" separators stay as path delimiters, not percent-encoded),
    /// and the rest pass the bare name through URI escaping.
    /// </summary>
    private static string NamePathSegment(DependencyEcosystem ecosystem, string name)
    {
        if (ecosystem is DependencyEcosystem.Maven or DependencyEcosystem.Gradle)
        {
            var separator = name.IndexOf(':');
            if (separator > 0 && separator < name.Length - 1)
            {
                return Uri.EscapeDataString(name[..separator]) + "/" + Uri.EscapeDataString(name[(separator + 1)..]);
            }
        }
        if (ecosystem == DependencyEcosystem.Go)
        {
            // Uri.EscapeDataString would turn "/" into "%2F", but the Go purl type treats "/"
            // as a literal path separator throughout the import path.
            return Uri.EscapeDataString(name).Replace("%2F", "/").Replace("%2f", "/");
        }
        return Uri.EscapeDataString(name);
    }

    private static string EcosystemSegment(DependencyEcosystem ecosystem) => ecosystem switch
    {
        DependencyEcosystem.NuGet => "nuget",
        DependencyEcosystem.Npm => "npm",
        DependencyEcosystem.PyPi => "pypi",
        DependencyEcosystem.Cargo => "cargo",
        // CMake declares its own first-class purl type; Maven covers Gradle because Gradle
        // artifacts use Maven groupId:artifactId coordinates and the Maven purl spec accepts
        // them; Go uses the golang purl type per the package-url specification.
        DependencyEcosystem.CMake => "cmake",
        DependencyEcosystem.Go => "golang",
        DependencyEcosystem.Maven => "maven",
        DependencyEcosystem.Gradle => "maven",
        _ => "generic"
    };

    private static string DeriveUuid(IReadOnlyList<SbomComponent> components)
    {
        // Deterministic UUID-shaped identifier: SHA-256 over canonical purls, RFC 4122 version 5
        // nibble and variant bits applied so the value still parses as a UUID.
        var canonical = string.Join("\n", components.Select(static c => c.Purl ?? "unversioned:" + c.Name));
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));

        Span<byte> uuid = stackalloc byte[16];
        digest.AsSpan(0, 16).CopyTo(uuid);
        uuid[6] = (byte)((uuid[6] & 0x0F) | 0x50);
        uuid[8] = (byte)((uuid[8] & 0x3F) | 0x80);

        var hex = Convert.ToHexString(uuid).ToLowerInvariant();
        return hex[..8] + "-" + hex[8..12] + "-" + hex[12..16] + "-" + hex[16..20] + "-" + hex[20..];
    }

    private sealed record SbomComponent(string Name, string? Version, string? Purl);
}

