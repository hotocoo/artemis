
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ACT.DependencyAnalysis;

/// <summary>
/// Renders a dependency inventory as a deterministic CycloneDX 1.5 document: identical manifests
/// always produce byte-identical output (no timestamps, hash-derived serial number, sorted purls).
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
        using (var writer = new Utf8JsonWriter(buffer, new JsonWriterOptions { Indented = false, SkipValidation = false }))
        {
            writer.WriteStartObject;
            WriteProperty(writer, "bomFormat", BomFormat);
            WriteProperty(writer, "specVersion", SpecVersion);
            WriteProperty(writer, "serialNumber", "urn:uuid:" + DeriveUuid(components));
            writer.WriteNumber("version", 1);

            writer.WriteStartObject("metadata");
            writer.WriteStartObject("tools");
            writer.WriteStartArray("components");
            writer.WriteStartObject;
            WriteProperty(writer, "type", "application");
            WriteProperty(writer, "name", name);
            WriteProperty(writer, "version", toolVersion);
            writer.WriteEndObject;
            writer.WriteEndArray;
            writer.WriteEndObject;
            writer.WriteWriteEndObject();

            writer.WriteStartArray("components");
            foreach (var component in components)
            {
                writer.WriteStartObject;
                WriteProperty(writer, "type", "library");
                if (component.Purl is not null)
                {
                    WriteProperty(writer, "bom-ref", component.Purl);
                }

                WriteProperty(writer, "name", component.Name);
                if (component.Version is not null)
                {
                    WriteProperty(writer, "version", component.Version);
                    WriteProperty(writer, "purl", component.Purl!);
                }

                writer.WriteEndObject;
            }

            writer.WriteEndArray;
            writer.WriteEndObject;
            writer.Flush;
        }

        return buffer.ToArray;
    }
}

