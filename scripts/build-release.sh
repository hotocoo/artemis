#!/usr/bin/env bash
#
# Cross-platform release builder for Artemis. Publishes self-contained single-file binaries
# for the requested runtime identifiers and produces, per RID:
#   release-manifest.json  - product/version/file inventory with SHA-256 hashes
#   SHA256SUMS             - 'sha256sum -c' compatible checksums over those files
#   sbom.json              - CycloneDX 1.5 component list from NuGet project.assets.json
#
# Unix twin of scripts/New-ReleaseManifest.ps1 (same manifest shape); Authenticode signing
# stays Windows-only by nature and remains in scripts/Sign-Release.ps1.
#
# Usage: scripts/build-release.sh [-p PUBDIR] [-o OUTDIR] rid [rid ...]
#   e.g. scripts/build-release.sh osx-arm64 linux-x64 win-x64

set -euo pipefail

PUBDIR="artifacts/publish"
OUTDIR="artifacts/release"
RIDS=()
while getopts "p:o:" opt; do
  case "$opt" in
    p) PUBDIR="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    *) echo "usage: $0 [-p pubdir] [-o outdir] rid [rid ...]" >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))
if [ "$#" -eq 0 ]; then
  echo "usage: $0 [-p pubdir] [-o outdir] rid [rid ...]" >&2
  exit 2
fi
RIDS=("$@")

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

VERSION=$(sed -n 's:.*<Version>\(.*\)</Version>.*:\1:p' Directory.Build.props | head -1)
if [ -z "$VERSION" ]; then
  echo "error: could not read <Version> from Directory.Build.props" >&2
  exit 1
fi
echo "Artemis release build v$VERSION for: ${RIDS[*]}"

publish_one() {
  local project="$1" name="$2" rid="$3"
  local out="$PUBDIR/$rid/$name"
  dotnet publish "$project" -c Release -r "$rid" \
    --self-contained true -p:PublishSingleFile=true \
    -p:IncludeNativeLibrariesForSelfExtract=true -o "$out" >/dev/null
  echo "published $name ($rid) -> $out"
}

stage_payload() {
  # stage_payload <rid>
  # Copy the published payload into the release directory BEFORE metadata is written, so
  # each artifacts/release/<rid> is self-contained: the binaries sit next to the manifest,
  # SHA256SUMS, and SBOM that describe them, 'sha256sum -c' verifies in place, and the
  # uploaded/published release artifact carries the executables themselves.
  local rid="$1"
  local out="$OUTDIR/$rid"
  rm -rf "$out"
  mkdir -p "$out"
  cp -R "$PUBDIR/$rid/." "$out/"
}

emit_metadata() {
  # emit_metadata <rid>
  local rid="$1"
  local dir="$PUBDIR/$rid"
  local out="$OUTDIR/$rid"
  mkdir -p "$out"

  python3 - "$dir" "$out" "$rid" "$VERSION" <<'PYEOF'
import datetime, hashlib, json, os, sys
pub_dir, out_dir, rid, version = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

files = []
for root, _, names in os.walk(pub_dir):
    for name in sorted(names):
        path = os.path.join(root, name)
        rel = os.path.relpath(path, pub_dir).replace(os.sep, "/")
        digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
        files.append({"path": rel, "sizeBytes": os.path.getsize(path), "sha256": digest})
files.sort(key=lambda f: f["path"])

manifest = {
    "product": "Artemis",
    "version": version,
    "builtUtc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "targetRuntime": rid,
    "selfContained": True,
    "singleFile": True,
    "files": files,
}
with open(os.path.join(out_dir, "release-manifest.json"), "w") as handle:
    json.dump(manifest, handle, indent=2)
    handle.write("\n")

with open(os.path.join(out_dir, "SHA256SUMS"), "w", newline="\n") as sums:
    for entry in files:
        sums.write(f"{entry['sha256']}  {entry['path']}\n")

# CycloneDX-style component SBOM assembled offline from the restored dependency graph.
components = {}
for project in ("ACT.Cli", "ACT.Desktop"):
    assets = os.path.join("src", project, "obj", "project.assets.json")
    if not os.path.exists(assets):
        continue
    graph = json.load(open(assets))
    for target in graph.get("targets", {}).values():
        # Target keys are 'Name/Version'; only entries typed 'package' are NuGet components -
        # project references carry no versioned package identity and must not appear.
        for key, meta in target.items():
            if meta.get("type") != "package":
                continue
            name, _, dep_version = key.rpartition("/")
            if name and dep_version:
                components[(name.lower(), dep_version)] = (name, dep_version)
sbom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "version": 1,
    "metadata": {
        "timestamp": manifest["builtUtc"],
        "properties": [{
            "name": "artemis:sbom-scope",
            "value": "NuGet runtime components of the self-contained publish for " + rid,
        }],
        "component": {"type": "application", "name": "Artemis", "version": version},
    },
    "components": [
        {"type": "library", "name": name, "version": ver,
         "purl": f"pkg:nuget/{name.lower()}@{ver}"}
        for (_, _), (name, ver) in sorted(components.items())
    ],
}
with open(os.path.join(out_dir, "sbom.json"), "w") as handle:
    json.dump(sbom, handle, indent=2)
    handle.write("\n")
print(f"metadata written: {out_dir} (manifest, SHA256SUMS, sbom.json)")
PYEOF
}

for rid in "${RIDS[@]}"; do
  publish_one src/ACT.Cli/ACT.Cli.csproj artemis "$rid"
  publish_one src/ACT.Desktop/ACT.Desktop.csproj artemis-console "$rid"
  stage_payload "$rid"
  emit_metadata "$rid"
done

echo "Release artifacts ready under $OUTDIR/"
