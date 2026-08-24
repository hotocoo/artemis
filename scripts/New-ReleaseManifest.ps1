# Builds SHA-256 checksums and a release manifest for published Artemis binaries.
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ArtifactsRoot,
    [Parameter(Mandatory)] [string] $OutDir
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$files = Get-ChildItem -Path $ArtifactsRoot -Recurse -File | Sort-Object FullName
$entries = foreach ($f in $files) {
    $hash = (Get-FileHash -Algorithm SHA256 $f.FullName).Hash.ToLowerInvariant()
    [PSCustomObject]@{
        path = [IO.Path]::GetRelativePath($ArtifactsRoot, $f.FullName)
        sizeBytes = $f.Length
        sha256 = $hash
    }
}

$manifest = [PSCustomObject]@{
    product = "Artemis"
    version = "1.0.0"
    builtUtc = (Get-Date).ToUniversalTime().ToString("o")
    targetRuntime = "win-x64"
    selfContained = $true
    singleFile = $true
    files = @($entries)
}

$manifestPath = Join-Path $OutDir "release-manifest.json"
$manifest | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 $manifestPath

$checksumLines = foreach ($e in $entries) { "$($e.sha256)  $($e.path)" }
Set-Content -Encoding ASCII -Path (Join-Path $OutDir "SHA256SUMS") -Value ($checksumLines -join [Environment]::NewLine)

Write-Host "Manifest written: $manifestPath"
Write-Host "Checksums written: $(Join-Path $OutDir 'SHA256SUMS')"
