# Signs release binaries with an organization-provided Authenticode certificate.
# Requires SHA-256 digest algorithm and RFC 3161 timestamping per modern signing guidance.
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ArtifactDir,
    [string] $TimestampUrl = $env:ARTEMIS_TIMESTAMP_URL
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($env:ARTEMIS_SIGN_CERT)) {
    throw "ARTEMIS_SIGN_CERT is not set. Provide a legitimate organization-controlled certificate; self-signed placeholders are rejected by policy."
}

$pfxPath = Join-Path $env:TEMP ("artemis-sign-" + [Guid]::NewGuid().ToString("N") + ".pfx")
try {
    [IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String($env:ARTEMIS_SIGN_CERT))

    $sdkRoot = Join-Path ([Environment]::GetEnvironmentVariable('ProgramFiles(x86)')) 'Windows Kits\10\bin'
    if (-not (Test-Path $sdkRoot)) { throw "Windows SDK binaries not found at $sdkRoot" }
    $signtool = Get-ChildItem $sdkRoot -Recurse -Filter signtool.exe |
        Where-Object { $_.Directory.Name -match 'x64' } |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $signtool) { throw "signtool.exe not found; install the Windows SDK." }

    $timestamp = if ($TimestampUrl) { $TimestampUrl } else { "http://timestamp.digicert.com" }
    $signArgs = @(
        "sign", "/f", $pfxPath,
        "/p", $env:ARTEMIS_SIGN_CERT_PASSWORD,
        "/fd", "SHA256",
        "/tr", $timestamp,
        "/td", "SHA256"
    )

    Get-ChildItem $ArtifactDir -Filter *.exe | ForEach-Object {
        Write-Host "Signing $($_.Name)"
        & $signtool.FullName ($signArgs + @($_.FullName))
        if ($LASTEXITCODE -ne 0) { throw "signtool failed for $($_.FullName)" }

        Write-Host "Verifying signature of $($_.Name)"
        & $signtool.FullName @("verify", "/pa", "/all", $_.FullName)
        if ($LASTEXITCODE -ne 0) { throw "signature verification failed for $($_.FullName)" }
    }
}
finally {
    if (Test-Path $pfxPath) { Remove-Item -Force $pfxPath }
}
