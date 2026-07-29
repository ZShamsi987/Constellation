param(
  [Parameter(Mandatory=$true)][string]$InstallDirectory
)

$ErrorActionPreference = "Stop"
$serviceHost = Join-Path $InstallDirectory "constellation-service.exe"
$daemon = Join-Path $InstallDirectory "constellationd.exe"
if (-not (Test-Path $serviceHost) -or -not (Test-Path $daemon)) {
  throw "Constellation service binaries are missing from $InstallDirectory"
}
if (Get-Service -Name "Constellation" -ErrorAction SilentlyContinue) {
  throw "Constellation service is already installed"
}
New-Service -Name "Constellation" -BinaryPathName ('"' + $serviceHost + '"') -DisplayName "Constellation" -Description "Private AI compute daemon" -StartupType Automatic
Start-Service -Name "Constellation"
