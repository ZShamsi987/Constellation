$ErrorActionPreference = "Stop"
$service = Get-Service -Name "Constellation" -ErrorAction SilentlyContinue
if ($service) {
  if ($service.Status -ne "Stopped") {
    Stop-Service -Name "Constellation" -Force
  }
  sc.exe delete "Constellation" | Out-Null
}
