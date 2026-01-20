$ErrorActionPreference="Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $root
try {
  powershell -NoProfile -ExecutionPolicy Bypass -File ".\smoke_tests.ps1"
  exit $LASTEXITCODE
} finally {
  Pop-Location
}
