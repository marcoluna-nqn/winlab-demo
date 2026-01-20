$ErrorActionPreference="Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
Push-Location $root
try {
  if (Test-Path ".\build_release.ps1") {
    powershell -NoProfile -ExecutionPolicy Bypass -File ".\build_release.ps1"
    exit $LASTEXITCODE
  } elseif (Test-Path ".\build.ps1") {
    powershell -NoProfile -ExecutionPolicy Bypass -File ".\build.ps1"
    exit $LASTEXITCODE
  } else {
    Write-Host "[FAIL] No build script found (build_release.ps1/build.ps1)"
    exit 1
  }
} finally {
  Pop-Location
}
