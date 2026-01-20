# WinLab release packaging

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$scriptPath = $PSCommandPath
if(-not $scriptPath){ $scriptPath = $MyInvocation.MyCommand.Path }
$root = (Resolve-Path (Split-Path -Parent $scriptPath)).Path

Write-Host "[INFO] Running smoke tests..." -ForegroundColor Cyan
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'smoke_tests.ps1')

$versionPath = Join-Path $root 'tools/cli/version.txt'
$version = (Get-Content -Raw -Path $versionPath).Trim()
if([string]::IsNullOrWhiteSpace($version)){ throw "Version not found in tools/cli/version.txt" }

$dist = Join-Path $root 'dist'
if(-not (Test-Path $dist)){ New-Item -ItemType Directory -Path $dist | Out-Null }

$siteZip = Join-Path $dist 'winlab_site.zip'
$productZip = Join-Path $dist ("WinLab_ProductPack_{0}.zip" -f $version)
$setupZip = Join-Path $root ("downloads/WinLab_Setup_v{0}.zip" -f $version)
if(-not (Test-Path $setupZip)){ throw "Missing setup zip: $setupZip" }

Remove-Item -Force -Path $siteZip,$productZip -ErrorAction SilentlyContinue

Push-Location $root
try {
  Write-Host "[INFO] Building site zip..." -ForegroundColor Cyan
  $siteItems = @('index.html','pricing.html','404.html','assets','docs','downloads')
  Compress-Archive -Path $siteItems -DestinationPath $siteZip -Force

  Write-Host "[INFO] Building product pack zip..." -ForegroundColor Cyan
  $items = Get-ChildItem -Force | Where-Object { $_.Name -notin @('.git','dist') } | Select-Object -ExpandProperty Name
  Compress-Archive -Path $items -DestinationPath $productZip -Force
} finally {
  Pop-Location
}

Write-Host "[INFO] Writing SHA256SUMS..." -ForegroundColor Cyan
$hashEntries = @(
  @{ Path = $siteZip; Name = 'dist/winlab_site.zip' },
  @{ Path = $productZip; Name = ("dist/WinLab_ProductPack_{0}.zip" -f $version) },
  @{ Path = $setupZip; Name = ("downloads/WinLab_Setup_v{0}.zip" -f $version) }
)
$lines = foreach($entry in $hashEntries){
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $entry.Path).Hash.ToLowerInvariant()
  "{0}  {1}" -f $hash, $entry.Name
}
Set-Content -Path (Join-Path $dist 'SHA256SUMS.txt') -Value $lines -Encoding ASCII

Write-Host "[OK] Release artifacts ready in dist/" -ForegroundColor Green
