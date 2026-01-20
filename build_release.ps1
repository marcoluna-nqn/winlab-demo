# WinLab release packaging

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$scriptPath = $PSCommandPath
if(-not $scriptPath){ $scriptPath = $MyInvocation.MyCommand.Path }
$root = (Resolve-Path (Split-Path -Parent $scriptPath)).Path

Write-Host "[INFO] Ejecutando smoke tests." -ForegroundColor Cyan
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'smoke_tests.ps1')

$versionPath = Join-Path $root 'tools/cli/version.txt'
$version = (Get-Content -Raw -Path $versionPath).Trim()
if([string]::IsNullOrWhiteSpace($version)){ throw "Version not found in tools/cli/version.txt" }

$dist = Join-Path $root 'dist'
if(-not (Test-Path $dist)){ New-Item -ItemType Directory -Path $dist | Out-Null }

$siteZip = Join-Path $dist 'winlab_site.zip'
$productZip = Join-Path $dist ("WinLab_ProductPack_{0}.zip" -f $version)
$setupSource = Join-Path $root ("downloads/WinLab_Setup_v{0}.zip" -f $version)
$setupZip = Join-Path $dist ("WinLab_Setup_{0}.zip" -f $version)
if(-not (Test-Path $setupSource)){ throw "Missing setup zip: $setupSource" }

Remove-Item -Force -Path $siteZip,$productZip,$setupZip -ErrorAction SilentlyContinue

Push-Location $root
try {
  Write-Host "[INFO] Generando zip del sitio." -ForegroundColor Cyan
  $siteItems = @('index.html','pricing.html','404.html','assets','docs','downloads')
  Compress-Archive -Path $siteItems -DestinationPath $siteZip -Force

  Write-Host "[INFO] Generando zip del product pack." -ForegroundColor Cyan
  $items = Get-ChildItem -Force | Where-Object { $_.Name -notin @('.git','dist') } | Select-Object -ExpandProperty Name
  Compress-Archive -Path $items -DestinationPath $productZip -Force

  Write-Host "[INFO] Copiando setup zip." -ForegroundColor Cyan
  Copy-Item -Path $setupSource -Destination $setupZip -Force
} finally {
  Pop-Location
}

Write-Host "[INFO] Generando SHA256SUMS." -ForegroundColor Cyan
$hashEntries = @(
  @{ Path = $siteZip; Name = 'dist/winlab_site.zip' },
  @{ Path = $productZip; Name = ("dist/WinLab_ProductPack_{0}.zip" -f $version) },
  @{ Path = $setupZip; Name = ("dist/WinLab_Setup_{0}.zip" -f $version) }
)
$lines = foreach($entry in $hashEntries){
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $entry.Path).Hash.ToLowerInvariant()
  "{0}  {1}" -f $hash, $entry.Name
}
Set-Content -Path (Join-Path $dist 'SHA256SUMS.txt') -Value $lines -Encoding ASCII

Write-Host "[OK] Release artifacts ready in dist/" -ForegroundColor Green
