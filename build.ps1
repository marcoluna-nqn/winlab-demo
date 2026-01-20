# WinLab build script (reproducible packaging)
# Output:
#   dist/winlab_site.zip
#   dist/WinLab_Setup_<version>.zip (copiado desde downloads)
#   dist/SHA256SUMS.txt

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Get-RepoRoot {
  $scriptPath = $PSCommandPath
  if(-not $scriptPath){ $scriptPath = $MyInvocation.MyCommand.Path }
  $here = Split-Path -Parent $scriptPath
  return (Resolve-Path $here).Path
}

$root = Get-RepoRoot
Set-Location $root

$dist = Join-Path $root 'dist'
New-Item -ItemType Directory -Force -Path $dist | Out-Null

$downloads = Join-Path $root 'downloads'
$setup = Get-ChildItem -Path $downloads -Filter 'WinLab_Setup_v*.zip' -File |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1
if (-not $setup) { throw 'No se encontró downloads/WinLab_Setup_v*.zip' }

$ver = 'unknown'
if ($setup.Name -match 'WinLab_Setup_v([0-9]+\.[0-9]+\.[0-9]+)\.zip') { $ver = $Matches[1] }

$siteItems = @('index.html','pricing.html','mobile.html','404.html','assets','docs','downloads')
foreach ($i in $siteItems) {
  if (-not (Test-Path (Join-Path $root $i))) { throw "Falta $i" }
}

$siteZip = Join-Path $dist 'winlab_site.zip'
Remove-Item $siteZip -Force -ErrorAction SilentlyContinue
$paths = $siteItems | ForEach-Object { Join-Path $root $_ }
Compress-Archive -Path $paths -DestinationPath $siteZip -Force

$setupOut = Join-Path $dist ("WinLab_Setup_{0}.zip" -f $ver)
Copy-Item -Path $setup.FullName -Destination $setupOut -Force

$sumFile = Join-Path $dist 'SHA256SUMS.txt'
$hashSite = (Get-FileHash -Algorithm SHA256 -Path $siteZip).Hash.ToLower()
$hashSetup = (Get-FileHash -Algorithm SHA256 -Path $setupOut).Hash.ToLower()
@(
  "$hashSite  $(Split-Path -Leaf $siteZip)",
  "$hashSetup  $(Split-Path -Leaf $setupOut)"
) | Set-Content -Path $sumFile -Encoding ASCII

Write-Host "Build OK" -ForegroundColor Green
Write-Host "- $siteZip" -ForegroundColor Green
Write-Host "- $setupOut" -ForegroundColor Green
Write-Host "- $sumFile" -ForegroundColor Green
