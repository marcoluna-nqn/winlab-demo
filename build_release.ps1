# WinLab release packaging

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$scriptPath = $PSCommandPath
if(-not $scriptPath){ $scriptPath = $MyInvocation.MyCommand.Path }
$root = (Resolve-Path (Split-Path -Parent $scriptPath)).Path

$versionPath = Join-Path $root 'tools/cli/version.txt'
$version = (Get-Content -Raw -Path $versionPath).Trim()
if([string]::IsNullOrWhiteSpace($version)){ throw "Version not found in tools/cli/version.txt" }

$dist = Join-Path $root 'dist'
if(-not (Test-Path $dist)){ New-Item -ItemType Directory -Path $dist | Out-Null }

# ----- Installer (Inno Setup preferido / IExpress fallback) -----
Write-Host "[INFO] Preparando instalador." -ForegroundColor Cyan
$installerStage = Join-Path $dist 'installer_stage'
$payload = Join-Path $installerStage 'payload'
Remove-Item -Recurse -Force -Path $installerStage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $payload | Out-Null

$downloads = Join-Path $payload 'downloads'
$docsDir = Join-Path $payload 'docs'
$toolsDir = Join-Path $payload 'tools'
New-Item -ItemType Directory -Force -Path $downloads,$docsDir,$toolsDir | Out-Null

Copy-Item -Recurse -Force -Path (Join-Path $root 'tools/cli') -Destination (Join-Path $toolsDir 'cli')
$cliVersion = Join-Path $payload 'tools/cli/version.txt'
if(Test-Path $cliVersion){ Remove-Item -Force $cliVersion }
Copy-Item -Recurse -Force -Path (Join-Path $root 'downloads/launcher') -Destination (Join-Path $downloads 'launcher')
Copy-Item -Recurse -Force -Path (Join-Path $root 'downloads/presets') -Destination (Join-Path $downloads 'presets')
Copy-Item -Recurse -Force -Path (Join-Path $root 'downloads/safe_mode') -Destination (Join-Path $downloads 'safe_mode')
Copy-Item -Recurse -Force -Path (Join-Path $root 'downloads/samples') -Destination (Join-Path $downloads 'samples')
Copy-Item -Force -Path (Join-Path $root 'docs/guia.html') -Destination (Join-Path $docsDir 'guia.html')
Copy-Item -Force -Path (Join-Path $root 'docs/guia_cliente.html') -Destination (Join-Path $docsDir 'guia_cliente.html')
Copy-Item -Force -Path (Join-Path $root 'scripts/installer/Uninstall-WinLab.ps1') -Destination (Join-Path $payload 'Uninstall-WinLab.ps1')
Set-Content -Path (Join-Path $payload 'VERSION.txt') -Value $version -Encoding ASCII
Copy-Item -Force -Path (Join-Path $root 'scripts/installer/WinLab_Install.ps1') -Destination (Join-Path $installerStage 'WinLab_Install.ps1')

$manifest = Join-Path $dist ("WinLab_Installer_{0}_manifest.txt" -f $version)
$files = Get-ChildItem -Path $payload -Recurse -File | ForEach-Object {
  $_.FullName.Substring($payload.Length + 1).Replace('\','/')
}
$files | Sort-Object | Set-Content -Path $manifest -Encoding ASCII

$installerExe = Join-Path $dist ("WinLab_Installer_{0}.exe" -f $version)
Remove-Item -Force -Path $installerExe -ErrorAction SilentlyContinue

$issTemplate = Join-Path $root 'scripts/installer/WinLab.iss.tpl'
$issOut = Join-Path $dist 'WinLab_Installer.iss'
$issContent = Get-Content -Raw -Path $issTemplate
$issContent = $issContent.Replace('{{VERSION}}', $version)
$issContent = $issContent.Replace('{{SOURCE_DIR}}', $payload)
$issContent = $issContent.Replace('{{OUTPUT_DIR}}', $dist)
Set-Content -Path $issOut -Value $issContent -Encoding ASCII

$inno = Get-Command iscc.exe -ErrorAction SilentlyContinue
$innoPath = $null
if($inno){ $innoPath = $inno.Source }
if(-not $innoPath){
  $candidates = @(
    (Join-Path ${env:ProgramFiles(x86)} 'Inno Setup 6\ISCC.exe'),
    (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe')
  )
  foreach($c in $candidates){
    if(Test-Path $c){ $innoPath = $c; break }
  }
}

if($innoPath){
  Write-Host "[INFO] Compilando instalador con Inno Setup." -ForegroundColor Cyan
  & $innoPath $issOut | Out-Null
} else {
  Write-Host "[WARN] Inno Setup no encontrado. Usando IExpress." -ForegroundColor Yellow
  $sed = Join-Path $dist 'WinLab_Installer.sed'
  $payloadRel = Get-ChildItem -Path $payload -Recurse -File | ForEach-Object {
    $_.FullName.Substring($installerStage.Length + 1)
  }
  $fileList = @('WinLab_Install.ps1') + $payloadRel
  $fileLines = ($fileList | ForEach-Object { $_ + '=' }) -join "`r`n"
  $sedContent = @"
[Version]
Class=IEXPRESS
SEDVersion=3
[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=1
HideExtractAnimation=1
UseLongFileName=1
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=I
InstallPrompt=
DisplayLicense=
FinishMessage=
TargetName=$installerExe
FriendlyName=WinLab Installer
AppLaunched=powershell.exe -NoProfile -ExecutionPolicy Bypass -File WinLab_Install.ps1
PostInstallCmd=
AdminQuietInstCmd=
UserQuietInstCmd=
SourceFiles=SourceFiles

[SourceFiles]
SourceFiles0=$installerStage
[SourceFiles0]
$fileLines
"@
  Set-Content -Path $sed -Value $sedContent -Encoding ASCII
  $iexpress = Join-Path $env:SystemRoot 'System32\iexpress.exe'
  if(-not (Test-Path $iexpress)){ throw "IExpress no encontrado en $iexpress" }
  & $iexpress /N /Q $sed | Out-Null
}

if(-not (Test-Path $installerExe)){ throw "No se genero el instalador: $installerExe" }
$cleanup = @($issOut)
if($sed){ $cleanup += $sed }
Remove-Item -Force -Path $cleanup -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force -Path $installerStage -ErrorAction SilentlyContinue

# ----- Zips -----
$siteZip = Join-Path $dist 'winlab_site.zip'
$productZip = Join-Path $dist ("WinLab_ProductPack_{0}.zip" -f $version)
$setupSource = Join-Path $root ("downloads/WinLab_Setup_v{0}.zip" -f $version)
$setupZip = Join-Path $dist ("WinLab_Setup_{0}.zip" -f $version)
if(-not (Test-Path $setupSource)){ throw "Missing setup zip: $setupSource" }

Remove-Item -Force -Path $siteZip,$productZip,$setupZip -ErrorAction SilentlyContinue

Push-Location $root
try {
  Write-Host "[INFO] Generando zip del sitio." -ForegroundColor Cyan
  $siteItems = @('index.html','pricing.html','mobile.html','404.html','assets','docs','downloads')
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
  @{ Path = $setupZip; Name = ("dist/WinLab_Setup_{0}.zip" -f $version) },
  @{ Path = $installerExe; Name = ("dist/WinLab_Installer_{0}.exe" -f $version) }
)
$lines = foreach($entry in $hashEntries){
  $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $entry.Path).Hash.ToLowerInvariant()
  "{0}  {1}" -f $hash, $entry.Name
}
Set-Content -Path (Join-Path $dist 'SHA256SUMS.txt') -Value $lines -Encoding ASCII

Write-Host "[INFO] Ejecutando smoke tests." -ForegroundColor Cyan
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'smoke_tests.ps1')

Write-Host "[OK] Release artifacts ready in dist/" -ForegroundColor Green
