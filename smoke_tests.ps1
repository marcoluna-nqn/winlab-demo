# WinLab smoke tests (fast validation)
# Validates basic repo integrity, local links, and installer contents.

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Fail($m){ Write-Host "[FAIL] $m" -ForegroundColor Red; exit 1 }
function Ok($m){ Write-Host "[ OK ] $m" -ForegroundColor Green }

$scriptPath = $PSCommandPath
if(-not $scriptPath){ $scriptPath = $MyInvocation.MyCommand.Path }
$root = (Resolve-Path (Split-Path -Parent $scriptPath)).Path
Set-Location $root

$required = @(
  'index.html',
  'pricing.html',
  '404.html',
  'docs/guia.html',
  'assets/config.js',
  'assets/styles.css',
  'downloads/samples/report_ok.html',
  'downloads/samples/report_detectado.html',
  'downloads/samples/report_inconcluso.html',
  'downloads/samples/report_ok.json',
  'downloads/samples/report_detectado.json',
  'downloads/samples/report_inconcluso.json',
  'downloads/launcher/WinLab_Launcher.cmd',
  'downloads/launcher/README_LAUNCHER.txt',
  'downloads/presets/Balanced_AUTO.wsb',
  'downloads/presets/UltraSecure_AUTO.wsb',
  'downloads/presets/Networked_AUTO.wsb',
  'tools/cli/WinLab.ps1',
  'tools/cli/winlab_cli.ps1',
  'tools/cli/bin/InsideLab.ps1',
  'tools/cli/version.txt',
  'PROMPT_CODEX_XHIGH.md',
  'CODEX_START.txt'
)
foreach($r in $required){
  if(-not (Test-Path (Join-Path $root $r))) { Fail "Falta requerido: $r" }
}
Ok 'Estructura base OK'

# index.html debe referenciar un setup existente
$index = Get-Content -Path (Join-Path $root 'index.html') -Raw
$m = [regex]::Match($index, 'downloads/(WinLab_Setup_v[0-9]+\.[0-9]+\.[0-9]+\.zip)')
if(-not $m.Success){ Fail 'index.html no referencia downloads/WinLab_Setup_vX.Y.Z.zip' }
$setupRel = $m.Groups[1].Value
$setupPath = Join-Path $root ("downloads/" + $setupRel)
if(-not (Test-Path $setupPath)){ Fail "No existe el ZIP de instalador referenciado: $setupRel" }
Ok "Installer link OK: $setupRel"

# Verificar contenido mínimo del instalador
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($setupPath)
try {
  $names = $zip.Entries | ForEach-Object { $_.FullName }
} finally {
  $zip.Dispose()
}
$mustContain = @(
  'payload/bin/InsideLab.ps1',
  'payload/tools/Run-WinLab.cmd',
  'payload/WinLab.ps1',
  'payload/version.txt'
)
function HasZipEntry([string]$name, [string[]]$entries){
  if($entries -contains $name){ return $true }
  $alt = $name.Replace('/', '\')
  return ($entries -contains $alt)
}
foreach($p in $mustContain){
  if(-not (HasZipEntry -name $p -entries $names)){ Fail "El instalador no contiene: $p" }
}
Ok 'Contenido mínimo del instalador OK'

# Validar schemaVersion en samples JSON
$sampleJson = @(
  'downloads/samples/report_ok.json',
  'downloads/samples/report_detectado.json',
  'downloads/samples/report_inconcluso.json'
)
foreach($p in $sampleJson){
  $full = Join-Path $root $p
  $json = Get-Content -Raw -Path $full | ConvertFrom-Json
  if($json.schemaVersion -ne '1.0'){ Fail "Sample JSON con schemaVersion invalida: $p" }
}
Ok 'Samples JSON OK'

Write-Host "All smoke tests passed" -ForegroundColor Green
