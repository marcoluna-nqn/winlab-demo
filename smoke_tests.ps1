# WinLab smoke tests (fast validation)
# Validates basic repo integrity, local links, and installer contents.

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

function Fail($m){ Write-Host "[FAIL] $m" -ForegroundColor Red; exit 1 }
function Ok($m){ Write-Host "[ OK ] $m" -ForegroundColor Green }
function ReadUtf8([string]$path){
  return [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
}
function StripHtml([string]$html){
  return ($html -replace '<[^>]+>', ' ')
}

$scriptPath = $PSCommandPath
if(-not $scriptPath){ $scriptPath = $MyInvocation.MyCommand.Path }
$root = (Resolve-Path (Split-Path -Parent $scriptPath)).Path
Set-Location $root

$required = @(
  'index.html',
  'pricing.html',
  '404.html',
  '.nojekyll',
  'docs/guia.html',
  'assets/config.js',
  'assets/styles.css',
  'scripts/publish.ps1',
  'RELEASE_NOTES.md',
  'PUBLISH_CHECKLIST.md',
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
  'downloads/safe_mode/README.txt',
  'downloads/safe_mode/SafeMode_Helper.cmd',
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

# Verificar instalador presente
$setupZip = Join-Path $root 'downloads/WinLab_Setup_v0.8.0.zip'
if(-not (Test-Path $setupZip)){ Fail 'Falta downloads/WinLab_Setup_v0.8.0.zip' }
Ok 'Setup ZIP OK'

$banTokensCase = @('TODO','PLACEHOLDER','TBD')
$banTokensInsensitive = @('lorem','lorem ipsum','buy','pricing','features','preview','starter','teams')

# index.html debe referenciar scripts y un setup existente
$index = ReadUtf8 (Join-Path $root 'index.html')
$indexText = StripHtml $index
$indexDeps = @('assets/config\.js','assets/app\.js')
foreach($d in $indexDeps){
  if($index -notmatch $d){ Fail "index.html no referencia $d" }
}
if($indexText -notmatch [regex]::Escape('Comprar ahora')){ Fail 'index.html sin copy requerido: Comprar ahora' }
if($indexText -notmatch [regex]::Escape('Cómo funciona') -and $indexText -notmatch [regex]::Escape('Como funciona')){
  Fail 'index.html sin copy requerido: Cómo funciona'
}
if($index -notmatch 'data-theme-toggle' -and $index -notmatch 'theme-toggle'){
  Fail 'index.html sin toggle de tema'
}
foreach($token in $banTokensCase){
  if($indexText -cmatch [regex]::Escape($token)){ Fail "index.html contiene texto no permitido: $token" }
}
foreach($token in $banTokensInsensitive){
  $pattern = '(?i)' + [regex]::Escape($token)
  if($indexText -match $pattern){ Fail "index.html contiene texto no permitido: $token" }
}
$m = [regex]::Match($index, 'downloads/(WinLab_Setup_v[0-9]+\.[0-9]+\.[0-9]+\.zip)')
if(-not $m.Success){ Fail 'index.html no referencia downloads/WinLab_Setup_vX.Y.Z.zip' }
$setupRel = $m.Groups[1].Value
$setupPath = Join-Path $root ("downloads/" + $setupRel)
if(-not (Test-Path $setupPath)){ Fail "No existe el ZIP de instalador referenciado: $setupRel" }
Ok "Installer link OK: $setupRel"
$sectionIds = @('id="how"','id="features"','id="reports"','id="pricing"','id="faq"')
foreach($sid in $sectionIds){
  if($index -notmatch $sid){ Fail "index.html sin seccion requerida: $sid" }
}
Ok 'Secciones clave en index OK'

# Verificar contenido minimo del instalador
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
Ok 'Contenido minimo del instalador OK'

# Launcher debe usar staging en C:\WinLab_Pack
$launcherPath = Join-Path $root 'downloads/launcher/WinLab_Launcher.cmd'
$launcher = Get-Content -Path $launcherPath -Raw
$launcherMust = @('C:\WinLab_Pack','C:\WinLab_Inbox','C:\WinLab_Outbox')
foreach($s in $launcherMust){
  if($launcher -notmatch [regex]::Escape($s)){ Fail "Launcher sin ruta requerida: $s" }
}
Ok 'Launcher staging OK'

# Presets AUTO deben mapear staging/inbox/outbox
$presetPaths = @(
  'downloads/presets/Balanced_AUTO.wsb',
  'downloads/presets/UltraSecure_AUTO.wsb',
  'downloads/presets/Networked_AUTO.wsb'
)
foreach($p in $presetPaths){
  $content = Get-Content -Path (Join-Path $root $p) -Raw
  foreach($s in $launcherMust){
    if($content -notmatch [regex]::Escape($s)){ Fail "Preset $p sin ruta requerida: $s" }
  }
}
Ok 'Presets AUTO OK'

# Pricing debe cargar config/app y tener botones
$pricing = ReadUtf8 (Join-Path $root 'pricing.html')
$pricingText = StripHtml $pricing
if($pricing -notmatch 'assets/config\.js'){ Fail 'pricing.html no referencia assets/config.js' }
if($pricing -notmatch 'assets/app\.js'){ Fail 'pricing.html no referencia assets/app.js' }
if($pricingText -notmatch [regex]::Escape('Comprar ahora')){ Fail 'pricing.html sin CTA Comprar ahora' }
if($pricing -notmatch 'data-theme-toggle' -and $pricing -notmatch 'theme-toggle'){
  Fail 'pricing.html sin toggle de tema'
}
if($pricing -notmatch [regex]::Escape('Mejor relación precio/valor') -and $pricing -notmatch [regex]::Escape('Mejor relacion precio/valor')){
  Fail 'pricing.html sin badge Mejor relación precio/valor'
}
foreach($token in $banTokensCase){
  if($pricingText -cmatch [regex]::Escape($token)){ Fail "pricing.html contiene texto no permitido: $token" }
}
foreach($token in $banTokensInsensitive){
  $pattern = '(?i)' + [regex]::Escape($token)
  if($pricingText -match $pattern){ Fail "pricing.html contiene texto no permitido: $token" }
}
foreach($token in @('data-buy="mp"','data-buy="stripe"','data-buy="whatsapp"')){
  if($pricing -notmatch [regex]::Escape($token)){ Fail "pricing.html sin boton: $token" }
}
$config = Get-Content -Path (Join-Path $root 'assets/config.js') -Raw
if($config -notmatch 'WHATSAPP_URL'){ Fail 'assets/config.js sin WHATSAPP_URL' }
$waMatch = [regex]::Match($config, 'WHATSAPP_URL\s*:\s*"([^"]+)"')
if(-not $waMatch.Success -or [string]::IsNullOrWhiteSpace($waMatch.Groups[1].Value)){
  Fail 'assets/config.js WHATSAPP_URL vacio'
}
$app = Get-Content -Path (Join-Path $root 'assets/app.js') -Raw
if($app -notmatch 'defaultWhatsApp'){ Fail 'assets/app.js sin fallback WhatsApp' }
Ok 'Pricing/config OK'

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
