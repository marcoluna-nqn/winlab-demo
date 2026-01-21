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
function Assert-TextClean([string]$label, [string]$text, [string[]]$banCase, [string[]]$banInsensitive){
  foreach($token in $banCase){
    if($text -cmatch [regex]::Escape($token)){ Fail "$label contiene texto no permitido: $token" }
  }
  foreach($token in $banInsensitive){
    if($token -match '\s'){
      $pattern = '(?i)' + [regex]::Escape($token)
    } else {
      $pattern = '(?i)(?<![A-Za-z])' + [regex]::Escape($token) + '(?![A-Za-z])'
    }
    if($text -match $pattern){ Fail "$label contiene texto no permitido: $token" }
  }
  if($text -match '\.\.\.'){ Fail "$label contiene '...'" }
}

$scriptPath = $PSCommandPath
if(-not $scriptPath){ $scriptPath = $MyInvocation.MyCommand.Path }
$root = (Resolve-Path (Split-Path -Parent $scriptPath)).Path
Set-Location $root

$required = @(
  'index.html',
  'pricing.html',
  'mobile.html',
  '404.html',
  '.nojekyll',
  'docs/guia.html',
  'docs/guia_cliente.html',
  'assets/pwa/manifest.webmanifest',
  'assets/pwa/sw.js',
  'assets/pwa/icon.svg',
  'assets/og/og.png',
  'assets/media/winlab-demo.mp4',
  'assets/media/winlab-demo-poster.png',
  'assets/media/demo-embed.html',
  'assets/config.js',
  'assets/styles.css',
  '.github/workflows/ci.yml',
  'scripts/publish.ps1',
  'scripts/installer/WinLab.iss.tpl',
  'scripts/installer/WinLab_Install.ps1',
  'scripts/installer/Uninstall-WinLab.ps1',
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
  'downloads/remote_host/README_REMOTE_HOST_ESAR.txt',
  'downloads/remote_host/RemoteHost_Doctor.ps1',
  'downloads/remote_host/RemoteHost_Hardening.txt',
  'downloads/remote_host/WinLab_RemoteHost.ps1',
  'downloads/remote_host/Install_RemoteHost.ps1',
  'downloads/remote_host/Start_RemoteHost.ps1',
  'downloads/remote_host/Stop_RemoteHost.ps1',
  'downloads/remote_host/Uninstall_RemoteHost.ps1',
  'downloads/remote_host/remote_host_config.json',
  'downloads/license.sample.json',
  'downloads/launcher/WinLab_Launcher_UI.ps1',
  'downloads/presets/Balanced_AUTO.wsb',
  'downloads/presets/UltraSecure_AUTO.wsb',
  'downloads/presets/Networked_AUTO.wsb',
  'downloads/safe_mode/README.txt',
  'downloads/safe_mode/SafeMode_Helper.cmd',
  'tools/cli/WinLab.ps1',
  'tools/cli/WinLab_Update.ps1',
  'tools/cli/WinLab_Context.cmd',
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
$versionPath = Join-Path $root 'tools/cli/version.txt'
$version = (Get-Content -Raw -Path $versionPath).Trim()
if([string]::IsNullOrWhiteSpace($version)){ Fail 'Version vacia en tools/cli/version.txt' }
if($version -ne '1.0.0'){ Fail "Version esperada 1.0.0 y se encontro $version" }
$setupZip = Join-Path $root ("downloads/WinLab_Setup_v{0}.zip" -f $version)
if(-not (Test-Path $setupZip)){ Fail "Falta downloads/WinLab_Setup_v$version.zip" }
Ok "Setup ZIP OK (v$version)"

$installerExe = Join-Path $root ("dist/WinLab_Installer_{0}.exe" -f $version)
$installerManifest = Join-Path $root ("dist/WinLab_Installer_{0}_manifest.txt" -f $version)
if(-not (Test-Path $installerExe)){ Fail "Falta dist/WinLab_Installer_$version.exe" }
if(-not (Test-Path $installerManifest)){ Fail "Falta dist/WinLab_Installer_${version}_manifest.txt" }
Ok "Installer EXE OK (v$version)"

$banTokensCase = @('TODO','PLACEHOLDER','TBD','PEGAR_AQUI')
$banTokensInsensitive = @('lorem','lorem ipsum','example','buy','features','preview','starter','teams','download','support','quick','guide','contact','free','trial','learn','click')
function Assert-TextNoPlaceholders([string]$label, [string]$text){
  Assert-TextClean $label $text $banTokensCase @()
}

# index.html debe referenciar scripts y un setup existente
$index = ReadUtf8 (Join-Path $root 'index.html')
$indexText = StripHtml $index
$indexDeps = @('assets/config\.js','assets/app\.js')
foreach($d in $indexDeps){
  if($index -notmatch $d){ Fail "index.html no referencia $d" }
}
if($index -notmatch 'assets/pwa/manifest\.webmanifest'){ Fail 'index.html sin manifest PWA' }
if($indexText -notmatch [regex]::Escape('Comprar ahora')){ Fail 'index.html sin copy requerido: Comprar ahora' }
if($indexText -notmatch [regex]::Escape('Cómo funciona') -and $indexText -notmatch [regex]::Escape('Como funciona')){
  Fail 'index.html sin copy requerido: Cómo funciona'
}
if($indexText -notmatch [regex]::Escape('Ver demo')){ Fail 'index.html sin CTA Ver demo' }
if($indexText -notmatch '(?i)Windows Sandbox'){ Fail 'index.html sin referencia a Windows Sandbox' }
if($indexText -notmatch '(?i)Microsoft Defender'){ Fail 'index.html sin referencia a Microsoft Defender' }
if($indexText -notmatch '(?i)sin servidor'){ Fail 'index.html sin linea requerida: sin servidor' }
if($indexText -notmatch '(?i)sandbox descartable'){ Fail 'index.html sin linea requerida: sandbox descartable' }
if($indexText -notmatch '(?i)reporte listo'){ Fail 'index.html sin linea requerida: reporte listo' }
if($indexText -notmatch 'ARS'){ Fail 'index.html sin precios ARS' }
if($indexText -notmatch '(?i)licencia'){ Fail 'index.html sin sección de licencia' }
if($index -notmatch 'data-theme-toggle' -and $index -notmatch 'theme-toggle'){
  Fail 'index.html sin toggle de tema'
}
if($index -notmatch 'data-video-open'){ Fail 'index.html sin CTA data-video-open' }
if($index -notmatch 'data-video-modal'){ Fail 'index.html sin modal de video' }
if($index -notmatch 'assets/media/winlab-demo\.mp4'){ Fail 'index.html sin referencia al mp4' }
Assert-TextClean 'index.html' $indexText $banTokensCase $banTokensInsensitive
$m = [regex]::Match($index, 'downloads/(WinLab_Setup_v[0-9]+\.[0-9]+\.[0-9]+\.zip)')
if(-not $m.Success){ Fail 'index.html no referencia downloads/WinLab_Setup_vX.Y.Z.zip' }
$setupRel = $m.Groups[1].Value
$setupPath = Join-Path $root ("downloads/" + $setupRel)
if(-not (Test-Path $setupPath)){ Fail "No existe el ZIP de instalador referenciado: $setupRel" }
Ok "Installer link OK: $setupRel"
$sectionIds = @('id="how"','id="features"','id="reports"','id="pricing"','id="requirements"','id="faq"')
foreach($sid in $sectionIds){
  if($index -notmatch $sid){ Fail "index.html sin seccion requerida: $sid" }
}
Ok 'Secciones clave en index OK'

$mobile = ReadUtf8 (Join-Path $root 'mobile.html')
$mobileText = StripHtml $mobile
if($mobile -notmatch 'assets/pwa/manifest\.webmanifest'){ Fail 'mobile.html sin manifest PWA' }
if($mobileText -notmatch '(?i)celular'){ Fail 'mobile.html sin referencia a celular' }
if($mobileText -notmatch '(?i)Laboratorio Remoto'){ Fail 'mobile.html sin Laboratorio Remoto' }
if($mobileText -notmatch '(?i)Tailscale|VPN'){ Fail 'mobile.html sin referencia a Tailscale o VPN' }
if($mobileText -notmatch '(?i)no corre en iPhone|no corre en Android|no corre en iOS'){ Fail 'mobile.html sin aviso de no correr en iPhone/Android' }
if($mobile -notmatch 'downloads/remote_host/README_REMOTE_HOST_ESAR\.txt'){ Fail 'mobile.html sin link a remote_host' }
Ok 'mobile.html OK'

# Validar textos clave en docs y samples (sin placeholders ni ingles)
$textChecks = @(
  @{ Label = 'README.md'; Path = 'README.md'; Strip = $false },
  @{ Label = 'docs/guia.html'; Path = 'docs/guia.html'; Strip = $true },
  @{ Label = 'docs/guia_cliente.html'; Path = 'docs/guia_cliente.html'; Strip = $true },
  @{ Label = 'downloads/launcher/README_LAUNCHER.txt'; Path = 'downloads/launcher/README_LAUNCHER.txt'; Strip = $false },
  @{ Label = 'downloads/license.sample.json'; Path = 'downloads/license.sample.json'; Strip = $false },
  @{ Label = 'downloads/remote_host/README_REMOTE_HOST_ESAR.txt'; Path = 'downloads/remote_host/README_REMOTE_HOST_ESAR.txt'; Strip = $false },
  @{ Label = 'downloads/samples/report_ok.html'; Path = 'downloads/samples/report_ok.html'; Strip = $true },
  @{ Label = 'downloads/samples/report_detectado.html'; Path = 'downloads/samples/report_detectado.html'; Strip = $true },
  @{ Label = 'downloads/samples/report_inconcluso.html'; Path = 'downloads/samples/report_inconcluso.html'; Strip = $true }
)
foreach($item in $textChecks){
  $full = Join-Path $root $item.Path
  $raw = ReadUtf8 $full
  $text = if($item.Strip){ StripHtml $raw } else { $raw }
  Assert-TextClean $item.Label $text $banTokensCase $banTokensInsensitive
}
Ok 'Docs y samples OK'

# Validar textos en scripts (sin placeholders ni rutas truncadas)
$scriptFiles = Get-ChildItem -Path $root -Recurse -File -Include *.ps1,*.cmd |
  Where-Object {
    $_.FullName -notmatch '\\dist\\' -and
    $_.FullName -notmatch '\\tmp\\' -and
    $_.FullName -notmatch '\\.git\\' -and
    $_.Name -ne 'smoke_tests.ps1'
  }
foreach($f in $scriptFiles){
  $content = ReadUtf8 $f.FullName
  $label = 'script: ' + $f.FullName.Substring($root.Length + 1)
  Assert-TextNoPlaceholders $label $content
}
Ok 'Scripts sin placeholders ni truncados'

# Verificar contenido minimo del instalador
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($setupPath)
try {
  $names = $zip.Entries | ForEach-Object { $_.FullName }

  $mustContain = @(
    'WinLab_Setup.cmd',
    'payload/WinLab_Launcher.cmd',
    'payload/bin/InsideLab.ps1',
    'payload/tools/Run-WinLab.cmd',
    'payload/WinLab.ps1',
    'payload/version.txt',
    'payload/docs/guia.html'
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

  $manifestLines = Get-Content -Path $installerManifest
  $manifestMust = @(
    'tools/cli/WinLab.ps1',
    'tools/cli/WinLab_Update.ps1',
    'tools/cli/WinLab_Context.cmd',
    'downloads/launcher/WinLab_Launcher.cmd',
    'downloads/launcher/WinLab_Launcher_UI.ps1',
    'downloads/presets/Balanced_AUTO.wsb',
    'downloads/presets/UltraSecure_AUTO.wsb',
    'downloads/presets/Networked_AUTO.wsb',
    'downloads/safe_mode/README.txt',
    'downloads/safe_mode/SafeMode_Helper.cmd',
    'downloads/remote_host/README_REMOTE_HOST_ESAR.txt',
    'downloads/remote_host/WinLab_RemoteHost.ps1',
    'downloads/remote_host/remote_host_config.json',
    'downloads/license.sample.json',
    'downloads/samples/report_ok.html',
    'downloads/samples/report_detectado.html',
    'downloads/samples/report_inconcluso.html',
    'docs/guia.html',
    'docs/guia_cliente.html',
    'VERSION.txt',
    'Uninstall-WinLab.ps1'
  )
  foreach($p in $manifestMust){
    if(-not ($manifestLines -contains $p)){ Fail "Installer manifest sin archivo requerido: $p" }
  }
Ok 'Installer manifest OK'

  # Validar texto dentro del ZIP (sin placeholders ni '...')
  $textExt = @('.cmd','.ps1','.txt','.md','.html','.json')
  foreach($entry in $zip.Entries){
    if($entry.FullName.EndsWith('/')){ continue }
    $ext = [System.IO.Path]::GetExtension($entry.FullName).ToLowerInvariant()
    if($textExt -contains $ext){
      $reader = New-Object System.IO.StreamReader($entry.Open(), [System.Text.Encoding]::UTF8, $true)
      try {
        $content = $reader.ReadToEnd()
      } finally {
        $reader.Dispose()
      }
      Assert-TextNoPlaceholders ("setup zip: " + $entry.FullName) $content
    }
  }
} finally {
  $zip.Dispose()
}

# Launcher debe usar staging en C:\WinLab_Pack
$launcherPath = Join-Path $root 'downloads/launcher/WinLab_Launcher.cmd'
$launcher = Get-Content -Path $launcherPath -Raw
$launcherMust = @('C:\WinLab_Pack','C:\WinLab_Inbox','C:\WinLab_Outbox','C:\WinLab\logs')
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

# Context menu integracion debe existir en scripts de instalacion
$installScript = ReadUtf8 (Join-Path $root 'scripts/installer/WinLab_Install.ps1')
$uninstallScript = ReadUtf8 (Join-Path $root 'scripts/installer/Uninstall-WinLab.ps1')
if($installScript -notmatch 'WinLab_Context\.cmd'){ Fail 'WinLab_Install.ps1 sin registro de contexto' }
if($installScript -notmatch 'HKLM:\\\\Software\\\\Classes' -or $installScript -notmatch 'WinLabAnalyze'){
  Fail 'WinLab_Install.ps1 sin clave de contexto para archivos'
}
if($uninstallScript -notmatch 'HKLM:\\\\Software\\\\Classes' -or $uninstallScript -notmatch 'WinLabAnalyze'){
  Fail 'Uninstall-WinLab.ps1 sin clave de contexto para archivos'
}
Ok 'Integracion de menu contextual OK'

# Pricing debe cargar config/app y tener botones
$pricing = ReadUtf8 (Join-Path $root 'pricing.html')
$pricingText = StripHtml $pricing
if($pricing -notmatch 'assets/config\.js'){ Fail 'pricing.html no referencia assets/config.js' }
if($pricing -notmatch 'assets/app\.js'){ Fail 'pricing.html no referencia assets/app.js' }
if($pricing -notmatch 'assets/pwa/manifest\.webmanifest'){ Fail 'pricing.html sin manifest PWA' }
if($pricingText -notmatch [regex]::Escape('Comprar ahora')){ Fail 'pricing.html sin CTA Comprar ahora' }
if($pricing -notmatch 'data-theme-toggle' -and $pricing -notmatch 'theme-toggle'){
  Fail 'pricing.html sin toggle de tema'
}
if($pricing -notmatch [regex]::Escape('Mejor relación precio/valor') -and $pricing -notmatch [regex]::Escape('Mejor relacion precio/valor')){
  Fail 'pricing.html sin badge Mejor relación precio/valor'
}
if($pricingText -notmatch 'ARS' -or $pricingText -notmatch '\bARS\s*[0-9]'){ Fail 'pricing.html sin precios ARS numericos' }
if($pricingText -match [regex]::Escape('Consultar')){ Fail 'pricing.html contiene Consultar' }
if($pricing -notmatch 'mobile\.html'){ Fail 'pricing.html sin link a mobile.html' }
Assert-TextClean 'pricing.html' $pricingText $banTokensCase $banTokensInsensitive
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
if($app -notmatch 'serviceWorker'){ Fail 'assets/app.js sin registro de service worker' }
if($app -notmatch 'assets/pwa/sw\.js'){ Fail 'assets/app.js sin referencia a assets/pwa/sw.js' }
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
  if($json.schemaVersion -ne '1.1'){ Fail "Sample JSON con schemaVersion invalida: $p" }
}
Ok 'Samples JSON OK'

Write-Host "All smoke tests passed" -ForegroundColor Green
