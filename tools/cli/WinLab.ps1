[CmdletBinding()]
param(
  [Parameter(Position=0)]
  [ValidateSet('scan','scan-file','url','analyze-url','session','help','version','doctor')]
  [string]$Command = 'help',

  # scan
  [string]$Path,

  # url/session
  [string]$Url,

  [ValidateSet('Balanced','UltraSecure','Networked')]
  [string]$Preset,

  [ValidateRange(1,120)]
  [int]$Minutes = 0,

  [switch]$OpenOutbox
)

$ErrorActionPreference = 'Stop'

$script:LogFile = $null

function Write-LogLine([string]$m){
  if(-not $script:LogFile){ return }
  $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  Add-Content -LiteralPath $script:LogFile -Value ("[{0}] {1}" -f $ts, $m)
}
function Write-Info([string]$m){ Write-Host $m; Write-LogLine $m }
function Write-Warn([string]$m){ Write-Host $m -ForegroundColor Yellow; Write-LogLine ("ADVERTENCIA: {0}" -f $m) }
function Write-Err([string]$m){ Write-Host $m -ForegroundColor Red; Write-LogLine ("ERROR: {0}" -f $m) }

function Get-NowStamp { Get-Date -Format 'yyyyMMdd_HHmmss' }

function Get-LogRoot {
  $primary = 'C:\WinLab\logs'
  try{
    New-Item -ItemType Directory -Force -Path $primary | Out-Null
    return $primary
  } catch {}
  $fallback = Join-Path $env:LOCALAPPDATA 'WinLab\logs'
  try{
    New-Item -ItemType Directory -Force -Path $fallback | Out-Null
    return $fallback
  } catch {}
  return $env:TEMP
}

function Get-WinLabVersion {
  $here = Split-Path -Parent $MyInvocation.MyCommand.Path
  $local = Join-Path $here 'version.txt'
  if(Test-Path $local){
    return (Get-Content -LiteralPath $local | Select-Object -First 1).Trim()
  }
  try{
    $root = Resolve-Path (Join-Path $here '..\\..') -ErrorAction SilentlyContinue
    if($root){
      $rootVer = Join-Path $root 'VERSION.txt'
      if(Test-Path $rootVer){
        return (Get-Content -LiteralPath $rootVer | Select-Object -First 1).Trim()
      }
    }
  } catch {}
  return 'unknown'
}

function Test-IsAdmin {
  try{
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
  } catch {
    return $false
  }
}

function Get-EditionInfo {
  $edition = ''
  $product = ''
  try{
    $edition = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction SilentlyContinue).EditionID
    $product = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName -ErrorAction SilentlyContinue).ProductName
  } catch {}
  if(-not $edition){ $edition = 'UNKNOWN' }
  if(-not $product){ $product = 'Windows' }
  return [pscustomobject]@{ Edition=$edition; Product=$product }
}

function Get-FeatureState {
  try{
    $line = (dism /online /English /Get-FeatureInfo /FeatureName:Containers-DisposableClientVM | Select-String -Pattern '^State' -ErrorAction SilentlyContinue | Select-Object -First 1).Line
    return $line
  } catch {
    return $null
  }
}

function Run-Doctor {
  $reportPath = 'C:\WinLab\logs\doctor.txt'
  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("WinLab Doctor")
  $lines.Add("Fecha: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
  $lines.Add("Version: $(Get-WinLabVersion)")

  $isAdmin = Test-IsAdmin
  $lines.Add("Admin: $isAdmin")

  $ed = Get-EditionInfo
  $lines.Add("Windows: $($ed.Product) (EditionID=$($ed.Edition))")
  $supported = $true
  if($ed.Edition -match 'Core' -or $ed.Product -match 'Home'){
    $supported = $false
  }
  $lines.Add("Edicion compatible: $supported")

  $wsbExe = Join-Path $env:SystemRoot 'System32\WindowsSandbox.exe'
  $wsbExists = Test-Path $wsbExe
  $lines.Add("WindowsSandbox.exe: $wsbExists")

  $featureLine = Get-FeatureState
  $featureEnabled = $false
  if($featureLine -and $featureLine -match 'Enabled'){ $featureEnabled = $true }
  $lines.Add("Feature Containers-DisposableClientVM: $featureLine")

  $logRoot = 'C:\WinLab\logs'
  $inbox = 'C:\WinLab_Inbox'
  $outbox = 'C:\WinLab_Outbox'
  $dirs = @($logRoot,$inbox,$outbox)
  foreach($d in $dirs){
    $ok = Test-Path $d
    if(-not $ok){
      try{ New-Item -ItemType Directory -Force -Path $d | Out-Null; $ok = $true } catch {}
    }
    $lines.Add("Carpeta $d: $ok")
  }

  $writeOk = $false
  try{
    New-Item -ItemType Directory -Force -Path $logRoot | Out-Null
    $lines | Set-Content -LiteralPath $reportPath -Encoding UTF8
    $writeOk = $true
  } catch {
    $writeOk = $false
  }
  $lines.Add("Log escrito: $writeOk ($reportPath)")

  $issues = @()
  if(-not $supported){ $issues += 'Edicion no compatible (se requiere Pro/Enterprise/Education).' }
  if(-not $wsbExists){ $issues += 'WindowsSandbox.exe no existe.' }
  if(-not $featureEnabled){
    if($featureLine){ $issues += 'Feature Containers-DisposableClientVM no esta habilitado.' }
    else { $issues += 'No se pudo consultar el feature Containers-DisposableClientVM (DISM). Ejecuta como Administrador.' }
  }
  if(-not $writeOk){ $issues += 'No se pudo escribir el reporte de doctor en C:\\WinLab\\logs.' }

  if($issues.Count -gt 0){
    Write-Warn 'Doctor: se detectaron problemas.'
    foreach($i in $issues){ Write-Warn ("- " + $i) }
    exit 2
  }

  Write-Info 'Doctor: todo OK.'
  Write-Info ("Reporte: " + $reportPath)
  exit 0
}
function Ensure-SandboxAvailable {
  $wsbExe = Join-Path $env:SystemRoot 'System32\WindowsSandbox.exe'
  if(-not (Test-Path $wsbExe)){
    throw "Windows Sandbox no esta disponible (WindowsSandbox.exe no existe). Requiere Windows 10/11 Pro/Enterprise/Education y el feature habilitado."
  }

  $stateLine = (dism /online /English /Get-FeatureInfo /FeatureName:Containers-DisposableClientVM | Select-String -Pattern '^State' -ErrorAction SilentlyContinue | Select-Object -First 1).Line
  if(-not $stateLine){
    throw 'No pude consultar el estado del feature (DISM). Ejecuta como Administrador o verifica DISM/Windows Update.'
  }
  if($stateLine -notmatch 'Enabled'){
    throw "Windows Sandbox no esta habilitado ($stateLine). Habilitalo con: Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All"
  }
  return $wsbExe
}

function Resolve-Defaults {
  if(-not $Preset -or $Preset -eq ''){
    if($Command -in @('url','session','analyze-url')){ $script:Preset = 'Networked' }
    elseif($Command -in @('scan','scan-file')){ $script:Preset = 'Balanced' }
  }

  if($Minutes -le 0){
    switch($Preset){
      'UltraSecure' { $script:Minutes = 5 }
      'Networked'   { $script:Minutes = 15 }
      default       { $script:Minutes = 10 }
    }
  }
}

function Start-WinLabSandbox {
  param(
    [string]$Preset,
    [int]$Minutes,
    [string]$Url,
    [string]$TargetPath
  )

  $wsbExe = Ensure-SandboxAvailable

  $root = Split-Path -Parent $MyInvocation.MyCommand.Path
  $labHome = Join-Path $env:LOCALAPPDATA 'WinLab'
  $outboxHost = Join-Path $labHome 'outbox'
  $logRoot = Get-LogRoot
  New-Item -ItemType Directory -Force -Path $outboxHost | Out-Null
  $stamp = Get-NowStamp
  $script:LogFile = Join-Path $logRoot ("host_{0}_{1}.log" -f $Preset,$stamp)
  Write-Info "Logs: $logRoot"
  $wsbFile = Join-Path $env:TEMP ("WinLab_{0}_{1}.wsb" -f $Preset,$stamp)

  $networking = 'Enable'
  $firewall = 'InternetOnly'
  $vGpu = 'Default'
  if($Preset -eq 'UltraSecure'){
    $networking = 'Disable'
    $firewall = 'BlockAll'
    $vGpu = 'Disable'
  } elseif($Preset -eq 'Networked'){
    $networking = 'Enable'
    $firewall = 'AllowMost'
    $vGpu = 'Default'
  }

  # Mapped inbox: default to Downloads (safe, ReadOnly), or the directory of TargetPath.
  $inboxHost = Join-Path $env:USERPROFILE 'Downloads'
  $targetName = ''
  if($TargetPath -and (Test-Path $TargetPath)){
    $inboxHost = Split-Path -Parent $TargetPath
    $targetName = Split-Path -Leaf $TargetPath
  }

  # Start watchdog (outbox hardening) using the bundled cmd.
  $watchdog = Join-Path (Join-Path $root 'tools') 'Watchdog.cmd'
  if(Test-Path $watchdog){
    Start-Process -WindowStyle Minimized -FilePath 'cmd.exe' -ArgumentList "/c \"`"$watchdog`" `"$outboxHost`" $Minutes $stamp > `"$logRoot\watchdog_$stamp.log`" 2>&1\"" | Out-Null
  }

  $logonCmd = @(
    'powershell.exe -NoProfile -ExecutionPolicy Bypass',
    '-File "C:\WinLabPkg\bin\InsideLab.ps1"',
    "-Preset $Preset",
    '-InputFolder "C:\WinLabInboxRO"',
    '-OutFolder "C:\Outbox"',
    "-Minutes $Minutes",
    "-FirewallMode $firewall",
    '-EnableOutbox 1',
    '-LogFolder "C:\WinLabLogs"'
  )
  if($Url){ $logonCmd += ('-Url "{0}"' -f $Url) }
  if($targetName){ $logonCmd += ('-TargetFileName "{0}"' -f $targetName) }
  $logonCmd = ($logonCmd -join ' ')

  $xml = @()
  $xml += '<Configuration>'
  $xml += '  <ProtectedClient>Enable</ProtectedClient>'
  $xml += "  <VGpu>$vGpu</VGpu>"
  $xml += "  <Networking>$networking</Networking>"
  $xml += '  <ClipboardRedirection>Disable</ClipboardRedirection>'
  $xml += '  <PrinterRedirection>Disable</PrinterRedirection>'
  $xml += '  <AudioInput>Disable</AudioInput>'
  $xml += '  <VideoInput>Disable</VideoInput>'
  $xml += '  <MappedFolders>'
  $xml += '    <MappedFolder>'
  $xml += "      <HostFolder>$inboxHost</HostFolder>"
  $xml += '      <SandboxFolder>C:\WinLabInboxRO</SandboxFolder>'
  $xml += '      <ReadOnly>true</ReadOnly>'
  $xml += '    </MappedFolder>'
  $xml += '    <MappedFolder>'
  $xml += "      <HostFolder>$root</HostFolder>"
  $xml += '      <SandboxFolder>C:\WinLabPkg</SandboxFolder>'
  $xml += '      <ReadOnly>true</ReadOnly>'
  $xml += '    </MappedFolder>'
  $xml += '    <MappedFolder>'
  $xml += "      <HostFolder>$outboxHost</HostFolder>"
  $xml += '      <SandboxFolder>C:\Outbox</SandboxFolder>'
  $xml += '      <ReadOnly>false</ReadOnly>'
  $xml += '    </MappedFolder>'
  $xml += '    <MappedFolder>'
  $xml += "      <HostFolder>$logRoot</HostFolder>"
  $xml += '      <SandboxFolder>C:\WinLabLogs</SandboxFolder>'
  $xml += '      <ReadOnly>false</ReadOnly>'
  $xml += '    </MappedFolder>'
  $xml += '  </MappedFolders>'
  $xml += '  <LogonCommand>'
  $xml += "    <Command>$logonCmd</Command>"
  $xml += '  </LogonCommand>'
  $xml += '</Configuration>'

  $xml -join "`r`n" | Set-Content -LiteralPath $wsbFile -Encoding UTF8

  Write-Info "[WinLab] Preset=$Preset Minutes=$Minutes"
  if($Url){ Write-Info "[WinLab] URL: $Url" }
  if($TargetPath){ Write-Info "[WinLab] Archivo: $TargetPath" }
  Write-Info "[WinLab] Carpeta de salida: $outboxHost"
  Write-Info "[WinLab] Archivo WSB: $wsbFile"

  Start-Process -FilePath $wsbExe -ArgumentList "`"$wsbFile`"" | Out-Null
  if($OpenOutbox){ Start-Process explorer.exe -ArgumentList "`"$outboxHost`"" | Out-Null }
}

function Show-Help {
  @'
WinLab (terminal)

Esto no es un antivirus propio: usa Microsoft Defender dentro de Windows Sandbox.
WinLab aporta aislamiento, un flujo repetible y reportes claros.

Uso:
  ./WinLab.ps1 scan    -Path <archivo>   [-Preset Balanced|UltraSecure] [-Minutes N] [-OpenOutbox]
  ./WinLab.ps1 url     -Url  <link>      [-Preset Networked|Balanced]   [-Minutes N] [-OpenOutbox]
  ./WinLab.ps1 session -Url  <link>      (alias de url)
  ./WinLab.ps1 scan-file    (alias de scan)
  ./WinLab.ps1 analyze-url  (alias de url)
  ./WinLab.ps1 version
  ./WinLab.ps1 doctor

Ejemplos:
  ./WinLab.ps1 scan -Path "$env:USERPROFILE\Downloads\factura.exe" -Preset UltraSecure -OpenOutbox
  ./WinLab.ps1 url  -Url "https://ejemplo.com" -Preset Networked -OpenOutbox
'
@ | Write-Host
}

if($Command -eq 'help'){ Show-Help; exit 0 }
if($Command -eq 'version'){
  Write-Host ("WinLab " + (Get-WinLabVersion))
  exit 0
}
if($Command -eq 'doctor'){
  Run-Doctor
  exit 0
}

Resolve-Defaults

$commandNorm = $Command
if($Command -eq 'scan-file'){ $commandNorm = 'scan' }
if($Command -eq 'analyze-url'){ $commandNorm = 'url' }

switch($commandNorm){
  'scan' {
    if(-not $Path){
      Write-Warn 'No especificaste -Path. Se va a usar el archivo mas reciente de Descargas (host).'
      Start-WinLabSandbox -Preset $Preset -Minutes $Minutes -Url '' -TargetPath ''
      exit 0
    }
    Start-WinLabSandbox -Preset $Preset -Minutes $Minutes -Url '' -TargetPath $Path
    exit 0
  }
  'url' {
    if(-not $Url){ throw 'Falta -Url.' }
    Start-WinLabSandbox -Preset $Preset -Minutes $Minutes -Url $Url -TargetPath ''
    exit 0
  }
  'session' {
    if(-not $Url){ throw 'Falta -Url.' }
    Start-WinLabSandbox -Preset $Preset -Minutes $Minutes -Url $Url -TargetPath ''
    exit 0
  }
  default {
    Show-Help
    exit 1
  }
}
