[CmdletBinding()]
param(
  [Parameter(Position=0)]
  [ValidateSet('scan','scan-file','url','analyze-url','session','help','version')]
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

function Write-Info([string]$m){ Write-Host $m }
function Write-Warn([string]$m){ Write-Host $m -ForegroundColor Yellow }
function Write-Err([string]$m){ Write-Host $m -ForegroundColor Red }

function Get-NowStamp { Get-Date -Format 'yyyyMMdd_HHmmss' }

function Ensure-SandboxAvailable {
  $wsbExe = Join-Path $env:SystemRoot 'System32\WindowsSandbox.exe'
  if(-not (Test-Path $wsbExe)){
    throw "Windows Sandbox no esta disponible (WindowsSandbox.exe no existe). Requiere Windows 10/11 Pro/Enterprise/Education + feature habilitado."
  }

  $stateLine = (dism /online /English /Get-FeatureInfo /FeatureName:Containers-DisposableClientVM | Select-String -Pattern '^State' -ErrorAction SilentlyContinue | Select-Object -First 1).Line
  if(-not $stateLine){
    throw 'No pude consultar el estado del feature (DISM). Ejecuta como Administrador o verifica DISM/Windows Update.'
  }
  if($stateLine -notmatch 'Enabled'){
    throw "Windows Sandbox feature no esta Enabled ($stateLine). Habilitalo con: Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All"
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
  $logs = Join-Path $labHome 'logs'
  New-Item -ItemType Directory -Force -Path $outboxHost | Out-Null
  New-Item -ItemType Directory -Force -Path $logs | Out-Null

  $stamp = Get-NowStamp
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
    Start-Process -WindowStyle Minimized -FilePath 'cmd.exe' -ArgumentList "/c \"`"$watchdog`" `"$outboxHost`" $Minutes $stamp > `"$logs\watchdog_$stamp.log`" 2>&1\"" | Out-Null
  }

  $logonCmd = @(
    'powershell.exe -NoProfile -ExecutionPolicy Bypass',
    '-File "C:\WinLabPkg\bin\InsideLab.ps1"',
    "-Preset $Preset",
    '-InputFolder "C:\WinLabInboxRO"',
    '-OutFolder "C:\Outbox"',
    "-Minutes $Minutes",
    "-FirewallMode $firewall",
    '-EnableOutbox 1'
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
  $xml += '  </MappedFolders>'
  $xml += '  <LogonCommand>'
  $xml += "    <Command>$logonCmd</Command>"
  $xml += '  </LogonCommand>'
  $xml += '</Configuration>'

  $xml -join "`r`n" | Set-Content -LiteralPath $wsbFile -Encoding UTF8

  Write-Info "[WinLab] Preset=$Preset Minutes=$Minutes"
  if($Url){ Write-Info "[WinLab] URL: $Url" }
  if($TargetPath){ Write-Info "[WinLab] Target: $TargetPath" }
  Write-Info "[WinLab] Outbox: $outboxHost"
  Write-Info "[WinLab] WSB: $wsbFile"

  Start-Process -FilePath $wsbExe -ArgumentList "`"$wsbFile`"" | Out-Null
  if($OpenOutbox){ Start-Process explorer.exe -ArgumentList "`"$outboxHost`"" | Out-Null }
}

function Show-Help {
  @'
WinLab (terminal)

Este software NO es un antivirus propio: usa Microsoft Defender dentro de Windows Sandbox.
WinLab aporta aislamiento + pipeline + reporte.

Uso:
  ./WinLab.ps1 scan    -Path <archivo>   [-Preset Balanced|UltraSecure] [-Minutes N] [-OpenOutbox]
  ./WinLab.ps1 url     -Url  <link>      [-Preset Networked|Balanced]   [-Minutes N] [-OpenOutbox]
  ./WinLab.ps1 session -Url  <link>      (alias de url)
  ./WinLab.ps1 scan-file    (alias de scan)
  ./WinLab.ps1 analyze-url  (alias de url)
  ./WinLab.ps1 version

Ejemplos:
  ./WinLab.ps1 scan -Path "$env:USERPROFILE\Downloads\factura.exe" -Preset UltraSecure -OpenOutbox
  ./WinLab.ps1 url  -Url "https://sitio.ejemplo" -Preset Networked -OpenOutbox
'
@ | Write-Host
}

if($Command -eq 'help'){ Show-Help; exit 0 }
if($Command -eq 'version'){
  $v = '0.8.0'
  try{
    $p = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'version.txt'
    if(Test-Path $p){ $v = (Get-Content -LiteralPath $p -ErrorAction SilentlyContinue | Select-Object -First 1) }
  } catch {}
  Write-Host "WinLab $v"
  exit 0
}

Resolve-Defaults

$commandNorm = $Command
if($Command -eq 'scan-file'){ $commandNorm = 'scan' }
if($Command -eq 'analyze-url'){ $commandNorm = 'url' }

switch($commandNorm){
  'scan' {
    if(-not $Path){
      Write-Warn 'No especificaste -Path. Se usara el archivo mas reciente de Descargas (host).'
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
