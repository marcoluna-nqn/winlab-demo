[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Get-EditionInfo {
  $edition = ''
  $product = ''
  try{
    $edition = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction SilentlyContinue).EditionID
    $product = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName -ErrorAction SilentlyContinue).ProductName
  } catch {}
  if(-not $edition){ $edition = 'DESCONOCIDO' }
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

function Read-RemoteConfig {
  $configDir = Join-Path $env:ProgramData 'WinLab\remote_host'
  $configFile = Join-Path $configDir 'config.json'
  if(Test-Path $configFile){
    return Get-Content -Raw -Path $configFile | ConvertFrom-Json
  }
  $localFile = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'remote_host_config.json'
  if(Test-Path $localFile){
    return Get-Content -Raw -Path $localFile | ConvertFrom-Json
  }
  return $null
}

function Find-Launcher {
  $candidates = @(
    'C:\Program Files\WinLab\downloads\launcher\WinLab_Launcher.cmd',
    'C:\WinLab_Pack\downloads\launcher\WinLab_Launcher.cmd'
  )
  foreach($c in $candidates){ if(Test-Path $c){ return $c } }
  return $null
}

$logRoot = 'C:\WinLab\logs'
$reportPath = Join-Path $logRoot 'remote_host_doctor.txt'
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add('WinLab Host Remoto - Doctor')
$lines.Add("Fecha: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")

$issues = New-Object System.Collections.Generic.List[string]

$ed = Get-EditionInfo
$lines.Add("Windows: $($ed.Product) (EditionID=$($ed.Edition))")
$supported = $true
if($ed.Edition -match 'Core' -or $ed.Product -match 'Home'){ $supported = $false }
$lines.Add("Edicion compatible: $supported")
if(-not $supported){ $issues.Add('Requiere Windows Pro/Enterprise/Education.') }

$wsbExe = Join-Path $env:SystemRoot 'System32\WindowsSandbox.exe'
$wsbExists = Test-Path $wsbExe
$lines.Add("WindowsSandbox.exe: $wsbExists")
if(-not $wsbExists){ $issues.Add('WindowsSandbox.exe no existe.') }

$featureLine = Get-FeatureState
$featureEnabled = $false
if($featureLine -and $featureLine -match 'Enabled'){ $featureEnabled = $true }
$lines.Add("Funcion Containers-DisposableClientVM: " + ($(if($featureEnabled){ 'Habilitada' } else { 'No habilitada' })))
if(-not $featureEnabled){ $issues.Add('Funcion Containers-DisposableClientVM no esta habilitada.') }

$virtEnabled = $null
try{
  $cpu = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
  if($cpu){ $virtEnabled = $cpu.VirtualizationFirmwareEnabled }
} catch {}
$lines.Add("Virtualizacion firmware: $virtEnabled")
if($virtEnabled -ne $true){ $issues.Add('Virtualizacion en BIOS/UEFI no detectada como habilitada.') }

$rdpEnabled = $null
try{
  $rdpValue = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction SilentlyContinue).fDenyTSConnections
  if($rdpValue -ne $null){ $rdpEnabled = ($rdpValue -eq 0) }
} catch {}
$lines.Add("RDP habilitado: $rdpEnabled (no abrir puertos a Internet)")

$tailscale = $false
$tsCandidates = @(
  Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe',
  Join-Path ${env:ProgramFiles(x86)} 'Tailscale\tailscale.exe'
)
foreach($c in $tsCandidates){ if($c -and (Test-Path $c)){ $tailscale = $true } }
$lines.Add("Tailscale detectado: $tailscale")

$launcher = Find-Launcher
$lines.Add("Lanzador WinLab: $launcher")
if(-not $launcher){ $issues.Add('Lanzador WinLab no encontrado.') }

$cfg = Read-RemoteConfig
if($cfg){
  $lines.Add("Config remota: OK")
  $lines.Add("Bind: $($cfg.direccionBind) / Puerto: $($cfg.puerto)")
  if([string]::IsNullOrWhiteSpace($cfg.claveApi)){ $issues.Add('claveApi vacia en config.json.') }
} else {
  $lines.Add("Config remota: no encontrada")
  $issues.Add('Config remota no encontrada.')
}

$svc = Get-Service -Name 'WinLabRemoteHost' -ErrorAction SilentlyContinue
if($svc){
  $lines.Add("Servicio WinLabRemoteHost: $($svc.Status)")
} else {
  $lines.Add("Servicio WinLabRemoteHost: no instalado")
}

$dirs = @('C:\WinLab\logs','C:\WinLab_Inbox','C:\WinLab_Outbox')
foreach($d in $dirs){
  $ok = Test-Path $d
  $lines.Add("Carpeta $d: $ok")
}

if($svc -and $svc.Status -eq 'Running' -and $cfg){
  try{
    $headers = @{ 'X-WINLAB-KEY' = $cfg.claveApi }
    $bind = if($cfg.direccionBind){ $cfg.direccionBind } else { '127.0.0.1' }
    $port = if($cfg.puerto){ [int]$cfg.puerto } else { 17171 }
    $uri = "http://$bind:$port/estado"
    $resp = Invoke-WebRequest -UseBasicParsing -Headers $headers -Uri $uri -TimeoutSec 3
    $lines.Add("Estado HTTP: $($resp.StatusCode)")
  } catch {
    $lines.Add('Estado HTTP: fallo al conectar')
    $issues.Add('No se pudo consultar /estado del servicio remoto.')
  }
}

try{
  New-Item -ItemType Directory -Force -Path $logRoot | Out-Null
  $lines | Set-Content -LiteralPath $reportPath -Encoding ASCII
  $lines.Add("Reporte: $reportPath")
} catch {
  $fallback = Join-Path $env:TEMP 'remote_host_doctor.txt'
  $lines | Set-Content -LiteralPath $fallback -Encoding ASCII
  $lines.Add("Reporte: $fallback")
}

Write-Host ($lines -join "`n")

if($issues.Count -gt 0){
  Write-Host "\nProblemas detectados:" -ForegroundColor Yellow
  foreach($i in $issues){ Write-Host ("- " + $i) -ForegroundColor Yellow }
  exit 2
}

Write-Host "\nDiagnostico OK. Host listo para uso remoto." -ForegroundColor Green
exit 0
