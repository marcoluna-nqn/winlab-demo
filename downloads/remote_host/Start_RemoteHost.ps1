param()

$ErrorActionPreference = 'Stop'

$serviceName = 'WinLabRemoteHost'
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if(-not $svc){
  Write-Host 'Servicio WinLabRemoteHost no encontrado. Ejecuta Install_RemoteHost.ps1.'
  exit 2
}
if($svc.Status -ne 'Running'){
  Start-Service -Name $serviceName
}
Write-Host 'WinLab Remote Host iniciado.'
