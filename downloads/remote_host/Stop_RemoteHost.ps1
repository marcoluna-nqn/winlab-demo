param()

$ErrorActionPreference = 'Stop'

$serviceName = 'WinLabRemoteHost'
$svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if(-not $svc){
  Write-Host 'Servicio WinLabRemoteHost no encontrado.'
  exit 2
}
if($svc.Status -ne 'Stopped'){
  Stop-Service -Name $serviceName -Force
}
Write-Host 'WinLab Host Remoto detenido.'
