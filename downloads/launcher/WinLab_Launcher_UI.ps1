[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Split-Path -Parent (Split-Path -Parent $scriptDir)
$launcherCmd = Join-Path $scriptDir 'WinLab_Launcher.cmd'
$updateScript = Join-Path $root 'tools\cli\WinLab_Update.ps1'
$doctorCmd = Join-Path $root 'tools\cli\WinLab.cmd'
$logsDir = 'C:\WinLab\logs'
$outbox = 'C:\WinLab_Outbox'
$licensePath = Join-Path $env:ProgramData 'WinLab\license.json'
$licenseSample = Join-Path $root 'downloads\license.sample.json'

function Compute-LicenseSignature([pscustomobject]$license){
  $secret = 'WINLAB2026_CLAVE'
  $payload = ($license.cliente + '|' + $license.plan + '|' + $license.validoHasta + '|' + $license.dispositivo)
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload + '|' + $secret)
  $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
  return ([System.BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
}

function Get-LicenseStatus {
  $paths = @($licensePath, $licenseSample)
  foreach($p in $paths){
    if(Test-Path $p){
      try{
        $json = Get-Content -Raw -Path $p | ConvertFrom-Json
        if($null -eq $json){ continue }
        $sig = Compute-LicenseSignature $json
        $validSig = ($json.firma -eq $sig)
        $expiry = Get-Date $json.validoHasta
        $expired = ($expiry -lt (Get-Date))
        return [pscustomobject]@{
          Ruta = $p
          Cliente = $json.cliente
          Plan = $json.plan
          Expira = $expiry
          FirmaOk = $validSig
          Expirada = $expired
        }
      } catch {}
    }
  }
  return $null
}

function Launch-Cmd([string]$preset, [string]$target){
  if(-not (Test-Path $launcherCmd)){ [System.Windows.Forms.MessageBox]::Show('No se encontró WinLab_Launcher.cmd','WinLab',0,[System.Windows.Forms.MessageBoxIcon]::Error); return }
  $args = @($preset)
  if($target){ $args += $target }
  Start-Process -FilePath $launcherCmd -ArgumentList $args -WindowStyle Hidden
}

function Open-LastReport {
  if(-not (Test-Path $outbox)){ [System.Windows.Forms.MessageBox]::Show('Todavía no hay reportes.','WinLab'); return }
  $latest = Get-ChildItem -Path $outbox -Filter report.html -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if($latest){ Start-Process $latest.FullName } else { [System.Windows.Forms.MessageBox]::Show('No se encontró un reporte reciente.','WinLab') }
}

function Ensure-Logs { if(-not (Test-Path $logsDir)){ New-Item -ItemType Directory -Force -Path $logsDir | Out-Null } }

# --- UI ---
$form = New-Object System.Windows.Forms.Form
$form.Text = 'WinLab - Lanzador'
$form.Size = New-Object System.Drawing.Size(540,520)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false

$lblPreset = New-Object System.Windows.Forms.Label
$lblPreset.Text = 'Perfil'
$lblPreset.Location = New-Object System.Drawing.Point(20,20)
$lblPreset.AutoSize = $true
$form.Controls.Add($lblPreset)

$presetCombo = New-Object System.Windows.Forms.ComboBox
$presetCombo.Location = New-Object System.Drawing.Point(20,45)
$presetCombo.Size = New-Object System.Drawing.Size(200,24)
$presetCombo.DropDownStyle = 'DropDownList'
$presetCombo.Items.AddRange(@('Equilibrado','Ultra seguro','Con red'))
$presetCombo.SelectedIndex = 0
$form.Controls.Add($presetCombo)

$lblFile = New-Object System.Windows.Forms.Label
$lblFile.Text = 'Archivo a analizar'
$lblFile.Location = New-Object System.Drawing.Point(20,80)
$lblFile.AutoSize = $true
$form.Controls.Add($lblFile)

$txtFile = New-Object System.Windows.Forms.TextBox
$txtFile.Location = New-Object System.Drawing.Point(20,105)
$txtFile.Size = New-Object System.Drawing.Size(360,24)
$form.Controls.Add($txtFile)

$btnBrowse = New-Object System.Windows.Forms.Button
$btnBrowse.Text = 'Elegir archivo'
$btnBrowse.Location = New-Object System.Drawing.Point(390,103)
$btnBrowse.Size = New-Object System.Drawing.Size(110,28)
$btnBrowse.Add_Click({
  $dlg = New-Object System.Windows.Forms.OpenFileDialog
  if($dlg.ShowDialog() -eq 'OK'){ $txtFile.Text = $dlg.FileName }
})
$form.Controls.Add($btnBrowse)

$btnFile = New-Object System.Windows.Forms.Button
$btnFile.Text = 'Analizar archivo'
$btnFile.Location = New-Object System.Drawing.Point(20,140)
$btnFile.Size = New-Object System.Drawing.Size(160,32)
$btnFile.Add_Click({
  if([string]::IsNullOrWhiteSpace($txtFile.Text) -or -not (Test-Path $txtFile.Text)){
    [System.Windows.Forms.MessageBox]::Show('Elegí un archivo válido.','WinLab')
    return
  }
  $preset = switch($presetCombo.SelectedIndex){0{'Balanced'}1{'UltraSecure'}2{'Networked'}}
  Launch-Cmd $preset $txtFile.Text
})
$form.Controls.Add($btnFile)

$lblUrl = New-Object System.Windows.Forms.Label
$lblUrl.Text = 'URL a analizar'
$lblUrl.Location = New-Object System.Drawing.Point(20,185)
$lblUrl.AutoSize = $true
$form.Controls.Add($lblUrl)

$txtUrl = New-Object System.Windows.Forms.TextBox
$txtUrl.Location = New-Object System.Drawing.Point(20,210)
$txtUrl.Size = New-Object System.Drawing.Size(360,24)
$form.Controls.Add($txtUrl)

$btnUrl = New-Object System.Windows.Forms.Button
$btnUrl.Text = 'Analizar URL'
$btnUrl.Location = New-Object System.Drawing.Point(390,208)
$btnUrl.Size = New-Object System.Drawing.Size(110,28)
$btnUrl.Add_Click({
  $u = $txtUrl.Text.Trim()
  if(-not $u.StartsWith('http')){
    [System.Windows.Forms.MessageBox]::Show('Ingresá una URL completa (http/https).','WinLab')
    return
  }
  Launch-Cmd 'Networked' $u
})
$form.Controls.Add($btnUrl)

$btnReport = New-Object System.Windows.Forms.Button
$btnReport.Text = 'Abrir último reporte'
$btnReport.Location = New-Object System.Drawing.Point(20,250)
$btnReport.Size = New-Object System.Drawing.Size(160,32)
$btnReport.Add_Click({ Open-LastReport })
$form.Controls.Add($btnReport)

$btnLogs = New-Object System.Windows.Forms.Button
$btnLogs.Text = 'Abrir logs'
$btnLogs.Location = New-Object System.Drawing.Point(200,250)
$btnLogs.Size = New-Object System.Drawing.Size(120,32)
$btnLogs.Add_Click({ Ensure-Logs; Start-Process $logsDir })
$form.Controls.Add($btnLogs)

$btnDoctor = New-Object System.Windows.Forms.Button
$btnDoctor.Text = 'Doctor'
$btnDoctor.Location = New-Object System.Drawing.Point(340,250)
$btnDoctor.Size = New-Object System.Drawing.Size(70,32)
$btnDoctor.Add_Click({
  Start-Process -FilePath $doctorCmd -ArgumentList 'doctor' -WindowStyle Hidden
})
$form.Controls.Add($btnDoctor)

$btnUpdate = New-Object System.Windows.Forms.Button
$btnUpdate.Text = 'Buscar actualización'
$btnUpdate.Location = New-Object System.Drawing.Point(20,290)
$btnUpdate.Size = New-Object System.Drawing.Size(200,32)
$btnUpdate.Add_Click({
  if(Test-Path $updateScript){
    Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$updateScript`""
  } else {
    [System.Windows.Forms.MessageBox]::Show('No se encontró WinLab_Update.ps1','WinLab')
  }
})
$form.Controls.Add($btnUpdate)

$btnLicense = New-Object System.Windows.Forms.Button
$btnLicense.Text = 'Licencia / Activar'
$btnLicense.Location = New-Object System.Drawing.Point(240,290)
$btnLicense.Size = New-Object System.Drawing.Size(180,32)
$btnLicense.Add_Click({
  Ensure-Logs
  $msg = "Guardá la licencia en $licensePath.`nConsultá por WhatsApp para activarla."
  Start-Process "https://wa.me/5492996209136?text=Quiero%20activar%20mi%20licencia%20WinLab"
  [System.Windows.Forms.MessageBox]::Show($msg,'WinLab')
})
$form.Controls.Add($btnLicense)

$lblLic = New-Object System.Windows.Forms.Label
$lblLic.Text = 'Licencia: verificando'
$lblLic.Location = New-Object System.Drawing.Point(20,335)
$lblLic.Size = New-Object System.Drawing.Size(480,30)
$form.Controls.Add($lblLic)

$btnClose = New-Object System.Windows.Forms.Button
$btnClose.Text = 'Salir'
$btnClose.Location = New-Object System.Drawing.Point(390,420)
$btnClose.Size = New-Object System.Drawing.Size(110,32)
$btnClose.Add_Click({ $form.Close() })
$form.Controls.Add($btnClose)

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 2000
$timer.Add_Tick({
  $lic = Get-LicenseStatus
  if($lic){
    $state = if($lic.FirmaOk -and -not $lic.Expirada){ 'Activa' } elseif(-not $lic.FirmaOk){ 'Firma invalida' } else { 'Vencida' }
    $lblLic.Text = "Licencia: $state ($($lic.Plan)) - vence $($lic.Expira.ToString('yyyy-MM-dd'))"
  } else {
    $lblLic.Text = 'Licencia: no encontrada. Guardá license.json en ProgramData.'
  }
})
$first = Get-LicenseStatus
if($first){
  $state = if($first.FirmaOk -and -not $first.Expirada){ 'Activa' } elseif(-not $first.FirmaOk){ 'Firma invalida' } else { 'Vencida' }
  $lblLic.Text = "Licencia: $state ($($first.Plan)) - vence $($first.Expira.ToString('yyyy-MM-dd'))"
} else {
  $lblLic.Text = 'Licencia: no encontrada. Guardá license.json en ProgramData.'
}
$timer.Start()

[void]$form.ShowDialog()
