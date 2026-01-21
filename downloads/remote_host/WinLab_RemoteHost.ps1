[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Write-Log([string]$message){
  $logRoot = 'C:\WinLab\logs'
  try{ New-Item -ItemType Directory -Force -Path $logRoot | Out-Null } catch {}
  $path = Join-Path $logRoot 'remote_host.log'
  $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  $line = "[$ts] $message"
  try{ Add-Content -LiteralPath $path -Value $line } catch {}
}

function Read-Config {
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

function Write-JsonResponse($context, [int]$status, [object]$payload){
  $context.Response.StatusCode = $status
  $context.Response.ContentType = 'application/json; charset=utf-8'
  $json = $payload | ConvertTo-Json -Depth 6
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
  $context.Response.ContentLength64 = $bytes.Length
  $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
  $context.Response.OutputStream.Close()
}

function Read-RequestBody($context){
  $reader = New-Object System.IO.StreamReader($context.Request.InputStream, $context.Request.ContentEncoding)
  try{ return $reader.ReadToEnd() } finally { $reader.Dispose() }
}

function Safe-FileName([string]$name){
  if([string]::IsNullOrWhiteSpace($name)){
    return 'archivo.bin'
  }
  $base = [System.IO.Path]::GetFileName($name)
  $safe = $base -replace '[^a-zA-Z0-9._-]', '_'
  if($safe.Length -lt 3){ $safe = 'archivo.bin' }
  return $safe
}

function Find-Launcher {
  $candidates = @(
    'C:\Program Files\WinLab\downloads\launcher\WinLab_Launcher.cmd',
    'C:\WinLab_Pack\downloads\launcher\WinLab_Launcher.cmd'
  )
  foreach($c in $candidates){ if(Test-Path $c){ return $c } }
  return $null
}

function Wait-ForReport([datetime]$since, [int]$timeoutMinutes){
  $outbox = 'C:\WinLab_Outbox'
  $deadline = $since.AddMinutes([math]::Max(1,$timeoutMinutes))
  while((Get-Date) -lt $deadline){
    $latest = Get-ChildItem -Path $outbox -Filter report.json -Recurse -ErrorAction SilentlyContinue |
      Where-Object { $_.LastWriteTime -ge $since } |
      Sort-Object LastWriteTime -Descending |
      Select-Object -First 1
    if($latest){ return $latest.FullName }
    Start-Sleep -Seconds 3
  }
  return $null
}

function Get-ClientIp($context){
  try{ return $context.Request.RemoteEndPoint.Address.ToString() } catch { return 'unknown' }
}

$cfg = Read-Config
if(-not $cfg){
  Write-Log 'Config no encontrada. Crear config.json en ProgramData o usar remote_host_config.json.'
  exit 2
}
if([string]::IsNullOrWhiteSpace($cfg.apiKey)){
  Write-Log 'API key vacia. Configura apiKey en config.json.'
  exit 3
}

$bind = if($cfg.bindAddress){ $cfg.bindAddress } else { '127.0.0.1' }
$port = if($cfg.port){ [int]$cfg.port } else { 17171 }
$maxUploadBytes = [int]($cfg.maxUploadMb * 1MB)
$timeoutMinutes = if($cfg.timeoutMinutes){ [int]$cfg.timeoutMinutes } else { 20 }
$allowed = @()
if($cfg.allowedExtensions){ $allowed = @($cfg.allowedExtensions) }

$listener = New-Object System.Net.HttpListener
$prefix = "http://$bind:$port/"
$listener.Prefixes.Add($prefix)
$listener.Start()
Write-Log "WinLab Remote Host activo en $prefix"

$rateWindow = 60
$rateLimit = 6
$rateMap = @{}
$busy = $false

while($listener.IsListening){
  $context = $listener.GetContext()
  try{
    $ip = Get-ClientIp $context
    $now = Get-Date
    if(-not $rateMap.ContainsKey($ip)){ $rateMap[$ip] = @() }
    $rateMap[$ip] = $rateMap[$ip] | Where-Object { $_ -ge $now.AddSeconds(-$rateWindow) }
    if($rateMap[$ip].Count -ge $rateLimit){
      Write-JsonResponse $context 429 @{ ok = $false; message = 'Limite de requests por minuto.' }
      continue
    }
    $rateMap[$ip] += $now

    $apiKey = $context.Request.Headers['X-WINLAB-KEY']
    if([string]::IsNullOrWhiteSpace($apiKey) -or $apiKey -ne $cfg.apiKey){
      Write-JsonResponse $context 401 @{ ok = $false; message = 'API key invalida.' }
      continue
    }

    $path = $context.Request.Url.AbsolutePath.ToLowerInvariant()
    $method = $context.Request.HttpMethod.ToUpperInvariant()

    if($path -eq '/status' -and $method -eq 'GET'){
      Write-JsonResponse $context 200 @{ ok = $true; busy = $busy; time = (Get-Date).ToString('o') }
      continue
    }

    if($busy){
      Write-JsonResponse $context 409 @{ ok = $false; message = 'Host ocupado. Reintenta en unos minutos.' }
      continue
    }

    if($path -eq '/api/scan-url' -and $method -eq 'POST'){
      $raw = Read-RequestBody $context
      $body = $null
      try{ $body = $raw | ConvertFrom-Json } catch {}
      if(-not $body -or -not $body.url){
        Write-JsonResponse $context 400 @{ ok = $false; message = 'Falta url en el body.' }
        continue
      }
      $url = $body.url.ToString().Trim()
      if(-not ($url -match '^https?://')){
        Write-JsonResponse $context 400 @{ ok = $false; message = 'La URL debe ser http o https.' }
        continue
      }

      $launcher = Find-Launcher
      if(-not $launcher){
        Write-JsonResponse $context 500 @{ ok = $false; message = 'Launcher WinLab no encontrado.' }
        continue
      }

      $busy = $true
      $start = Get-Date
      Write-Log "Scan URL solicitado: $url"
      Start-Process -FilePath $launcher -ArgumentList @('Networked', $url) -WindowStyle Hidden | Out-Null

      $reportPath = Wait-ForReport -since $start -timeoutMinutes $timeoutMinutes
      if(-not $reportPath){
        $busy = $false
        Write-JsonResponse $context 504 @{ ok = $false; message = 'Timeout esperando reporte.' }
        continue
      }

      $report = Get-Content -Raw -Path $reportPath | ConvertFrom-Json
      $runDir = Split-Path -Parent $reportPath
      $busy = $false
      Write-JsonResponse $context 200 @{
        ok = $true
        jobId = (Get-Date -Format 'yyyyMMdd_HHmmss')
        status = $report.summary.status
        decision = $report.summary.finalDecision
        risk = $report.summary.riskLevel
        recommendation = $report.summary.recommendation
        reportJson = $reportPath
        reportHtml = (Join-Path $runDir 'report.html')
      }
      continue
    }

    if($path -eq '/api/scan-file' -and $method -eq 'POST'){
      $raw = Read-RequestBody $context
      $body = $null
      try{ $body = $raw | ConvertFrom-Json } catch {}
      if(-not $body -or -not $body.fileName -or -not $body.contentBase64){
        Write-JsonResponse $context 400 @{ ok = $false; message = 'Falta fileName o contentBase64.' }
        continue
      }

      $safeName = Safe-FileName $body.fileName
      $ext = [System.IO.Path]::GetExtension($safeName).ToLowerInvariant()
      if($allowed.Count -gt 0 -and ($allowed -notcontains $ext)){
        Write-JsonResponse $context 415 @{ ok = $false; message = 'Extension no permitida.' }
        continue
      }

      $bytes = $null
      try{ $bytes = [System.Convert]::FromBase64String($body.contentBase64) } catch {}
      if(-not $bytes){
        Write-JsonResponse $context 400 @{ ok = $false; message = 'Base64 invalido.' }
        continue
      }
      if($bytes.Length -gt $maxUploadBytes){
        Write-JsonResponse $context 413 @{ ok = $false; message = 'Archivo demasiado grande.' }
        continue
      }

      $inbox = 'C:\WinLab_Inbox'
      try{ New-Item -ItemType Directory -Force -Path $inbox | Out-Null } catch {}
      $dest = Join-Path $inbox ("host_" + (Get-Date -Format 'yyyyMMdd_HHmmss') + "_" + $safeName)
      [System.IO.File]::WriteAllBytes($dest, $bytes)

      $launcher = Find-Launcher
      if(-not $launcher){
        Write-JsonResponse $context 500 @{ ok = $false; message = 'Launcher WinLab no encontrado.' }
        continue
      }

      $busy = $true
      $start = Get-Date
      Write-Log "Scan archivo solicitado: $dest"
      Start-Process -FilePath $launcher -ArgumentList @('Balanced', $dest) -WindowStyle Hidden | Out-Null

      $reportPath = Wait-ForReport -since $start -timeoutMinutes $timeoutMinutes
      if(-not $reportPath){
        $busy = $false
        Write-JsonResponse $context 504 @{ ok = $false; message = 'Timeout esperando reporte.' }
        continue
      }

      $report = Get-Content -Raw -Path $reportPath | ConvertFrom-Json
      $runDir = Split-Path -Parent $reportPath
      $busy = $false
      Write-JsonResponse $context 200 @{
        ok = $true
        jobId = (Get-Date -Format 'yyyyMMdd_HHmmss')
        status = $report.summary.status
        decision = $report.summary.finalDecision
        risk = $report.summary.riskLevel
        recommendation = $report.summary.recommendation
        reportJson = $reportPath
        reportHtml = (Join-Path $runDir 'report.html')
      }
      continue
    }

    Write-JsonResponse $context 404 @{ ok = $false; message = 'Ruta no encontrada.' }
  } catch {
    Write-Log ("Error: " + $_.Exception.Message)
    try{ Write-JsonResponse $context 500 @{ ok = $false; message = 'Error interno.' } } catch {}
  }
}
