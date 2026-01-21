[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$versionFile = Join-Path $root 'tools\cli\version.txt'
$current = (Get-Content -Raw -Path $versionFile).Trim()
$logDir = 'C:\WinLab\logs'
try{ New-Item -ItemType Directory -Force -Path $logDir | Out-Null } catch {}
$logFile = Join-Path $logDir 'update.log'
function Log([string]$m){
  $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
  $line = "[$ts] $m"
  Add-Content -LiteralPath $logFile -Value $line
  Write-Host $line
}

Log "Versión actual: $current"
$url = 'https://api.github.com/repos/marcoluna-nqn/winlab-demo/releases/latest'
$headers = @{ 'User-Agent' = 'WinLab-Updater' }
$resp = Invoke-RestMethod -Uri $url -Headers $headers -ErrorAction Stop
$tag = $resp.tag_name
if($tag -match '^v'){ $tag = $tag.Substring(1) }
$remote = if($tag){ $tag } else { $resp.name }
if(-not $remote){ throw "No pude obtener versión remota" }

Log "Versión remota: $remote"
if([version]$remote -le [version]$current){
  Log 'Ya estás en la última versión.'
  exit 0
}

$asset = $resp.assets | Where-Object { $_.name -like "WinLab_Installer_${remote}.exe" } | Select-Object -First 1
if(-not $asset){
  $asset = $resp.assets | Where-Object { $_.name -like "WinLab_ProductPack_${remote}.zip" } | Select-Object -First 1
}
if(-not $asset){ throw "No encontré un artefacto compatible en GitHub." }

$destDir = Join-Path $env:USERPROFILE 'Downloads'
try{ New-Item -ItemType Directory -Force -Path $destDir | Out-Null } catch {}
$dest = Join-Path $destDir $asset.name

Log "Descargando $($asset.name) a $dest"
Invoke-WebRequest -Uri $asset.browser_download_url -Headers $headers -OutFile $dest -UseBasicParsing
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $dest).Hash.ToLowerInvariant()
Log "SHA256: $hash"
Log 'Descarga lista. Abrí el archivo para actualizar.'
Start-Process $dest
