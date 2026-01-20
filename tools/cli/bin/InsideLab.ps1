[CmdletBinding()]
param(
  [Parameter(Mandatory=$false)]
  [string]$Preset = 'Balanced',

  # Host-mapped inbox (ReadOnly). Default matches Run-WinLab.cmd mapping.
  [Parameter(Mandatory=$false)]
  [string]$InputFolder = 'C:\WinLabInboxRO',

  # Report output. When Outbox is mapped, points to C:\Outbox.
  [Parameter(Mandatory=$false)]
  [string]$OutFolder = 'C:\Outbox',

  # Session duration (minutes). Sandbox will self-close after this.
  [Parameter(Mandatory=$false)]
  [int]$Minutes = 10,

  # Network hardening inside Sandbox (best-effort).
  [ValidateSet('BlockAll','InternetOnly','AllowMost')]
  [string]$FirewallMode = 'InternetOnly',

  # If 1, write reports to OutFolder (mapped to host). If 0, write locally in Sandbox.
  [Parameter(Mandatory=$false)]
  [int]$EnableOutbox = 1,

  # Optional URL to open in Edge (in-private) inside Sandbox.
  [Parameter(Mandatory=$false)]
  [string]$Url = '',

  # Optional: scan a specific filename from InputFolder instead of "latest".
  [Parameter(Mandatory=$false)]
  [string]$TargetFileName = '',

  # If 1, compute a risk score and produce an "autoDecision" section.
  [Parameter(Mandatory=$false)]
  [int]$AutoDecisionEnabled = 1,

  # If 1, collect process/network deltas (best-effort).
  [Parameter(Mandatory=$false)]
  [int]$CollectDeltas = 1
)

$ErrorActionPreference = 'Stop'

# =====================
# Helpers
# =====================
function NowStamp { Get-Date -Format "yyyyMMdd_HHmmss" }
function SafeFileName([string]$s){
  if([string]::IsNullOrWhiteSpace($s)){ return '' }
  return ($s -replace "[^A-Za-z0-9_.-]","_")
}
function Log([string]$m){
  try{ Write-Host ("[WinLab] " + $m) } catch {}
}
function HtmlE([string]$s){
  if($null -eq $s){ return '' }
  return ($s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;'))
}

function Ensure-Dir([string]$p){
  New-Item -ItemType Directory -Force -Path $p | Out-Null
}

function Ensure-OutDir([int]$enable, [string]$outFolder){
  if($enable -eq 1){
    Ensure-Dir $outFolder
    return $outFolder
  }
  $local = 'C:\WinLabReports'
  Ensure-Dir $local
  return $local
}

function Apply-Firewall([string]$mode){
  try{
    Log "Firewall mode: $mode"

    # Clean our old rules to avoid accumulation
    Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'WinLab-*' } | Remove-NetFirewallRule -ErrorAction SilentlyContinue

    if($mode -eq 'BlockAll'){
      Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
      Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block -DefaultInboundAction Block
      return
    }

    if($mode -eq 'InternetOnly'){
      # Allow only core web browsing + DNS + WHOIS (43) + NTP. Everything else is blocked.
      Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
      Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block -DefaultInboundAction Block

      New-NetFirewallRule -DisplayName 'WinLab-Allow-DNS' -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow | Out-Null
      New-NetFirewallRule -DisplayName 'WinLab-Allow-HTTP' -Direction Outbound -Protocol TCP -RemotePort 80 -Action Allow | Out-Null
      New-NetFirewallRule -DisplayName 'WinLab-Allow-HTTPS' -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow | Out-Null
      New-NetFirewallRule -DisplayName 'WinLab-Allow-QUIC' -Direction Outbound -Protocol UDP -RemotePort 443 -Action Allow | Out-Null
      New-NetFirewallRule -DisplayName 'WinLab-Allow-WHOIS' -Direction Outbound -Protocol TCP -RemotePort 43 -Action Allow | Out-Null
      New-NetFirewallRule -DisplayName 'WinLab-Allow-NTP' -Direction Outbound -Protocol UDP -RemotePort 123 -Action Allow | Out-Null

      # Block SMB explicitly (defense-in-depth)
      New-NetFirewallRule -DisplayName 'WinLab-Block-SMB' -Direction Outbound -Protocol TCP -RemotePort 445 -Action Block | Out-Null
      return
    }

    if($mode -eq 'AllowMost'){
      Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
      Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow -DefaultInboundAction Block

      # Still block SMB (defense-in-depth)
      New-NetFirewallRule -DisplayName 'WinLab-Block-SMB' -Direction Outbound -Protocol TCP -RemotePort 445 -Action Block | Out-Null
      return
    }
  } catch {
    Log "Firewall: no pude aplicar reglas ($($_.Exception.Message))."
  }
}

function Try-UpdateDefenderSignatures {
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $ok = $false
  $method = $null
  $err = $null

  try {
    Log 'Actualizando firmas de Microsoft Defender (Update-MpSignature)...'
    Update-MpSignature | Out-Null
    $ok = $true
    $method = 'Update-MpSignature'
  } catch {
    $err = $_.Exception.Message
    try {
      $candidates = @(
        (Join-Path $env:ProgramFiles 'Windows Defender\\MpCmdRun.exe'),
        (Join-Path $env:ProgramFiles 'Microsoft Defender\\MpCmdRun.exe')
      )

      $mpCmd = $null
      foreach($c in $candidates){ if(Test-Path $c){ $mpCmd = $c; break } }

      if(-not $mpCmd){
        $hits = Get-ChildItem -Path 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MpCmdRun.exe' -ErrorAction SilentlyContinue | Sort-Object FullName -Descending
        if($hits){ $mpCmd = $hits[0].FullName }
      }

      if($mpCmd){
        Log 'Fallback firmas (MpCmdRun.exe -SignatureUpdate)...'
        Start-Process -FilePath $mpCmd -ArgumentList '-SignatureUpdate' -Wait -NoNewWindow | Out-Null
        $ok = $true
        $method = 'MpCmdRun -SignatureUpdate'
        $err = $null
      }
    } catch {
      if(-not $err){ $err = $_.Exception.Message }
    }
  }

  $sw.Stop()
  return [pscustomobject]@{ Ok=$ok; Method=$method; Error=$err; DurationMs=[int]$sw.Elapsed.TotalMilliseconds }
}

function Get-DefenderStatus {
  try {
    $s = Get-MpComputerStatus
    return [pscustomobject]@{
      AntivirusEnabled = $s.AntivirusEnabled
      RealTimeProtectionEnabled = $s.RealTimeProtectionEnabled
      AntivirusSignatureVersion = $s.AntivirusSignatureVersion
      AntivirusSignatureLastUpdated = $s.AntivirusSignatureLastUpdated
      NISSignatureVersion = $s.NISSignatureVersion
      NISSignatureLastUpdated = $s.NISSignatureLastUpdated
      EngineVersion = $s.AMEngineVersion
      ServiceVersion = $s.AMServiceVersion
    }
  } catch {
    return $null
  }
}

function Get-SignatureAgeDays([object]$status){
  try {
    if($status -and $status.AntivirusSignatureLastUpdated){
      return [math]::Round(((Get-Date) - [datetime]$status.AntivirusSignatureLastUpdated).TotalDays,2)
    }
  } catch {}
  return $null
}

function Pick-InputFile([string]$folder, [string]$targetName){
  if(-not (Test-Path $folder)){
    return $null
  }
  if(-not [string]::IsNullOrWhiteSpace($targetName)){
    $p = Join-Path $folder $targetName
    if(Test-Path $p){ return (Get-Item -LiteralPath $p -ErrorAction SilentlyContinue) }
  }

  $skipExt = @('.crdownload','.tmp','.part')
  $candidates = Get-ChildItem -LiteralPath $folder -File -ErrorAction SilentlyContinue |
    Where-Object { $skipExt -notcontains $_.Extension.ToLowerInvariant() } |
    Sort-Object LastWriteTime -Descending

  return ($candidates | Select-Object -First 1)
}

function Copy-ToWork([string]$srcPath){
  $workRoot = 'C:\\WinLabWork'
  $inDir = Join-Path $workRoot 'input'
  Ensure-Dir $inDir

  $name = Split-Path $srcPath -Leaf
  $dst = Join-Path $inDir ((NowStamp) + '__' + (SafeFileName $name))
  Copy-Item -LiteralPath $srcPath -Destination $dst -Force
  return $dst
}

function Compute-Sha256([string]$path){
  try { return (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash } catch { return $null }
}

function Read-MOTW([string]$path){
  # Mark-of-the-Web (Zone.Identifier ADS). Best-effort.
  try {
    $ads = Get-Content -LiteralPath $path -Stream Zone.Identifier -ErrorAction Stop
    $zone = $null
    $ref  = $null
    foreach($l in $ads){
      if($l -match '^ZoneId=(\\d+)'){ $zone = [int]$Matches[1] }
      if($l -match '^ReferrerUrl=(.*)$'){ $ref = $Matches[1] }
    }
    return [pscustomobject]@{ Present=$true; ZoneId=$zone; ReferrerUrl=$ref; Raw=($ads -join "`n") }
  } catch {
    return [pscustomobject]@{ Present=$false; ZoneId=$null; ReferrerUrl=$null; Raw=$null }
  }
}

function Get-AuthenticodeSummary([string]$path){
  try {
    $sig = Get-AuthenticodeSignature -LiteralPath $path
    $subject = $null
    $thumb = $null
    $issuer = $null
    $notBefore = $null
    $notAfter = $null
    if($sig.SignerCertificate){
      $subject = $sig.SignerCertificate.Subject
      $thumb = $sig.SignerCertificate.Thumbprint
      $issuer = $sig.SignerCertificate.Issuer
      $notBefore = $sig.SignerCertificate.NotBefore
      $notAfter = $sig.SignerCertificate.NotAfter
    }
    return [pscustomobject]@{
      Status = [string]$sig.Status
      StatusMessage = [string]$sig.StatusMessage
      IsOSBinary = [bool]$sig.IsOSBinary
      SignerSubject = $subject
      SignerThumbprint = $thumb
      SignerIssuer = $issuer
      CertNotBefore = $notBefore
      CertNotAfter = $notAfter
    }
  } catch {
    return $null
  }
}

function Start-CustomScan([string]$path){
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $ok = $false
  $err = $null
  try {
    Start-MpScan -ScanType CustomScan -ScanPath $path | Out-Null
    $ok = $true
  } catch {
    $err = $_.Exception.Message
  }
  $sw.Stop()
  return [pscustomobject]@{ Ok=$ok; Error=$err; DurationMs=[int]$sw.Elapsed.TotalMilliseconds }
}

function Get-ThreatDetections([datetime]$since){
  try {
    $hits = Get-MpThreatDetection | Where-Object {
      ($_.InitialDetectionTime -ge $since) -or ($_.LastThreatStatusChangeTime -ge $since)
    }

    return @($hits | Select-Object -First 50 | ForEach-Object {
      [pscustomobject]@{
        ThreatName = $_.ThreatName
        ThreatID = $_.ThreatID
        SeverityID = $_.SeverityID
        CategoryID = $_.CategoryID
        ActionSuccess = $_.ActionSuccess
        Resources = $_.Resources
        InitialDetectionTime = $_.InitialDetectionTime
        LastThreatStatusChangeTime = $_.LastThreatStatusChangeTime
        ProcessName = $_.ProcessName
      }
    })
  } catch {
    return @()
  }
}

function Get-ProcSnapshot {
  try {
    return @(
      Get-Process -ErrorAction SilentlyContinue |
        Select-Object Id,ProcessName,Path,StartTime,CPU,WorkingSet |
        ForEach-Object {
          [pscustomobject]@{
            pid=$_.Id
            name=$_.ProcessName
            path=$_.Path
            startTime=$_.StartTime
            cpu=$_.CPU
            ws=$_.WorkingSet
          }
        }
    )
  } catch {
    return @()
  }
}

function Get-NetSnapshot {
  try {
    return @(
      Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object { $_.State -in @('Established','SynSent','SynReceived','TimeWait') } |
        Select-Object -First 150 -Property State,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess |
        ForEach-Object {
          [pscustomobject]@{
            state=$_.State
            laddr=$_.LocalAddress
            lport=$_.LocalPort
            raddr=$_.RemoteAddress
            rport=$_.RemotePort
            pid=$_.OwningProcess
          }
        }
    )
  } catch {
    return @()
  }
}

function Get-BehaviorSignals([object[]]$proc0, [object[]]$proc1, [object[]]$net0, [object[]]$net1){
  $newProcCount = 0
  $newConnCount = 0
  $suspiciousPorts = @()
  $allowedPorts = @(53,80,123,443,43)

  try {
    $baseProcs = @{}
    foreach($p in @($proc0)){
      $key = ($p.name + '|' + $p.path)
      $baseProcs[$key] = $true
    }
    $newProcs = @()
    foreach($p in @($proc1)){
      $key = ($p.name + '|' + $p.path)
      if(-not $baseProcs.ContainsKey($key)){ $newProcs += $p }
    }
    $newProcCount = @($newProcs).Count
  } catch {}

  try {
    $baseConn = @{}
    foreach($n in @($net0)){
      $key = ($n.raddr + ':' + $n.rport)
      $baseConn[$key] = $true
    }
    $newConns = @()
    foreach($n in @($net1)){
      if($n.raddr -in @('127.0.0.1','::1','0.0.0.0')){ continue }
      $key = ($n.raddr + ':' + $n.rport)
      if(-not $baseConn.ContainsKey($key)){ $newConns += $n }
    }
    $newConnCount = @($newConns).Count
    $suspiciousPorts = @(
      $newConns |
        Where-Object { $_.rport -and ($allowedPorts -notcontains [int]$_.rport) } |
        Select-Object -ExpandProperty rport -Unique
    )
  } catch {}

  $suspicious = $false
  if($newProcCount -ge 10){ $suspicious = $true }
  if(@($suspiciousPorts).Count -ge 3){ $suspicious = $true }

  return [pscustomobject]@{
    newProcessCount = $newProcCount
    newConnectionCount = $newConnCount
    suspiciousPorts = @($suspiciousPorts)
    suspicious = $suspicious
  }
}

function Resolve-Domain([string]$host){
  try {
    $ips = @()
    try { $ips = [System.Net.Dns]::GetHostAddresses($host) | ForEach-Object { $_.IPAddressToString } } catch {}
    return @($ips | Select-Object -Unique | Select-Object -First 10)
  } catch { return @() }
}

function Head-Url([string]$u){
  try {
    $resp = Invoke-WebRequest -Uri $u -Method Head -MaximumRedirection 0 -UseBasicParsing -TimeoutSec 12 -ErrorAction Stop
    return [pscustomobject]@{ ok=$true; status=[int]$resp.StatusCode; headers=$resp.Headers; location=$resp.Headers['Location'] }
  } catch {
    # Some servers block HEAD; try GET without downloading full content.
    try {
      $resp2 = Invoke-WebRequest -Uri $u -Method Get -MaximumRedirection 0 -UseBasicParsing -TimeoutSec 12 -ErrorAction Stop
      return [pscustomobject]@{ ok=$true; status=[int]$resp2.StatusCode; headers=$resp2.Headers; location=$resp2.Headers['Location'] }
    } catch {
      return [pscustomobject]@{ ok=$false; status=$null; headers=$null; location=$null; error=$_.Exception.Message }
    }
  }
}

function Get-TlsInfo([string]$host){
  # Best-effort: open a TLS handshake and read remote certificate.
  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $client.ReceiveTimeout = 8000
    $client.SendTimeout = 8000
    $client.Connect($host, 443)

    $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false, ({$true}))
    $ssl.ReadTimeout = 8000
    $ssl.WriteTimeout = 8000
    $ssl.AuthenticateAsClient($host)

    $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
    $ssl.Close(); $client.Close()

    return [pscustomobject]@{
      ok=$true
      subject=$cert2.Subject
      issuer=$cert2.Issuer
      notBefore=$cert2.NotBefore
      notAfter=$cert2.NotAfter
      thumbprint=$cert2.Thumbprint
      serial=$cert2.SerialNumber
    }
  } catch {
    try{ if($ssl){$ssl.Close()} } catch {}
    try{ if($client){$client.Close()} } catch {}
    return [pscustomobject]@{ ok=$false; error=$_.Exception.Message }
  }
}

function Whois-Query([string]$host){
  # WHOIS via TCP/43. Many environments block it; return best-effort.
  try {
    $q = $host
    $server = 'whois.iana.org'

    $first = Invoke-Whois -Server $server -Query $q
    if($first -and $first.refer){
      $second = Invoke-Whois -Server $first.refer -Query $q
      return [pscustomobject]@{ ok=$true; server=$first.refer; raw=$second.raw; country=$second.country; org=$second.org }
    }
    return [pscustomobject]@{ ok=$true; server=$server; raw=$first.raw; country=$first.country; org=$first.org }
  } catch {
    return [pscustomobject]@{ ok=$false; error=$_.Exception.Message }
  }
}

function Invoke-Whois([string]$Server, [string]$Query){
  $client = New-Object System.Net.Sockets.TcpClient
  $client.ReceiveTimeout = 9000
  $client.SendTimeout = 9000
  $client.Connect($Server, 43)
  $stream = $client.GetStream()
  $writer = New-Object System.IO.StreamWriter($stream)
  $writer.NewLine = "`r`n"
  $writer.WriteLine($Query)
  $writer.Flush()

  $reader = New-Object System.IO.StreamReader($stream)
  $raw = $reader.ReadToEnd()
  $reader.Close(); $writer.Close(); $stream.Close(); $client.Close()

  $refer = $null
  foreach($line in ($raw -split "`r?`n")){
    if($line -match '^refer:\s*(.+)$'){ $refer = $Matches[1].Trim(); break }
  }

  $country = $null
  $org = $null
  foreach($line in ($raw -split "`r?`n")){
    if(-not $country -and $line -match '^(country|Country):\s*(.+)$'){ $country = $Matches[2].Trim() }
    if(-not $org -and $line -match '^(org|OrgName|organization|descr|Organization):\s*(.+)$'){ $org = $Matches[2].Trim() }
  }

  return [pscustomobject]@{ raw=$raw; refer=$refer; country=$country; org=$org }
}

function Analyze-Url([string]$u){
  if([string]::IsNullOrWhiteSpace($u)){
    return $null
  }

  $o = $null
  try { $o = [uri]$u } catch { return [pscustomobject]@{ ok=$false; error='URL invalida.'; url=$u } }

  $host = $o.Host
  $ips = Resolve-Domain $host
  $head = Head-Url $u

  $redirects = @()
  $cur = $u
  for($i=0; $i -lt 8; $i++){
    $h = Head-Url $cur
    if(-not $h.ok){ break }
    $redirects += [pscustomobject]@{ url=$cur; status=$h.status; location=$h.location }
    if($h.status -ge 300 -and $h.status -lt 400 -and $h.location){
      try{
        $next = [uri]::new([uri]$cur, $h.location)
        $cur = $next.AbsoluteUri
        continue
      } catch { break }
    }
    break
  }

  $tls = $null
  if($o.Scheme -eq 'https'){
    $tls = Get-TlsInfo $host
  }

  $whois = Whois-Query $host

  return [pscustomobject]@{
    ok=$true
    url=$u
    scheme=$o.Scheme
    host=$host
    port=$o.Port
    path=$o.AbsolutePath
    ips=$ips
    headStatus=$head.status
    headError=$head.error
    redirects=$redirects
    tls=$tls
    whois=$whois
  }
}

function Compute-Risk([object]$urlInfo, [object[]]$artifacts, [object[]]$detections, [object]$defenderUpdate, [double]$sigAgeDays, [object]$behavior){
  $score = 0
  $reasons = New-Object System.Collections.Generic.List[string]
  $hasRedirects = $false
  $hasMotwUnsigned = $false
  $behaviorWeird = $false

  if($detections -and $detections.Count -gt 0){
    $score += 80
    $reasons.Add('Defender reporto detecciones en este run.')
  }

  if($defenderUpdate -and (-not $defenderUpdate.Ok)){
    $score += 15
    $reasons.Add('No se pudo actualizar firmas de Defender (posible falta de red o bloqueo).')
  }

  if($sigAgeDays -ne $null -and $sigAgeDays -gt 2){
    $score += 10
    $reasons.Add('Las firmas de Defender tienen mas de 48h.')
  }

  if($urlInfo -and $urlInfo.ok){
    if($urlInfo.scheme -ne 'https'){
      $score += 10
      $reasons.Add('La URL no usa HTTPS.')
    }

    $rCount = 0
    if($urlInfo.redirects){ $rCount = @($urlInfo.redirects | Where-Object { $_.status -ge 300 -and $_.status -lt 400 }).Count }
    if($rCount -ge 2){
      $score += 8
      $reasons.Add('La URL usa multiples redirecciones.')
      $hasRedirects = $true
    }

    if($urlInfo.tls -and $urlInfo.tls.ok){
      try{
        $daysLeft = ([datetime]$urlInfo.tls.notAfter - (Get-Date)).TotalDays
        if($daysLeft -lt 7){
          $score += 6
          $reasons.Add('El certificado TLS esta por expirar.')
        }
      } catch {}
    }

    if($urlInfo.whois -and $urlInfo.whois.ok){
      $org = ($urlInfo.whois.org + '')
      if([string]::IsNullOrWhiteSpace($org)){
        $score += 5
        $reasons.Add('WHOIS sin organizacion clara (dato incompleto).')
      }
    } else {
      $score += 3
      $reasons.Add('No se pudo resolver WHOIS (no concluyente).')
    }
  }

  if($artifacts){
    $exe = @($artifacts | Where-Object { $_.extension -in @('.exe','.msi','.scr','.js','.vbs','.ps1','.bat','.cmd','.lnk') })
    if($exe.Count -gt 0){
      $score += 10
      $reasons.Add('Se detectaron archivos ejecutables o scripts descargados durante la sesion.')
    }

    $unsigned = @($artifacts | Where-Object { $_.authenticode -and $_.authenticode.Status -in @('NotSigned','UnknownError') })
    if($unsigned.Count -gt 0){
      $score += 10
      $reasons.Add('Hay ejecutables o scripts sin firma valida.')
    }

    $motwPresent = @($artifacts | Where-Object { $_.motw -and $_.motw.Present })
    if($motwPresent.Count -gt 0 -and $unsigned.Count -gt 0){
      $hasMotwUnsigned = $true
      $reasons.Add('Archivos con MOTW y sin firma valida (senal combinada).')
    }

    $motwNone = @($artifacts | Where-Object { $_.motw -and (-not $_.motw.Present) })
    if($motwNone.Count -gt 0){
      $score += 5
      $reasons.Add('Algunos archivos no tienen Mark-of-the-Web (MOTW).')
    }
  }

  if($behavior -and $behavior.suspicious){
    $behaviorWeird = $true
    $score += 8
    $reasons.Add('Se observaron conexiones/procesos inusuales en la sesion.')
  }

  $strongSignals = $hasMotwUnsigned -and $hasRedirects -and $behaviorWeird
  if($strongSignals){
    $score += 12
    $reasons.Add('Senales fuertes: MOTW + sin firma + redirecciones + comportamiento inusual.')
  }

  $forceInconclusive = $false
  if($strongSignals -and (-not $detections -or $detections.Count -eq 0)){
    $forceInconclusive = $true
  }

  if($score -gt 100){ $score = 100 }

  $level = if($score -ge 80){'ALTO'} elseif($score -ge 50){'MEDIO'} elseif($score -ge 25){'BAJO'} else {'MINIMO'}
  $decision = if($score -ge 80){
    'BLOQUEAR'
  } elseif($score -ge 50){
    'CAUTELA'
  } else {
    'OK'
  }

  return [pscustomobject]@{
    enabled=$true
    score=$score
    level=$level
    decision=$decision
    reasons=@($reasons)
    strongSignals=$strongSignals
    forceInconclusive=$forceInconclusive
    behaviorSummary=$behavior
  }
}

function Build-Artifact([string]$path, [string]$source){
  $name = Split-Path $path -Leaf
  $ext = ([System.IO.Path]::GetExtension($name) + '').ToLowerInvariant()

  $sha = Compute-Sha256 $path
  $motw = Read-MOTW $path
  $sig = $null
  # Only attempt Authenticode for PE/script types
  if($ext -in @('.exe','.dll','.msi','.sys','.ps1','.psm1','.vbs','.js','.cmd','.bat','.scr')){
    $sig = Get-AuthenticodeSummary $path
  }

  return [pscustomobject]@{
    source=$source
    fileName=$name
    extension=$ext
    fullPath=$path
    sha256=$sha
    motw=$motw
    authenticode=$sig
  }
}

function Write-ReportFiles([string]$runDir, [object]$report){
  $jsonPath = Join-Path $runDir 'report.json'
  $htmlPath = Join-Path $runDir 'report.html'
  $txtPath  = Join-Path $runDir 'report.txt'

  ($report | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $jsonPath -Encoding UTF8

  $statusText = $report.summary.status
  $badge = if($statusText -eq 'OK'){'#1f7a1f'} elseif($statusText -eq 'DETECTADO'){'#b00020'} else {'#b26a00'}

  $riskBadge = '#3a3a3a'
  $riskText = 'N/A'
  if($report.autoDecision -and $report.autoDecision.enabled){
    $riskText = "$($report.autoDecision.level) ($($report.autoDecision.score))"
    $riskBadge = if($report.autoDecision.level -eq 'ALTO'){'#b00020'} elseif($report.autoDecision.level -eq 'MEDIO'){'#b26a00'} elseif($report.autoDecision.level -eq 'BAJO'){'#2f6f98'} else {'#3a3a3a'}
  }

  $detRows = ''
  foreach($d in @($report.evidence.detections)){
    $res = ''
    try{ $res = ($d.Resources -join '<br>') } catch {}
    $detRows += "<tr><td><code>$(HtmlE $d.ThreatName)</code></td><td>$(HtmlE ($d.ThreatID+''))</td><td>$(HtmlE ($d.SeverityID+''))</td><td><small>$(HtmlE $res)</small></td></tr>"
  }
  if([string]::IsNullOrWhiteSpace($detRows)){
    $detRows = "<tr><td colspan='4' class='muted'>Sin detecciones de Defender registradas en este run.</td></tr>"
  }

  $artRows = ''
  foreach($a in @($report.artifacts.files)){
    $sigS = ''
    if($a.authenticode){ $sigS = $a.authenticode.Status }
    $motwS = if($a.motw -and $a.motw.Present){ "ZoneId=$($a.motw.ZoneId)" } else { 'sin MOTW' }
    $artRows += "<tr><td>$(HtmlE $a.source)</td><td>$(HtmlE $a.fileName)</td><td><code>$(HtmlE $a.sha256)</code></td><td>$(HtmlE $motwS)</td><td>$(HtmlE $sigS)</td></tr>"
  }
  if([string]::IsNullOrWhiteSpace($artRows)){
    $artRows = "<tr><td colspan='5' class='muted'>No se registraron archivos (entrada o descargas) para detallar.</td></tr>"
  }

  $redirRows = ''
  if($report.urlAnalysis -and $report.urlAnalysis.ok -and $report.urlAnalysis.redirects){
    foreach($r in @($report.urlAnalysis.redirects)){
      $redirRows += "<tr><td>$(HtmlE $r.status)</td><td><small>$(HtmlE $r.url)</small></td><td><small>$(HtmlE ($r.location+''))</small></td></tr>"
    }
  }
  if([string]::IsNullOrWhiteSpace($redirRows)){
    $redirRows = "<tr><td colspan='3' class='muted'>Sin datos de redirecciones.</td></tr>"
  }

  $reasonsHtml = ''
  if($report.autoDecision -and $report.autoDecision.enabled -and $report.autoDecision.reasons){
    foreach($rr in @($report.autoDecision.reasons)){
      $reasonsHtml += '<li>' + (HtmlE $rr) + '</li>'
    }
  } else {
    $reasonsHtml = '<li class="muted">AutoDecision deshabilitado o sin razones.</li>'
  }

  $inconcl = ''
  if($report.summary.inconclusiveReason){ $inconcl = "<div class=\"alert warn\">Motivo inconcluso: $(HtmlE $report.summary.inconclusiveReason)</div>" }

  $meaning = $report.summary.meaning
  $scanCount = @($report.artifacts.scans).Count
  $scanOk = (@($report.artifacts.scans) | Where-Object { [CmdletBinding()]
param(
  [Parameter(Mandatory=$false)]
  [string]$Preset = 'Balanced',

  # Host-mapped inbox (ReadOnly). Default matches Run-WinLab.cmd mapping.
  [Parameter(Mandatory=$false)]
  [string]$InputFolder = 'C:\WinLabInboxRO',

  # Report output. When Outbox is mapped, points to C:\Outbox.
  [Parameter(Mandatory=$false)]
  [string]$OutFolder = 'C:\Outbox',

  # Session duration (minutes). Sandbox will self-close after this.
  [Parameter(Mandatory=$false)]
  [int]$Minutes = 10,

  # Network hardening inside Sandbox (best-effort).
  [ValidateSet('BlockAll','InternetOnly','AllowMost')]
  [string]$FirewallMode = 'InternetOnly',

  # If 1, write reports to OutFolder (mapped to host). If 0, write locally in Sandbox.
  [Parameter(Mandatory=$false)]
  [int]$EnableOutbox = 1,

  # Optional URL to open in Edge (in-private) inside Sandbox.
  [Parameter(Mandatory=$false)]
  [string]$Url = '',

  # Optional: scan a specific filename from InputFolder instead of "latest".
  [Parameter(Mandatory=$false)]
  [string]$TargetFileName = '',

  # If 1, compute a risk score and produce an "autoDecision" section.
  [Parameter(Mandatory=$false)]
  [int]$AutoDecisionEnabled = 1,

  # If 1, collect process/network deltas (best-effort).
  [Parameter(Mandatory=$false)]
  [int]$CollectDeltas = 1
)

$ErrorActionPreference = 'Stop'

# =====================
# Helpers
# =====================
function NowStamp { Get-Date -Format "yyyyMMdd_HHmmss" }
function SafeFileName([string]$s){
  if([string]::IsNullOrWhiteSpace($s)){ return '' }
  return ($s -replace "[^A-Za-z0-9_.-]","_")
}
function Log([string]$m){
  try{ Write-Host ("[WinLab] " + $m) } catch {}
}
function HtmlE([string]$s){
  if($null -eq $s){ return '' }
  return ($s.Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;').Replace("'",'&#39;'))
}

function Ensure-Dir([string]$p){
  New-Item -ItemType Directory -Force -Path $p | Out-Null
}

function Ensure-OutDir([int]$enable, [string]$outFolder){
  if($enable -eq 1){
    Ensure-Dir $outFolder
    return $outFolder
  }
  $local = 'C:\WinLabReports'
  Ensure-Dir $local
  return $local
}

function Apply-Firewall([string]$mode){
  try{
    Log "Firewall mode: $mode"

    # Clean our old rules to avoid accumulation
    Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like 'WinLab-*' } | Remove-NetFirewallRule -ErrorAction SilentlyContinue

    if($mode -eq 'BlockAll'){
      Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
      Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block -DefaultInboundAction Block
      return
    }

    if($mode -eq 'InternetOnly'){
      # Allow only core web browsing + DNS + WHOIS (43) + NTP. Everything else is blocked.
      Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
      Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Block -DefaultInboundAction Block

      New-NetFirewallRule -DisplayName 'WinLab-Allow-DNS' -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow | Out-Null
      New-NetFirewallRule -DisplayName 'WinLab-Allow-HTTP' -Direction Outbound -Protocol TCP -RemotePort 80 -Action Allow | Out-Null
      New-NetFirewallRule -DisplayName 'WinLab-Allow-HTTPS' -Direction Outbound -Protocol TCP -RemotePort 443 -Action Allow | Out-Null
      New-NetFirewallRule -DisplayName 'WinLab-Allow-QUIC' -Direction Outbound -Protocol UDP -RemotePort 443 -Action Allow | Out-Null
      New-NetFirewallRule -DisplayName 'WinLab-Allow-WHOIS' -Direction Outbound -Protocol TCP -RemotePort 43 -Action Allow | Out-Null
      New-NetFirewallRule -DisplayName 'WinLab-Allow-NTP' -Direction Outbound -Protocol UDP -RemotePort 123 -Action Allow | Out-Null

      # Block SMB explicitly (defense-in-depth)
      New-NetFirewallRule -DisplayName 'WinLab-Block-SMB' -Direction Outbound -Protocol TCP -RemotePort 445 -Action Block | Out-Null
      return
    }

    if($mode -eq 'AllowMost'){
      Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
      Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow -DefaultInboundAction Block

      # Still block SMB (defense-in-depth)
      New-NetFirewallRule -DisplayName 'WinLab-Block-SMB' -Direction Outbound -Protocol TCP -RemotePort 445 -Action Block | Out-Null
      return
    }
  } catch {
    Log "Firewall: no pude aplicar reglas ($($_.Exception.Message))."
  }
}

function Try-UpdateDefenderSignatures {
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $ok = $false
  $method = $null
  $err = $null

  try {
    Log 'Actualizando firmas de Microsoft Defender (Update-MpSignature)...'
    Update-MpSignature | Out-Null
    $ok = $true
    $method = 'Update-MpSignature'
  } catch {
    $err = $_.Exception.Message
    try {
      $candidates = @(
        (Join-Path $env:ProgramFiles 'Windows Defender\\MpCmdRun.exe'),
        (Join-Path $env:ProgramFiles 'Microsoft Defender\\MpCmdRun.exe')
      )

      $mpCmd = $null
      foreach($c in $candidates){ if(Test-Path $c){ $mpCmd = $c; break } }

      if(-not $mpCmd){
        $hits = Get-ChildItem -Path 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\*\\MpCmdRun.exe' -ErrorAction SilentlyContinue | Sort-Object FullName -Descending
        if($hits){ $mpCmd = $hits[0].FullName }
      }

      if($mpCmd){
        Log 'Fallback firmas (MpCmdRun.exe -SignatureUpdate)...'
        Start-Process -FilePath $mpCmd -ArgumentList '-SignatureUpdate' -Wait -NoNewWindow | Out-Null
        $ok = $true
        $method = 'MpCmdRun -SignatureUpdate'
        $err = $null
      }
    } catch {
      if(-not $err){ $err = $_.Exception.Message }
    }
  }

  $sw.Stop()
  return [pscustomobject]@{ Ok=$ok; Method=$method; Error=$err; DurationMs=[int]$sw.Elapsed.TotalMilliseconds }
}

function Get-DefenderStatus {
  try {
    $s = Get-MpComputerStatus
    return [pscustomobject]@{
      AntivirusEnabled = $s.AntivirusEnabled
      RealTimeProtectionEnabled = $s.RealTimeProtectionEnabled
      AntivirusSignatureVersion = $s.AntivirusSignatureVersion
      AntivirusSignatureLastUpdated = $s.AntivirusSignatureLastUpdated
      NISSignatureVersion = $s.NISSignatureVersion
      NISSignatureLastUpdated = $s.NISSignatureLastUpdated
      EngineVersion = $s.AMEngineVersion
      ServiceVersion = $s.AMServiceVersion
    }
  } catch {
    return $null
  }
}

function Get-SignatureAgeDays([object]$status){
  try {
    if($status -and $status.AntivirusSignatureLastUpdated){
      return [math]::Round(((Get-Date) - [datetime]$status.AntivirusSignatureLastUpdated).TotalDays,2)
    }
  } catch {}
  return $null
}

function Pick-InputFile([string]$folder, [string]$targetName){
  if(-not (Test-Path $folder)){
    return $null
  }
  if(-not [string]::IsNullOrWhiteSpace($targetName)){
    $p = Join-Path $folder $targetName
    if(Test-Path $p){ return (Get-Item -LiteralPath $p -ErrorAction SilentlyContinue) }
  }

  $skipExt = @('.crdownload','.tmp','.part')
  $candidates = Get-ChildItem -LiteralPath $folder -File -ErrorAction SilentlyContinue |
    Where-Object { $skipExt -notcontains $_.Extension.ToLowerInvariant() } |
    Sort-Object LastWriteTime -Descending

  return ($candidates | Select-Object -First 1)
}

function Copy-ToWork([string]$srcPath){
  $workRoot = 'C:\\WinLabWork'
  $inDir = Join-Path $workRoot 'input'
  Ensure-Dir $inDir

  $name = Split-Path $srcPath -Leaf
  $dst = Join-Path $inDir ((NowStamp) + '__' + (SafeFileName $name))
  Copy-Item -LiteralPath $srcPath -Destination $dst -Force
  return $dst
}

function Compute-Sha256([string]$path){
  try { return (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash } catch { return $null }
}

function Read-MOTW([string]$path){
  # Mark-of-the-Web (Zone.Identifier ADS). Best-effort.
  try {
    $ads = Get-Content -LiteralPath $path -Stream Zone.Identifier -ErrorAction Stop
    $zone = $null
    $ref  = $null
    foreach($l in $ads){
      if($l -match '^ZoneId=(\\d+)'){ $zone = [int]$Matches[1] }
      if($l -match '^ReferrerUrl=(.*)$'){ $ref = $Matches[1] }
    }
    return [pscustomobject]@{ Present=$true; ZoneId=$zone; ReferrerUrl=$ref; Raw=($ads -join "`n") }
  } catch {
    return [pscustomobject]@{ Present=$false; ZoneId=$null; ReferrerUrl=$null; Raw=$null }
  }
}

function Get-AuthenticodeSummary([string]$path){
  try {
    $sig = Get-AuthenticodeSignature -LiteralPath $path
    $subject = $null
    $thumb = $null
    $issuer = $null
    $notBefore = $null
    $notAfter = $null
    if($sig.SignerCertificate){
      $subject = $sig.SignerCertificate.Subject
      $thumb = $sig.SignerCertificate.Thumbprint
      $issuer = $sig.SignerCertificate.Issuer
      $notBefore = $sig.SignerCertificate.NotBefore
      $notAfter = $sig.SignerCertificate.NotAfter
    }
    return [pscustomobject]@{
      Status = [string]$sig.Status
      StatusMessage = [string]$sig.StatusMessage
      IsOSBinary = [bool]$sig.IsOSBinary
      SignerSubject = $subject
      SignerThumbprint = $thumb
      SignerIssuer = $issuer
      CertNotBefore = $notBefore
      CertNotAfter = $notAfter
    }
  } catch {
    return $null
  }
}

function Start-CustomScan([string]$path){
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $ok = $false
  $err = $null
  try {
    Start-MpScan -ScanType CustomScan -ScanPath $path | Out-Null
    $ok = $true
  } catch {
    $err = $_.Exception.Message
  }
  $sw.Stop()
  return [pscustomobject]@{ Ok=$ok; Error=$err; DurationMs=[int]$sw.Elapsed.TotalMilliseconds }
}

function Get-ThreatDetections([datetime]$since){
  try {
    $hits = Get-MpThreatDetection | Where-Object {
      ($_.InitialDetectionTime -ge $since) -or ($_.LastThreatStatusChangeTime -ge $since)
    }

    return @($hits | Select-Object -First 50 | ForEach-Object {
      [pscustomobject]@{
        ThreatName = $_.ThreatName
        ThreatID = $_.ThreatID
        SeverityID = $_.SeverityID
        CategoryID = $_.CategoryID
        ActionSuccess = $_.ActionSuccess
        Resources = $_.Resources
        InitialDetectionTime = $_.InitialDetectionTime
        LastThreatStatusChangeTime = $_.LastThreatStatusChangeTime
        ProcessName = $_.ProcessName
      }
    })
  } catch {
    return @()
  }
}

function Get-ProcSnapshot {
  try {
    return @(
      Get-Process -ErrorAction SilentlyContinue |
        Select-Object Id,ProcessName,Path,StartTime,CPU,WorkingSet |
        ForEach-Object {
          [pscustomobject]@{
            pid=$_.Id
            name=$_.ProcessName
            path=$_.Path
            startTime=$_.StartTime
            cpu=$_.CPU
            ws=$_.WorkingSet
          }
        }
    )
  } catch {
    return @()
  }
}

function Get-NetSnapshot {
  try {
    return @(
      Get-NetTCPConnection -ErrorAction SilentlyContinue |
        Where-Object { $_.State -in @('Established','SynSent','SynReceived','TimeWait') } |
        Select-Object -First 150 -Property State,LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess |
        ForEach-Object {
          [pscustomobject]@{
            state=$_.State
            laddr=$_.LocalAddress
            lport=$_.LocalPort
            raddr=$_.RemoteAddress
            rport=$_.RemotePort
            pid=$_.OwningProcess
          }
        }
    )
  } catch {
    return @()
  }
}

function Get-BehaviorSignals([object[]]$proc0, [object[]]$proc1, [object[]]$net0, [object[]]$net1){
  $newProcCount = 0
  $newConnCount = 0
  $suspiciousPorts = @()
  $allowedPorts = @(53,80,123,443,43)

  try {
    $baseProcs = @{}
    foreach($p in @($proc0)){
      $key = ($p.name + '|' + $p.path)
      $baseProcs[$key] = $true
    }
    $newProcs = @()
    foreach($p in @($proc1)){
      $key = ($p.name + '|' + $p.path)
      if(-not $baseProcs.ContainsKey($key)){ $newProcs += $p }
    }
    $newProcCount = @($newProcs).Count
  } catch {}

  try {
    $baseConn = @{}
    foreach($n in @($net0)){
      $key = ($n.raddr + ':' + $n.rport)
      $baseConn[$key] = $true
    }
    $newConns = @()
    foreach($n in @($net1)){
      if($n.raddr -in @('127.0.0.1','::1','0.0.0.0')){ continue }
      $key = ($n.raddr + ':' + $n.rport)
      if(-not $baseConn.ContainsKey($key)){ $newConns += $n }
    }
    $newConnCount = @($newConns).Count
    $suspiciousPorts = @(
      $newConns |
        Where-Object { $_.rport -and ($allowedPorts -notcontains [int]$_.rport) } |
        Select-Object -ExpandProperty rport -Unique
    )
  } catch {}

  $suspicious = $false
  if($newProcCount -ge 10){ $suspicious = $true }
  if(@($suspiciousPorts).Count -ge 3){ $suspicious = $true }

  return [pscustomobject]@{
    newProcessCount = $newProcCount
    newConnectionCount = $newConnCount
    suspiciousPorts = @($suspiciousPorts)
    suspicious = $suspicious
  }
}

function Resolve-Domain([string]$host){
  try {
    $ips = @()
    try { $ips = [System.Net.Dns]::GetHostAddresses($host) | ForEach-Object { $_.IPAddressToString } } catch {}
    return @($ips | Select-Object -Unique | Select-Object -First 10)
  } catch { return @() }
}

function Head-Url([string]$u){
  try {
    $resp = Invoke-WebRequest -Uri $u -Method Head -MaximumRedirection 0 -UseBasicParsing -TimeoutSec 12 -ErrorAction Stop
    return [pscustomobject]@{ ok=$true; status=[int]$resp.StatusCode; headers=$resp.Headers; location=$resp.Headers['Location'] }
  } catch {
    # Some servers block HEAD; try GET without downloading full content.
    try {
      $resp2 = Invoke-WebRequest -Uri $u -Method Get -MaximumRedirection 0 -UseBasicParsing -TimeoutSec 12 -ErrorAction Stop
      return [pscustomobject]@{ ok=$true; status=[int]$resp2.StatusCode; headers=$resp2.Headers; location=$resp2.Headers['Location'] }
    } catch {
      return [pscustomobject]@{ ok=$false; status=$null; headers=$null; location=$null; error=$_.Exception.Message }
    }
  }
}

function Get-TlsInfo([string]$host){
  # Best-effort: open a TLS handshake and read remote certificate.
  try {
    $client = New-Object System.Net.Sockets.TcpClient
    $client.ReceiveTimeout = 8000
    $client.SendTimeout = 8000
    $client.Connect($host, 443)

    $ssl = New-Object System.Net.Security.SslStream($client.GetStream(), $false, ({$true}))
    $ssl.ReadTimeout = 8000
    $ssl.WriteTimeout = 8000
    $ssl.AuthenticateAsClient($host)

    $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($ssl.RemoteCertificate)
    $ssl.Close(); $client.Close()

    return [pscustomobject]@{
      ok=$true
      subject=$cert2.Subject
      issuer=$cert2.Issuer
      notBefore=$cert2.NotBefore
      notAfter=$cert2.NotAfter
      thumbprint=$cert2.Thumbprint
      serial=$cert2.SerialNumber
    }
  } catch {
    try{ if($ssl){$ssl.Close()} } catch {}
    try{ if($client){$client.Close()} } catch {}
    return [pscustomobject]@{ ok=$false; error=$_.Exception.Message }
  }
}

function Whois-Query([string]$host){
  # WHOIS via TCP/43. Many environments block it; return best-effort.
  try {
    $q = $host
    $server = 'whois.iana.org'

    $first = Invoke-Whois -Server $server -Query $q
    if($first -and $first.refer){
      $second = Invoke-Whois -Server $first.refer -Query $q
      return [pscustomobject]@{ ok=$true; server=$first.refer; raw=$second.raw; country=$second.country; org=$second.org }
    }
    return [pscustomobject]@{ ok=$true; server=$server; raw=$first.raw; country=$first.country; org=$first.org }
  } catch {
    return [pscustomobject]@{ ok=$false; error=$_.Exception.Message }
  }
}

function Invoke-Whois([string]$Server, [string]$Query){
  $client = New-Object System.Net.Sockets.TcpClient
  $client.ReceiveTimeout = 9000
  $client.SendTimeout = 9000
  $client.Connect($Server, 43)
  $stream = $client.GetStream()
  $writer = New-Object System.IO.StreamWriter($stream)
  $writer.NewLine = "`r`n"
  $writer.WriteLine($Query)
  $writer.Flush()

  $reader = New-Object System.IO.StreamReader($stream)
  $raw = $reader.ReadToEnd()
  $reader.Close(); $writer.Close(); $stream.Close(); $client.Close()

  $refer = $null
  foreach($line in ($raw -split "`r?`n")){
    if($line -match '^refer:\s*(.+)$'){ $refer = $Matches[1].Trim(); break }
  }

  $country = $null
  $org = $null
  foreach($line in ($raw -split "`r?`n")){
    if(-not $country -and $line -match '^(country|Country):\s*(.+)$'){ $country = $Matches[2].Trim() }
    if(-not $org -and $line -match '^(org|OrgName|organization|descr|Organization):\s*(.+)$'){ $org = $Matches[2].Trim() }
  }

  return [pscustomobject]@{ raw=$raw; refer=$refer; country=$country; org=$org }
}

function Analyze-Url([string]$u){
  if([string]::IsNullOrWhiteSpace($u)){
    return $null
  }

  $o = $null
  try { $o = [uri]$u } catch { return [pscustomobject]@{ ok=$false; error='URL invalida.'; url=$u } }

  $host = $o.Host
  $ips = Resolve-Domain $host
  $head = Head-Url $u

  $redirects = @()
  $cur = $u
  for($i=0; $i -lt 8; $i++){
    $h = Head-Url $cur
    if(-not $h.ok){ break }
    $redirects += [pscustomobject]@{ url=$cur; status=$h.status; location=$h.location }
    if($h.status -ge 300 -and $h.status -lt 400 -and $h.location){
      try{
        $next = [uri]::new([uri]$cur, $h.location)
        $cur = $next.AbsoluteUri
        continue
      } catch { break }
    }
    break
  }

  $tls = $null
  if($o.Scheme -eq 'https'){
    $tls = Get-TlsInfo $host
  }

  $whois = Whois-Query $host

  return [pscustomobject]@{
    ok=$true
    url=$u
    scheme=$o.Scheme
    host=$host
    port=$o.Port
    path=$o.AbsolutePath
    ips=$ips
    headStatus=$head.status
    headError=$head.error
    redirects=$redirects
    tls=$tls
    whois=$whois
  }
}

function Compute-Risk([object]$urlInfo, [object[]]$artifacts, [object[]]$detections, [object]$defenderUpdate, [double]$sigAgeDays, [object]$behavior){
  $score = 0
  $reasons = New-Object System.Collections.Generic.List[string]
  $hasRedirects = $false
  $hasMotwUnsigned = $false
  $behaviorWeird = $false

  if($detections -and $detections.Count -gt 0){
    $score += 80
    $reasons.Add('Defender reporto detecciones en este run.')
  }

  if($defenderUpdate -and (-not $defenderUpdate.Ok)){
    $score += 15
    $reasons.Add('No se pudo actualizar firmas de Defender (posible falta de red o bloqueo).')
  }

  if($sigAgeDays -ne $null -and $sigAgeDays -gt 2){
    $score += 10
    $reasons.Add('Las firmas de Defender tienen mas de 48h.')
  }

  if($urlInfo -and $urlInfo.ok){
    if($urlInfo.scheme -ne 'https'){
      $score += 10
      $reasons.Add('La URL no usa HTTPS.')
    }

    $rCount = 0
    if($urlInfo.redirects){ $rCount = @($urlInfo.redirects | Where-Object { $_.status -ge 300 -and $_.status -lt 400 }).Count }
    if($rCount -ge 2){
      $score += 8
      $reasons.Add('La URL usa multiples redirecciones.')
      $hasRedirects = $true
    }

    if($urlInfo.tls -and $urlInfo.tls.ok){
      try{
        $daysLeft = ([datetime]$urlInfo.tls.notAfter - (Get-Date)).TotalDays
        if($daysLeft -lt 7){
          $score += 6
          $reasons.Add('El certificado TLS esta por expirar.')
        }
      } catch {}
    }

    if($urlInfo.whois -and $urlInfo.whois.ok){
      $org = ($urlInfo.whois.org + '')
      if([string]::IsNullOrWhiteSpace($org)){
        $score += 5
        $reasons.Add('WHOIS sin organizacion clara (dato incompleto).')
      }
    } else {
      $score += 3
      $reasons.Add('No se pudo resolver WHOIS (no concluyente).')
    }
  }

  if($artifacts){
    $exe = @($artifacts | Where-Object { $_.extension -in @('.exe','.msi','.scr','.js','.vbs','.ps1','.bat','.cmd','.lnk') })
    if($exe.Count -gt 0){
      $score += 10
      $reasons.Add('Se detectaron archivos ejecutables o scripts descargados durante la sesion.')
    }

    $unsigned = @($artifacts | Where-Object { $_.authenticode -and $_.authenticode.Status -in @('NotSigned','UnknownError') })
    if($unsigned.Count -gt 0){
      $score += 10
      $reasons.Add('Hay ejecutables o scripts sin firma valida.')
    }

    $motwPresent = @($artifacts | Where-Object { $_.motw -and $_.motw.Present })
    if($motwPresent.Count -gt 0 -and $unsigned.Count -gt 0){
      $hasMotwUnsigned = $true
      $reasons.Add('Archivos con MOTW y sin firma valida (senal combinada).')
    }

    $motwNone = @($artifacts | Where-Object { $_.motw -and (-not $_.motw.Present) })
    if($motwNone.Count -gt 0){
      $score += 5
      $reasons.Add('Algunos archivos no tienen Mark-of-the-Web (MOTW).')
    }
  }

  if($behavior -and $behavior.suspicious){
    $behaviorWeird = $true
    $score += 8
    $reasons.Add('Se observaron conexiones/procesos inusuales en la sesion.')
  }

  $strongSignals = $hasMotwUnsigned -and $hasRedirects -and $behaviorWeird
  if($strongSignals){
    $score += 12
    $reasons.Add('Senales fuertes: MOTW + sin firma + redirecciones + comportamiento inusual.')
  }

  if($score -gt 100){ $score = 100 }

  $level = if($score -ge 80){'ALTO'} elseif($score -ge 50){'MEDIO'} elseif($score -ge 25){'BAJO'} else {'MINIMO'}
  $decision = if($score -ge 80){
    'BLOQUEAR'
  } elseif($score -ge 50){
    'CAUTELA'
  } else {
    'OK'
  }

  return [pscustomobject]@{
    enabled=$true
    score=$score
    level=$level
    decision=$decision
    reasons=@($reasons)
    strongSignals=$strongSignals
    forceInconclusive=$strongSignals
    behaviorSummary=$behavior
  }
}

function Build-Artifact([string]$path, [string]$source){
  $name = Split-Path $path -Leaf
  $ext = ([System.IO.Path]::GetExtension($name) + '').ToLowerInvariant()

  $sha = Compute-Sha256 $path
  $motw = Read-MOTW $path
  $sig = $null
  # Only attempt Authenticode for PE/script types
  if($ext -in @('.exe','.dll','.msi','.sys','.ps1','.psm1','.vbs','.js','.cmd','.bat','.scr')){
    $sig = Get-AuthenticodeSummary $path
  }

  return [pscustomobject]@{
    source=$source
    fileName=$name
    extension=$ext
    fullPath=$path
    sha256=$sha
    motw=$motw
    authenticode=$sig
  }
}

function Write-ReportFiles([string]$runDir, [object]$report){
  $jsonPath = Join-Path $runDir 'report.json'
  $htmlPath = Join-Path $runDir 'report.html'
  $txtPath  = Join-Path $runDir 'report.txt'

  ($report | ConvertTo-Json -Depth 10) | Set-Content -LiteralPath $jsonPath -Encoding UTF8

  $statusText = $report.summary.status
  $badge = if($statusText -eq 'OK'){'#1f7a1f'} elseif($statusText -eq 'DETECTADO'){'#b00020'} else {'#b26a00'}

  $riskBadge = '#3a3a3a'
  $riskText = 'N/A'
  if($report.autoDecision -and $report.autoDecision.enabled){
    $riskText = "$($report.autoDecision.level) ($($report.autoDecision.score))"
    $riskBadge = if($report.autoDecision.level -eq 'ALTO'){'#b00020'} elseif($report.autoDecision.level -eq 'MEDIO'){'#b26a00'} elseif($report.autoDecision.level -eq 'BAJO'){'#2f6f98'} else {'#3a3a3a'}
  }

  $detRows = ''
  foreach($d in @($report.evidence.detections)){
    $res = ''
    try{ $res = ($d.Resources -join '<br>') } catch {}
    $detRows += "<tr><td><code>$(HtmlE $d.ThreatName)</code></td><td>$(HtmlE ($d.ThreatID+''))</td><td>$(HtmlE ($d.SeverityID+''))</td><td><small>$(HtmlE $res)</small></td></tr>"
  }
  if([string]::IsNullOrWhiteSpace($detRows)){
    $detRows = "<tr><td colspan='4' class='muted'>Sin detecciones de Defender registradas en este run.</td></tr>"
  }

  $artRows = ''
  foreach($a in @($report.artifacts.files)){
    $sigS = ''
    if($a.authenticode){ $sigS = $a.authenticode.Status }
    $motwS = if($a.motw -and $a.motw.Present){ "ZoneId=$($a.motw.ZoneId)" } else { 'sin MOTW' }
    $artRows += "<tr><td>$(HtmlE $a.source)</td><td>$(HtmlE $a.fileName)</td><td><code>$(HtmlE $a.sha256)</code></td><td>$(HtmlE $motwS)</td><td>$(HtmlE $sigS)</td></tr>"
  }
  if([string]::IsNullOrWhiteSpace($artRows)){
    $artRows = "<tr><td colspan='5' class='muted'>No se registraron archivos (entrada o descargas) para detallar.</td></tr>"
  }

  $redirRows = ''
  if($report.urlAnalysis -and $report.urlAnalysis.ok -and $report.urlAnalysis.redirects){
    foreach($r in @($report.urlAnalysis.redirects)){
      $redirRows += "<tr><td>$(HtmlE $r.status)</td><td><small>$(HtmlE $r.url)</small></td><td><small>$(HtmlE ($r.location+''))</small></td></tr>"
    }
  }
  if([string]::IsNullOrWhiteSpace($redirRows)){
    $redirRows = "<tr><td colspan='3' class='muted'>Sin datos de redirecciones.</td></tr>"
  }

  $reasonsHtml = ''
  if($report.autoDecision -and $report.autoDecision.enabled -and $report.autoDecision.reasons){
    foreach($rr in @($report.autoDecision.reasons)){
      $reasonsHtml += '<li>' + (HtmlE $rr) + '</li>'
    }
  } else {
    $reasonsHtml = '<li class="muted">AutoDecision deshabilitado o sin razones.</li>'
  }

  $inconcl = ''
  if($report.summary.inconclusiveReason){ $inconcl = "<p><b>Motivo Inconcluso:</b> $(HtmlE $report.summary.inconclusiveReason)</p>" }

  $html = @"
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>WinLab - Reporte</title>
  <style>
    body{font-family:Segoe UI,Arial,sans-serif;margin:24px;color:#111;background:#fff;}
    .wrap{max-width:1040px}
    .card{border:1px solid #ddd;border-radius:14px;padding:18px;background:#fff;}
    .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
    .badge{display:inline-block;padding:6px 10px;border-radius:999px;color:#fff;background:$badge;font-weight:700;letter-spacing:.2px}
    .risk{display:inline-block;padding:6px 10px;border-radius:999px;color:#fff;background:$riskBadge;font-weight:700;letter-spacing:.2px}
    .muted{color:#666}
    table{border-collapse:collapse;width:100%;margin-top:10px;font-size:14px}
    th,td{border:1px solid #e5e5e5;padding:8px;vertical-align:top}
    th{background:#fafafa;text-align:left}
    code{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
    .k{font-weight:700}
    .sec{margin-top:16px}
    .hr{height:1px;background:#eee;margin:16px 0}
    .small{font-size:13px}
    ul{margin:8px 0 0 18px}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="row">
        <h2 style="margin:0">WinLab - Reporte de analisis</h2>
        <span class="badge">$statusText</span>
        <span class="risk">Riesgo: $riskText</span>
      </div>
      <p class="muted small" style="margin-top:6px">Timestamp: $(HtmlE $report.meta.timestamp) Â· Preset: $(HtmlE $report.meta.preset) Â· Firewall: $(HtmlE $report.meta.firewallMode)</p>

      $inconcl

      <div class="grid sec">
        <div>
          <div class="k">Entrada principal</div>
          <div>Archivo: $(HtmlE $report.target.fileName)</div>
          <div class="muted"><code>$(HtmlE $report.target.sha256)</code></div>
          <div class="muted small">MOTW: $(HtmlE ($report.target.motwSummary+''))</div>
          <div class="muted small">Firma: $(HtmlE ($report.target.signatureSummary+''))</div>
        </div>
        <div>
          <div class="k">Defender</div>
          <div class="muted small">Engine: $(HtmlE ($report.defender.engineVersion+'')) Â· Sig: $(HtmlE ($report.defender.antivirusSignatureVersion+''))</div>
          <div class="muted small">Sig updated: $(HtmlE ($report.defender.antivirusSignatureLastUpdated+'')) (age: $(HtmlE ($report.defender.signatureAgeDays+'')) dias)</div>
          <div class="muted small">Update: $(HtmlE ($report.defender.update.Method+'')) Â· ok=$(HtmlE ($report.defender.update.Ok+''))</div>
          <div class="muted small">Duracion: update $(HtmlE ($report.timing.updateDurationMs+'')) ms Â· scans $(HtmlE ($report.timing.totalScanDurationMs+'')) ms</div>
        </div>
      </div>

      <div class="hr"></div>

      <div class="sec">
        <div class="k">AutoDecision (heuristica)</div>
        <ul>
          $reasonsHtml
        </ul>
        <p class="small"><b>Decision sugerida:</b> $(HtmlE ($report.autoDecision.decision+'')) Â· <b>Recomendacion:</b> $(HtmlE $report.summary.recommendation)</p>
      </div>

      <div class="sec">
        <div class="k">URL / servidor (si aplica)</div>
        <p class="small muted">URL: <code>$(HtmlE ($report.urlAnalysis.url+''))</code></p>
        <div class="grid">
          <div>
            <div class="small"><b>Host:</b> $(HtmlE ($report.urlAnalysis.host+''))</div>
            <div class="small"><b>IPs:</b> $(HtmlE (($report.urlAnalysis.ips -join ', ')+''))</div>
            <div class="small"><b>Status:</b> $(HtmlE ($report.urlAnalysis.headStatus+''))</div>
          </div>
          <div>
            <div class="small"><b>TLS:</b> $(HtmlE ($report.urlAnalysis.tls.subject+''))</div>
            <div class="small"><b>Issuer:</b> $(HtmlE ($report.urlAnalysis.tls.issuer+''))</div>
            <div class="small"><b>NotAfter:</b> $(HtmlE ($report.urlAnalysis.tls.notAfter+''))</div>
          </div>
        </div>

        <table>
          <thead><tr><th>Status</th><th>URL</th><th>Location</th></tr></thead>
          <tbody>$redirRows</tbody>
        </table>
      </div>

      <div class="sec">
        <div class="k">Archivos observados (entrada + descargas)</div>
        <table>
          <thead><tr><th>Origen</th><th>Archivo</th><th>SHA256</th><th>MOTW</th><th>Firma</th></tr></thead>
          <tbody>$artRows</tbody>
        </table>
      </div>

      <div class="sec">
        <div class="k">Evidencias (Defender)</div>
        <table>
          <thead><tr><th>ThreatName</th><th>ID</th><th>Severity</th><th>Resources</th></tr></thead>
          <tbody>$detRows</tbody>
        </table>
      </div>

      <div class="sec">
        <div class="k">Notas</div>
        <p class="small">Esto no es magia: WinLab no es un "antivirus propio". El motor de deteccion es Microsoft Defender; WinLab agrega aislamiento (Windows Sandbox), un pipeline repetible y un reporte legible.</p>
        <p class="small muted">"INCONCLUSO" suele significar: firmas viejas, no se pudo actualizar, timeout, archivo protegido o la URL no se pudo analizar sin red. En ese caso: reintentar en Balanced (con Internet) y/o validar por otra via.</p>
      </div>

    </div>
  </div>
</body>
</html>
"@

  $html | Set-Content -LiteralPath $htmlPath -Encoding UTF8

  $txt = @()
  $txt += 'WinLab - Reporte'
  $txt += "Estado: $($report.summary.status)"
  if($report.autoDecision -and $report.autoDecision.enabled){
    $txt += "Riesgo: $($report.autoDecision.level) ($($report.autoDecision.score)) / Decision: $($report.autoDecision.decision)"
  }
  $txt += "Archivo: $($report.target.fileName)"
  $txt += "SHA256: $($report.target.sha256)"
  $txt += "Preset: $($report.meta.preset) / Firewall: $($report.meta.firewallMode)"
  $txt += "Firmas: $($report.defender.antivirusSignatureVersion) (LastUpdated $($report.defender.antivirusSignatureLastUpdated))"
  if($report.urlAnalysis -and $report.urlAnalysis.ok){ $txt += "URL: $($report.urlAnalysis.url)" }
  if($report.summary.inconclusiveReason){ $txt += "Inconcluso: $($report.summary.inconclusiveReason)" }
  $txt += "Recomendacion: $($report.summary.recommendation)"
  ($txt -join "`r`n") | Set-Content -LiteralPath $txtPath -Encoding UTF8
}

# =====================
# Main
# =====================
$schemaVersion = '1.0'
$startTime = Get-Date
$deadline = $startTime.AddMinutes([math]::Max(1,$Minutes))

Apply-Firewall $FirewallMode

$outRoot = Ensure-OutDir -enable $EnableOutbox -outFolder $OutFolder
$runId = 'run_' + (NowStamp) + '_' + (SafeFileName $Preset)
$runDir = Join-Path $outRoot $runId
Ensure-Dir $runDir

Log "Preset: $Preset"
Log "OutFolder: $outRoot"

# Optional: capture deltas
$proc0 = @(); $net0 = @()
if($CollectDeltas -eq 1){
  $proc0 = Get-ProcSnapshot
  $net0 = Get-NetSnapshot
}

# Defender update/status
$update = Try-UpdateDefenderSignatures
$defStatus = Get-DefenderStatus
$sigAge = Get-SignatureAgeDays $defStatus

# Artifacts list
$artifacts = New-Object System.Collections.Generic.List[object]
$scanRuns = New-Object System.Collections.Generic.List[object]

# Scan host-mapped inbox file (if any)
$inconclusiveReason = $null
$target = $null
$targetCopy = $null

try{
  $target = Pick-InputFile -folder $InputFolder -targetName $TargetFileName
} catch { $target = $null }

$primaryTargetMeta = [pscustomobject]@{ fileName=$null; sourcePath=$null; sandboxCopyPath=$null; sha256=$null; motwSummary=$null; signatureSummary=$null }

if($target){
  try{
    Log "Entrada (host-mapped): $($target.FullName)"
    $targetCopy = Copy-ToWork $target.FullName
    $a = Build-Artifact -path $targetCopy -source 'host_mapped'
    $artifacts.Add($a)

    $primaryTargetMeta.fileName = $target.Name
    $primaryTargetMeta.sourcePath = $target.FullName
    $primaryTargetMeta.sandboxCopyPath = $targetCopy
    $primaryTargetMeta.sha256 = $a.sha256
    $primaryTargetMeta.motwSummary = if($a.motw.Present){ "ZoneId=$($a.motw.ZoneId)" } else { 'sin MOTW' }
    $primaryTargetMeta.signatureSummary = if($a.authenticode){ $a.authenticode.Status } else { 'N/A' }

    $sw = Start-CustomScan $targetCopy
    $scanRuns.Add([pscustomobject]@{ kind='file'; path=$targetCopy; ok=$sw.Ok; error=$sw.Error; durationMs=$sw.DurationMs })
  } catch {
    $inconclusiveReason = 'No pude copiar/escaneaar el archivo de entrada (posible bloqueo o permisos).'
  }
} else {
  Log 'No se encontro archivo en inbox (host Downloads).'
}

# If URL provided: analyze + open Edge session
$urlInfo = $null
$openedUrl = $false

if(-not [string]::IsNullOrWhiteSpace($Url)){
  Log "URL solicitada: $Url"
  try{
    $urlInfo = Analyze-Url $Url
  } catch {
    $urlInfo = [pscustomobject]@{ ok=$false; url=$Url; error=$_.Exception.Message }
  }

  # Open Edge only if Networking is not disabled (or firewall not BlockAll)
  if($FirewallMode -ne 'BlockAll'){
    try{
      $edge = Join-Path $env:ProgramFiles 'Microsoft\\Edge\\Application\\msedge.exe'
      if(-not (Test-Path $edge)){
        $edge = 'msedge.exe'
      }
      Start-Process -FilePath $edge -ArgumentList @('--inprivate', $Url) | Out-Null
      $openedUrl = $true
      Log 'Edge lanzado (InPrivate).'
    } catch {
      Log "No pude lanzar Edge: $($_.Exception.Message)"
    }
  } else {
    $inconclusiveReason = if($inconclusiveReason){ $inconclusiveReason } else { 'Preset sin red: no se puede analizar/visitar URL.' }
  }
}

# Monitor sandbox downloads for the duration of the session (best-effort)
$dlDir = Join-Path $env:USERPROFILE 'Downloads'
$known = @{}
try{
  if(Test-Path $dlDir){
    Get-ChildItem -LiteralPath $dlDir -File -ErrorAction SilentlyContinue | ForEach-Object { $known[$_.FullName] = $_.LastWriteTimeUtc.Ticks }
  }
} catch {}

function Scan-NewDownloads {
  param([datetime]$since)
  if(-not (Test-Path $dlDir)){ return }

  $files = Get-ChildItem -LiteralPath $dlDir -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension.ToLowerInvariant() -notin @('.crdownload','.tmp','.part') } |
    Sort-Object LastWriteTime -Descending

  foreach($f in $files){
    $k = $f.FullName
    $tick = $f.LastWriteTimeUtc.Ticks
    if($known.ContainsKey($k) -and $known[$k] -eq $tick){
      continue
    }

    # Wait for file to stabilize (size stops changing)
    $stable = $false
    $last = -1
    for($i=0; $i -lt 8; $i++){
      try{
        $len = (Get-Item -LiteralPath $k -ErrorAction Stop).Length
        if($len -gt 0 -and $len -eq $last){ $stable = $true; break }
        $last = $len
      } catch {}
      Start-Sleep -Milliseconds 400
    }

    $known[$k] = $tick

    if(-not $stable){
      Log "Descarga detectada pero no estable: $($f.Name)"
      continue
    }

    try{
      Log "Descarga detectada: $($f.Name)"
      $a = Build-Artifact -path $k -source 'sandbox_download'
      $artifacts.Add($a)

      $sw = Start-CustomScan $k
      $scanRuns.Add([pscustomobject]@{ kind='download'; path=$k; ok=$sw.Ok; error=$sw.Error; durationMs=$sw.DurationMs })
    } catch {
      Log "No pude escanear descarga: $($_.Exception.Message)"
    }
  }
}

while((Get-Date) -lt $deadline){
  try{ Scan-NewDownloads -since $startTime } catch {}
  Start-Sleep -Seconds 2
}

# Collect defender detections
$detections = Get-ThreatDetections -since $startTime.AddMinutes(-5)

# Compute deltas
$proc1 = @(); $net1 = @()
if($CollectDeltas -eq 1){
  $proc1 = Get-ProcSnapshot
  $net1 = Get-NetSnapshot
}

$behaviorSummary = $null
if($CollectDeltas -eq 1){
  $behaviorSummary = Get-BehaviorSignals -proc0 $proc0 -proc1 $proc1 -net0 $net0 -net1 $net1
} else {
  $behaviorSummary = [pscustomobject]@{ newProcessCount=0; newConnectionCount=0; suspiciousPorts=@(); suspicious=$false }
}

# Determine status
$statusText = 'INCONCLUSO'

if($detections.Count -gt 0){
  $statusText = 'DETECTADO'
} else {
  # If we scanned at least one file and update is OK or sig age is reasonable -> OK
  $scanOkAny = (@($scanRuns) | Where-Object { $_.ok -eq $true }).Count -gt 0
  if($scanOkAny){
    if($update.Ok -or ($sigAge -ne $null -and $sigAge -le 2)){
      $statusText = 'OK'
    } else {
      $statusText = 'INCONCLUSO'
      if(-not $inconclusiveReason){
        $inconclusiveReason = 'No se pudo actualizar firmas y las definiciones parecen viejas; el resultado puede no ser confiable.'
      }
    }
  } else {
    # No scan executed
    if(-not $inconclusiveReason){
      $inconclusiveReason = 'No se ejecuto un escaneo (sin archivo de entrada o sin descargas estables).'
    }
    $statusText = 'INCONCLUSO'
  }
}

# AutoDecision
$auto = $null
if($AutoDecisionEnabled -eq 1){
  $auto = Compute-Risk -urlInfo $urlInfo -artifacts @($artifacts) -detections @($detections) -defenderUpdate $update -sigAgeDays $sigAge -behavior $behaviorSummary
} else {
  $auto = [pscustomobject]@{ enabled=$false }
}

if($statusText -eq 'OK' -and $auto -and $auto.forceInconclusive){
  $statusText = 'INCONCLUSO'
  if(-not $inconclusiveReason){
    $inconclusiveReason = 'AutoDecision detecto senales fuertes (MOTW + sin firma + redirecciones + comportamiento inusual). Tratalo como no confiable.'
  }
}

$statusMeaning = switch($statusText){
  'DETECTADO' { 'Defender detecto una amenaza en este run. Evita ejecutar el archivo.' }
  'OK'        { 'No se detectaron amenazas en este run. No es una garantia de seguridad.' }
  default     { 'Resultado no confiable o con senales fuertes. Reintenta y valida por otra via.' }
}

# Recommendation
$recommendation = switch($statusText){
  'DETECTADO' { 'No ejecutes ni abras el archivo. Eliminalo o aislarlo. Si fue recibido por trabajo/banco, reportalo a IT/Seguridad.' }
  'OK'        { 'No se detectaron amenazas en este run. Igual, si el origen es dudoso, mantenelo aislado y evita habilitar macros o ejecutar instaladores.' }
  default     { 'Resultado inconcluso. Reintenta en Balanced (con Internet) para actualizar firmas y repetir el analisis. Para URLs, usa Networked/InternetOnly y evita iniciar sesion o ingresar datos.' }
}

# Total scan duration
$totalScan = 0
try{ $totalScan = (@($scanRuns) | Measure-Object -Property durationMs -Sum).Sum } catch { $totalScan = 0 }

# Minimal summaries for primary target
$motwSummary = $primaryTargetMeta.motwSummary
$sigSummary = $primaryTargetMeta.signatureSummary
$endTime = Get-Date

$report = [pscustomobject]@{
  schemaVersion = $schemaVersion
  meta = [pscustomobject]@{
    runId = $runId
    timestamp = $endTime.ToString('o')
    preset = $Preset
    firewallMode = $FirewallMode
    enableOutbox = [bool]($EnableOutbox -eq 1)
    sandbox = 'Windows Sandbox'
    openedUrl = [bool]$openedUrl
  }
  target = [pscustomobject]@{
    fileName = $primaryTargetMeta.fileName
    sourcePath = $primaryTargetMeta.sourcePath
    sandboxCopyPath = $primaryTargetMeta.sandboxCopyPath
    sha256 = $primaryTargetMeta.sha256
    motwSummary = $motwSummary
    signatureSummary = $sigSummary
  }
  urlAnalysis = $urlInfo
  defender = [pscustomobject]@{
    antivirusSignatureVersion = if($defStatus){ $defStatus.AntivirusSignatureVersion } else { $null }
    antivirusSignatureLastUpdated = if($defStatus){ $defStatus.AntivirusSignatureLastUpdated } else { $null }
    signatureAgeDays = $sigAge
    engineVersion = if($defStatus){ $defStatus.EngineVersion } else { $null }
    serviceVersion = if($defStatus){ $defStatus.ServiceVersion } else { $null }
    update = $update
  }
  timing = [pscustomobject]@{
    startedAt = $startTime.ToString('o')
    endedAt = $endTime.ToString('o')
    updateDurationMs = $update.DurationMs
    totalScanDurationMs = [int]$totalScan
    minutes = $Minutes
  }
  artifacts = [pscustomobject]@{
    files = @($artifacts)
    scans = @($scanRuns)
  }
  evidence = [pscustomobject]@{
    detections = @($detections)
  }
  telemetry = [pscustomobject]@{
    processBaseline = if($CollectDeltas -eq 1){ $proc0 } else { $null }
    processFinal = if($CollectDeltas -eq 1){ $proc1 } else { $null }
    netBaseline = if($CollectDeltas -eq 1){ $net0 } else { $null }
    netFinal = if($CollectDeltas -eq 1){ $net1 } else { $null }
  }
  autoDecision = $auto
  summary = [pscustomobject]@{
    status = $statusText
    meaning = $statusMeaning
    inconclusiveReason = $inconclusiveReason
    recommendation = $recommendation
  }
}

Write-ReportFiles -runDir $runDir -report $report
Log "Reporte generado: $runDir"

# Close Sandbox
Log 'Tiempo cumplido. Cerrando Sandbox...'
try { shutdown.exe /s /t 0 } catch {}
.ok -eq $true }).Count
  $scanSummary = if($scanCount -gt 0){ "$scanOk/$scanCount ok" } else { 'sin escaneos' }

  $autoForce = ''
  if($report.autoDecision -and $report.autoDecision.forceInconclusive){
    $autoForce = '<div class="alert warn">AutoDecision forzo INCONCLUSO por senales fuertes.</div>'
  }

  $behaviorLine = ''
  if($report.autoDecision -and $report.autoDecision.behaviorSummary){
    $b = $report.autoDecision.behaviorSummary
    $ports = 'n/a'
    if($b.suspiciousPorts -and @($b.suspiciousPorts).Count -gt 0){ $ports = ($b.suspiciousPorts -join ', ') }
    $behaviorLine = "<div class=\"small muted\">Procesos nuevos: $($b.newProcessCount) · Conexiones nuevas: $($b.newConnectionCount) · Puertos: $(HtmlE $ports)</div>"
  }

  $legendHtml = @"
<ul class="legend">
  <li><b>OK:</b> Sin detecciones de Defender en este run. No garantiza inocuidad.</li>
  <li><b>DETECTADO:</b> Defender encontro una amenaza en el entorno.</li>
  <li><b>INCONCLUSO:</b> Resultado no confiable o con senales fuertes. Reintentar/validar.</li>
</ul>
"@

  $urlSection = ''
  if($report.urlAnalysis -and $report.urlAnalysis.ok){
    $urlSection = @"
<section class="card">
  <h2>Analisis de URL</h2>
  <div class="grid">
    <div>
      <div class="small"><b>URL:</b> $(HtmlE ($report.urlAnalysis.url+''))</div>
      <div class="small"><b>Host:</b> $(HtmlE ($report.urlAnalysis.host+''))</div>
      <div class="small"><b>IPs:</b> $(HtmlE (($report.urlAnalysis.ips -join ', ')+''))</div>
      <div class="small"><b>Status:</b> $(HtmlE ($report.urlAnalysis.headStatus+''))</div>
    </div>
    <div>
      <div class="small"><b>TLS:</b> $(HtmlE ($report.urlAnalysis.tls.subject+''))</div>
      <div class="small"><b>Issuer:</b> $(HtmlE ($report.urlAnalysis.tls.issuer+''))</div>
      <div class="small"><b>NotAfter:</b> $(HtmlE ($report.urlAnalysis.tls.notAfter+''))</div>
    </div>
  </div>
  <table>
    <thead><tr><th>Status</th><th>URL</th><th>Location</th></tr></thead>
    <tbody>$redirRows</tbody>
  </table>
</section>
"@
  } elseif($report.urlAnalysis -and $report.urlAnalysis.url){
    $urlSection = "<section class=\"card\"><h2>Analisis de URL</h2><p class=\"muted\">No disponible: $(HtmlE ($report.urlAnalysis.error+''))</p></section>"
  }

  $html = @"
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>WinLab - Reporte</title>
  <style>
    :root{--bg:#f6f7fb;--card:#fff;--text:#111827;--muted:#4b5563;--line:#e5e7eb;--ok:#1f7a1f;--warn:#b26a00;--bad:#b00020}
    body{font-family:Segoe UI,Arial,sans-serif;margin:0;padding:24px;color:var(--text);background:var(--bg);}
    .wrap{max-width:1080px;margin:0 auto;}
    .header{display:flex;gap:12px;align-items:flex-start;justify-content:space-between;margin-bottom:12px;}
    .badge{display:inline-block;padding:8px 12px;border-radius:999px;color:#fff;background:$badge;font-weight:700;letter-spacing:.2px}
    .risk{display:inline-block;padding:6px 10px;border-radius:999px;color:#fff;background:$riskBadge;font-weight:700;letter-spacing:.2px}
    .card{border:1px solid var(--line);border-radius:16px;padding:16px;background:var(--card);margin-bottom:12px;}
    .grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
    .k{font-weight:700;margin-bottom:6px;}
    .lead{margin:6px 0 10px 0;color:var(--muted);line-height:1.5;}
    .muted{color:var(--muted);}
    .small{font-size:13px;}
    table{border-collapse:collapse;width:100%;margin-top:8px;font-size:13.5px}
    th,td{border:1px solid var(--line);padding:8px;vertical-align:top}
    th{background:#f9fafb;text-align:left}
    code{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}
    .alert{margin:8px 0;padding:10px 12px;border-radius:12px;background:#fff7ed;border:1px solid #fed7aa;color:#9a3412;}
    .alert.warn{background:#fff7ed;border-color:#fed7aa;color:#9a3412;}
    .legend{margin:0;padding-left:18px;color:var(--muted);}
    .timeline{margin:0;padding-left:18px;color:var(--muted);}
    @media (max-width: 900px){
      .grid{grid-template-columns:1fr;}
      .header{flex-direction:column;align-items:flex-start;}
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <div>
        <h1 style="margin:0;">WinLab - Reporte</h1>
        <div class="small muted">Run: $(HtmlE ($report.meta.runId+'')) · Preset: $(HtmlE ($report.meta.preset+'')) · Firewall: $(HtmlE ($report.meta.firewallMode+'')) · $(HtmlE ($report.meta.timestamp+''))</div>
      </div>
      <div class="badge">$statusText</div>
    </div>

    <section class="card">
      <h2 style="margin-top:0;">Resumen ejecutivo</h2>
      <p class="lead">$(HtmlE ($meaning+''))</p>
      $inconcl
      $autoForce
      <div class="grid">
        <div>
          <div class="k">Recomendacion</div>
          <div>$(HtmlE ($report.summary.recommendation+''))</div>
        </div>
        <div>
          <div class="k">AutoDecision</div>
          <div class="risk">Riesgo: $riskText</div>
          $behaviorLine
          <ul>$reasonsHtml</ul>
        </div>
      </div>
    </section>

    <section class="card">
      <h2 style="margin-top:0;">Que significa</h2>
      $legendHtml
    </section>

    <section class="card">
      <h2 style="margin-top:0;">Entrada principal</h2>
      <div class="grid">
        <div>
          <div class="small"><b>Archivo:</b> $(HtmlE ($report.target.fileName+''))</div>
          <div class="small"><b>SHA-256:</b> <code>$(HtmlE ($report.target.sha256+''))</code></div>
          <div class="small"><b>MOTW:</b> $(HtmlE ($report.target.motwSummary+''))</div>
          <div class="small"><b>Firma:</b> $(HtmlE ($report.target.signatureSummary+''))</div>
        </div>
        <div>
          <div class="small"><b>Engine:</b> $(HtmlE ($report.defender.engineVersion+''))</div>
          <div class="small"><b>Sig:</b> $(HtmlE ($report.defender.antivirusSignatureVersion+''))</div>
          <div class="small"><b>Sig age:</b> $(HtmlE ($report.defender.signatureAgeDays+'')) dias</div>
          <div class="small"><b>Update:</b> $(HtmlE ($report.defender.update.Method+'')) · ok=$(HtmlE ($report.defender.update.Ok+''))</div>
        </div>
      </div>
    </section>

    <section class="card">
      <h2 style="margin-top:0;">Timeline</h2>
      <ul class="timeline">
        <li><b>Inicio:</b> $(HtmlE ($report.timing.startedAt+''))</li>
        <li><b>Update firmas:</b> $(HtmlE ($report.defender.update.Method+'')) · ok=$(HtmlE ($report.defender.update.Ok+'')) · $(HtmlE ($report.timing.updateDurationMs+'')) ms</li>
        <li><b>Escaneos:</b> $scanSummary · total $(HtmlE ($report.timing.totalScanDurationMs+'')) ms</li>
        <li><b>Fin:</b> $(HtmlE ($report.timing.endedAt+''))</li>
      </ul>
    </section>

    <section class="card">
      <h2 style="margin-top:0;">Archivos observados</h2>
      <table>
        <thead><tr><th>Origen</th><th>Archivo</th><th>SHA256</th><th>MOTW</th><th>Firma</th></tr></thead>
        <tbody>$artRows</tbody>
      </table>
    </section>

    <section class="card">
      <h2 style="margin-top:0;">Evidencias (Defender)</h2>
      <table>
        <thead><tr><th>ThreatName</th><th>ID</th><th>Severity</th><th>Resources</th></tr></thead>
        <tbody>$detRows</tbody>
      </table>
    </section>

    $urlSection

    <section class="card">
      <h2 style="margin-top:0;">Notas y limitaciones</h2>
      <p class="small">WinLab no es un antivirus propio: usa Microsoft Defender dentro de Windows Sandbox. El objetivo es reducir riesgo, no eliminarlo.</p>
      <p class="small muted">Los archivos se copian desde una carpeta mapeada ReadOnly hacia una carpeta interna antes de escanear. No se modifica el host.</p>
    </section>
  </div>
</body>
</html>
"@

  $html | Set-Content -LiteralPath $htmlPath -Encoding UTF8

  $txt = @()
  $txt += 'WinLab - Reporte'
  $txt += "Estado: $($report.summary.status)"
  $txt += "Significado: $($report.summary.meaning)"
  if($report.autoDecision -and $report.autoDecision.enabled){
    $txt += "Riesgo: $($report.autoDecision.level) ($($report.autoDecision.score)) / Decision: $($report.autoDecision.decision)"
  }
  $txt += "Archivo: $($report.target.fileName)"
  $txt += "SHA256: $($report.target.sha256)"
  $txt += "Preset: $($report.meta.preset) / Firewall: $($report.meta.firewallMode)"
  $txt += "Firmas: $($report.defender.antivirusSignatureVersion) (LastUpdated $($report.defender.antivirusSignatureLastUpdated))"
  if($report.urlAnalysis -and $report.urlAnalysis.ok){ $txt += "URL: $($report.urlAnalysis.url)" }
  if($report.summary.inconclusiveReason){ $txt += "Inconcluso: $($report.summary.inconclusiveReason)" }
  $txt += "Recomendacion: $($report.summary.recommendation)"
  ($txt -join "`r`n") | Set-Content -LiteralPath $txtPath -Encoding UTF8
}

# =====================
# Main
# =====================
$schemaVersion = '1.0'
$startTime = Get-Date
$deadline = $startTime.AddMinutes([math]::Max(1,$Minutes))

Apply-Firewall $FirewallMode

$outRoot = Ensure-OutDir -enable $EnableOutbox -outFolder $OutFolder
$runId = 'run_' + (NowStamp) + '_' + (SafeFileName $Preset)
$runDir = Join-Path $outRoot $runId
Ensure-Dir $runDir

Log "Preset: $Preset"
Log "OutFolder: $outRoot"

# Optional: capture deltas
$proc0 = @(); $net0 = @()
if($CollectDeltas -eq 1){
  $proc0 = Get-ProcSnapshot
  $net0 = Get-NetSnapshot
}

# Defender update/status
$update = Try-UpdateDefenderSignatures
$defStatus = Get-DefenderStatus
$sigAge = Get-SignatureAgeDays $defStatus

# Artifacts list
$artifacts = New-Object System.Collections.Generic.List[object]
$scanRuns = New-Object System.Collections.Generic.List[object]

# Scan host-mapped inbox file (if any)
$inconclusiveReason = $null
$target = $null
$targetCopy = $null

try{
  $target = Pick-InputFile -folder $InputFolder -targetName $TargetFileName
} catch { $target = $null }

$primaryTargetMeta = [pscustomobject]@{ fileName=$null; sourcePath=$null; sandboxCopyPath=$null; sha256=$null; motwSummary=$null; signatureSummary=$null }

if($target){
  try{
    Log "Entrada (host-mapped): $($target.FullName)"
    $targetCopy = Copy-ToWork $target.FullName
    $a = Build-Artifact -path $targetCopy -source 'host_mapped'
    $artifacts.Add($a)

    $primaryTargetMeta.fileName = $target.Name
    $primaryTargetMeta.sourcePath = $target.FullName
    $primaryTargetMeta.sandboxCopyPath = $targetCopy
    $primaryTargetMeta.sha256 = $a.sha256
    $primaryTargetMeta.motwSummary = if($a.motw.Present){ "ZoneId=$($a.motw.ZoneId)" } else { 'sin MOTW' }
    $primaryTargetMeta.signatureSummary = if($a.authenticode){ $a.authenticode.Status } else { 'N/A' }

    $sw = Start-CustomScan $targetCopy
    $scanRuns.Add([pscustomobject]@{ kind='file'; path=$targetCopy; ok=$sw.Ok; error=$sw.Error; durationMs=$sw.DurationMs })
  } catch {
    $inconclusiveReason = 'No pude copiar/escaneaar el archivo de entrada (posible bloqueo o permisos).'
  }
} else {
  Log 'No se encontro archivo en inbox (host Downloads).'
}

# If URL provided: analyze + open Edge session
$urlInfo = $null
$openedUrl = $false

if(-not [string]::IsNullOrWhiteSpace($Url)){
  Log "URL solicitada: $Url"
  try{
    $urlInfo = Analyze-Url $Url
  } catch {
    $urlInfo = [pscustomobject]@{ ok=$false; url=$Url; error=$_.Exception.Message }
  }

  # Open Edge only if Networking is not disabled (or firewall not BlockAll)
  if($FirewallMode -ne 'BlockAll'){
    try{
      $edge = Join-Path $env:ProgramFiles 'Microsoft\\Edge\\Application\\msedge.exe'
      if(-not (Test-Path $edge)){
        $edge = 'msedge.exe'
      }
      Start-Process -FilePath $edge -ArgumentList @('--inprivate', $Url) | Out-Null
      $openedUrl = $true
      Log 'Edge lanzado (InPrivate).'
    } catch {
      Log "No pude lanzar Edge: $($_.Exception.Message)"
    }
  } else {
    $inconclusiveReason = if($inconclusiveReason){ $inconclusiveReason } else { 'Preset sin red: no se puede analizar/visitar URL.' }
  }
}

# Monitor sandbox downloads for the duration of the session (best-effort)
$dlDir = Join-Path $env:USERPROFILE 'Downloads'
$known = @{}
try{
  if(Test-Path $dlDir){
    Get-ChildItem -LiteralPath $dlDir -File -ErrorAction SilentlyContinue | ForEach-Object { $known[$_.FullName] = $_.LastWriteTimeUtc.Ticks }
  }
} catch {}

function Scan-NewDownloads {
  param([datetime]$since)
  if(-not (Test-Path $dlDir)){ return }

  $files = Get-ChildItem -LiteralPath $dlDir -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension.ToLowerInvariant() -notin @('.crdownload','.tmp','.part') } |
    Sort-Object LastWriteTime -Descending

  foreach($f in $files){
    $k = $f.FullName
    $tick = $f.LastWriteTimeUtc.Ticks
    if($known.ContainsKey($k) -and $known[$k] -eq $tick){
      continue
    }

    # Wait for file to stabilize (size stops changing)
    $stable = $false
    $last = -1
    for($i=0; $i -lt 8; $i++){
      try{
        $len = (Get-Item -LiteralPath $k -ErrorAction Stop).Length
        if($len -gt 0 -and $len -eq $last){ $stable = $true; break }
        $last = $len
      } catch {}
      Start-Sleep -Milliseconds 400
    }

    $known[$k] = $tick

    if(-not $stable){
      Log "Descarga detectada pero no estable: $($f.Name)"
      continue
    }

    try{
      Log "Descarga detectada: $($f.Name)"
      $a = Build-Artifact -path $k -source 'sandbox_download'
      $artifacts.Add($a)

      $sw = Start-CustomScan $k
      $scanRuns.Add([pscustomobject]@{ kind='download'; path=$k; ok=$sw.Ok; error=$sw.Error; durationMs=$sw.DurationMs })
    } catch {
      Log "No pude escanear descarga: $($_.Exception.Message)"
    }
  }
}

while((Get-Date) -lt $deadline){
  try{ Scan-NewDownloads -since $startTime } catch {}
  Start-Sleep -Seconds 2
}

# Collect defender detections
$detections = Get-ThreatDetections -since $startTime.AddMinutes(-5)

# Compute deltas
$proc1 = @(); $net1 = @()
if($CollectDeltas -eq 1){
  $proc1 = Get-ProcSnapshot
  $net1 = Get-NetSnapshot
}

$behaviorSummary = $null
if($CollectDeltas -eq 1){
  $behaviorSummary = Get-BehaviorSignals -proc0 $proc0 -proc1 $proc1 -net0 $net0 -net1 $net1
} else {
  $behaviorSummary = [pscustomobject]@{ newProcessCount=0; newConnectionCount=0; suspiciousPorts=@(); suspicious=$false }
}

# Determine status
$statusText = 'INCONCLUSO'

if($detections.Count -gt 0){
  $statusText = 'DETECTADO'
} else {
  # If we scanned at least one file and update is OK or sig age is reasonable -> OK
  $scanOkAny = (@($scanRuns) | Where-Object { $_.ok -eq $true }).Count -gt 0
  if($scanOkAny){
    if($update.Ok -or ($sigAge -ne $null -and $sigAge -le 2)){
      $statusText = 'OK'
    } else {
      $statusText = 'INCONCLUSO'
      if(-not $inconclusiveReason){
        $inconclusiveReason = 'No se pudo actualizar firmas y las definiciones parecen viejas; el resultado puede no ser confiable.'
      }
    }
  } else {
    # No scan executed
    if(-not $inconclusiveReason){
      $inconclusiveReason = 'No se ejecuto un escaneo (sin archivo de entrada o sin descargas estables).'
    }
    $statusText = 'INCONCLUSO'
  }
}

# AutoDecision
$auto = $null
if($AutoDecisionEnabled -eq 1){
  $auto = Compute-Risk -urlInfo $urlInfo -artifacts @($artifacts) -detections @($detections) -defenderUpdate $update -sigAgeDays $sigAge -behavior $behaviorSummary
} else {
  $auto = [pscustomobject]@{ enabled=$false }
}

if($statusText -eq 'OK' -and $auto -and $auto.forceInconclusive){
  $statusText = 'INCONCLUSO'
  if(-not $inconclusiveReason){
    $inconclusiveReason = 'AutoDecision detecto senales fuertes (MOTW + sin firma + redirecciones + comportamiento inusual). Tratalo como no confiable.'
  }
}

$statusMeaning = switch($statusText){
  'DETECTADO' { 'Defender detecto una amenaza en este run. Evita ejecutar el archivo.' }
  'OK'        { 'No se detectaron amenazas en este run. No es una garantia de seguridad.' }
  default     { 'Resultado no confiable o con senales fuertes. Reintenta y valida por otra via.' }
}

# Recommendation
$recommendation = switch($statusText){
  'DETECTADO' { 'No ejecutes ni abras el archivo. Eliminalo o aislarlo. Si fue recibido por trabajo/banco, reportalo a IT/Seguridad.' }
  'OK'        { 'No se detectaron amenazas en este run. Igual, si el origen es dudoso, mantenelo aislado y evita habilitar macros o ejecutar instaladores.' }
  default     { 'Resultado inconcluso. Reintenta en Balanced (con Internet) para actualizar firmas y repetir el analisis. Para URLs, usa Networked/InternetOnly y evita iniciar sesion o ingresar datos.' }
}

# Total scan duration
$totalScan = 0
try{ $totalScan = (@($scanRuns) | Measure-Object -Property durationMs -Sum).Sum } catch { $totalScan = 0 }

# Minimal summaries for primary target
$motwSummary = $primaryTargetMeta.motwSummary
$sigSummary = $primaryTargetMeta.signatureSummary
$endTime = Get-Date

$report = [pscustomobject]@{
  schemaVersion = $schemaVersion
  meta = [pscustomobject]@{
    runId = $runId
    timestamp = $endTime.ToString('o')
    preset = $Preset
    firewallMode = $FirewallMode
    enableOutbox = [bool]($EnableOutbox -eq 1)
    sandbox = 'Windows Sandbox'
    openedUrl = [bool]$openedUrl
  }
  target = [pscustomobject]@{
    fileName = $primaryTargetMeta.fileName
    sourcePath = $primaryTargetMeta.sourcePath
    sandboxCopyPath = $primaryTargetMeta.sandboxCopyPath
    sha256 = $primaryTargetMeta.sha256
    motwSummary = $motwSummary
    signatureSummary = $sigSummary
  }
  urlAnalysis = $urlInfo
  defender = [pscustomobject]@{
    antivirusSignatureVersion = if($defStatus){ $defStatus.AntivirusSignatureVersion } else { $null }
    antivirusSignatureLastUpdated = if($defStatus){ $defStatus.AntivirusSignatureLastUpdated } else { $null }
    signatureAgeDays = $sigAge
    engineVersion = if($defStatus){ $defStatus.EngineVersion } else { $null }
    serviceVersion = if($defStatus){ $defStatus.ServiceVersion } else { $null }
    update = $update
  }
  timing = [pscustomobject]@{
    startedAt = $startTime.ToString('o')
    endedAt = $endTime.ToString('o')
    updateDurationMs = $update.DurationMs
    totalScanDurationMs = [int]$totalScan
    minutes = $Minutes
  }
  artifacts = [pscustomobject]@{
    files = @($artifacts)
    scans = @($scanRuns)
  }
  evidence = [pscustomobject]@{
    detections = @($detections)
  }
  telemetry = [pscustomobject]@{
    processBaseline = if($CollectDeltas -eq 1){ $proc0 } else { $null }
    processFinal = if($CollectDeltas -eq 1){ $proc1 } else { $null }
    netBaseline = if($CollectDeltas -eq 1){ $net0 } else { $null }
    netFinal = if($CollectDeltas -eq 1){ $net1 } else { $null }
  }
  autoDecision = $auto
  summary = [pscustomobject]@{
    status = $statusText
    meaning = $statusMeaning
    inconclusiveReason = $inconclusiveReason
    recommendation = $recommendation
  }
}

Write-ReportFiles -runDir $runDir -report $report
Log "Reporte generado: $runDir"

# Close Sandbox
Log 'Tiempo cumplido. Cerrando Sandbox...'
try { shutdown.exe /s /t 0 } catch {}

