# WinLab publish script (one-command)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Exit-OnFail {
  param([int]$code, [string]$label)
  if($code -ne 0){
    Write-Host "[FAIL] $label (exit $code)" -ForegroundColor Red
    exit $code
  }
}

$scriptPath = $PSCommandPath
if(-not $scriptPath){ $scriptPath = $MyInvocation.MyCommand.Path }
$root = (Resolve-Path (Split-Path -Parent $scriptPath)).Path
Set-Location $root

$version = '0.8.0'
$verPath = Join-Path $root 'tools/cli/version.txt'
if(Test-Path $verPath){
  $v = (Get-Content -Raw -Path $verPath).Trim()
  if($v){ $version = $v }
}

Write-Host "[INFO] Ejecutando smoke tests." -ForegroundColor Cyan
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'smoke_tests.ps1')
Exit-OnFail $LASTEXITCODE 'smoke_tests.ps1'

Write-Host "[INFO] Generando artifacts de release." -ForegroundColor Cyan
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'build_release.ps1')
Exit-OnFail $LASTEXITCODE 'build_release.ps1'

$status = & git status --porcelain
Exit-OnFail $LASTEXITCODE 'git status'
if($status){
  & git add -A
  Exit-OnFail $LASTEXITCODE 'git add'
  & git commit -m ("chore: publish prep {0}" -f $version)
  Exit-OnFail $LASTEXITCODE 'git commit'
}

$targetOrigin = 'https://github.com/marcoluna-nqn/winlab-demo.git'
$originUrl = & git remote get-url origin 2>$null
if($LASTEXITCODE -ne 0){
  & git remote add origin $targetOrigin
  Exit-OnFail $LASTEXITCODE 'git remote add origin'
} else {
  if($originUrl.Trim() -ne $targetOrigin){
    & git remote set-url origin $targetOrigin
    Exit-OnFail $LASTEXITCODE 'git remote set-url origin'
  }
}

& git push -u origin main
Exit-OnFail $LASTEXITCODE 'git push main'

$tagName = "v$version"
$tagExists = & git tag -l $tagName
Exit-OnFail $LASTEXITCODE 'git tag -l'
if(-not $tagExists){
  & git tag $tagName
  Exit-OnFail $LASTEXITCODE 'git tag'
}
& git push origin $tagName
Exit-OnFail $LASTEXITCODE 'git push tag'

if(Get-Command gh -ErrorAction SilentlyContinue){
  & gh auth status
  if($LASTEXITCODE -ne 0){
    & gh auth login -w
    Exit-OnFail $LASTEXITCODE 'gh auth login'
  }

  $releaseView = & gh release view $tagName 2>$null
  if($LASTEXITCODE -ne 0){
    $pack = Join-Path $root ("dist/WinLab_ProductPack_{0}.zip" -f $version)
    $site = Join-Path $root 'dist/winlab_site.zip'
    $sums = Join-Path $root 'dist/SHA256SUMS.txt'
    if(-not (Test-Path $pack)){ throw "Missing release asset: $pack" }
    if(-not (Test-Path $site)){ throw "Missing release asset: $site" }
    if(-not (Test-Path $sums)){ throw "Missing release asset: $sums" }
    & gh release create $tagName $pack $site $sums -F (Join-Path $root 'RELEASE_NOTES.md') -t ("WinLab v{0}" -f $version)
    Exit-OnFail $LASTEXITCODE 'gh release create'
  }

  $pagesOk = $true
  & gh api -X POST "repos/marcoluna-nqn/winlab-demo/pages" -F "source[branch]=main" -F "source[path]=/"
  if($LASTEXITCODE -ne 0){
    & gh api -X PUT "repos/marcoluna-nqn/winlab-demo/pages" -F "source[branch]=main" -F "source[path]=/"
    if($LASTEXITCODE -ne 0){ $pagesOk = $false }
  }
  if(-not $pagesOk){
    Write-Host "[WARN] Pages enable failed. UI steps:" -ForegroundColor Yellow
    Write-Host "1) Repo Settings -> Pages" -ForegroundColor Yellow
    Write-Host "2) Source: Deploy from a branch" -ForegroundColor Yellow
    Write-Host "3) Branch: main / (root)" -ForegroundColor Yellow
    Write-Host "4) Save" -ForegroundColor Yellow
  }
} else {
  Write-Host "[WARN] gh CLI not found; skipping release/pages automation." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Expected URL: https://marcoluna-nqn.github.io/winlab-demo/"
Write-Host "Next steps:"
Write-Host "- Set real payment links in assets/config.js"
Write-Host "- Validate launcher on a clean Windows 10/11 Pro host"
Write-Host "- Verify downloads and release assets on GitHub"
