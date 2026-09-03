$ErrorActionPreference = "Stop"
$tp = Join-Path (Split-Path $PSScriptRoot -Parent) "third_party"
New-Item -ItemType Directory -Force $tp | Out-Null
$ffUrl = "https://github.com/BtbN/FFmpeg-Builds/releases/download/autobuild-2026-08-25-13-06/ffmpeg-n9.0.1-6-g9d4ca21220-win64-gpl-shared-9.0.zip"
$ffSha = "83399212173269cb27991f02ac467f792d1066c6de2d695980f338775bc09c58"
$zip = Join-Path $tp "ffmpeg-9.0.1-shared.zip"
if (-not (Test-Path $zip)) { Invoke-WebRequest -Uri $ffUrl -OutFile $zip }
$h = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
if ($h -ne $ffSha) { throw "ffmpeg zip sha256 mismatch: $h" }
if (-not (Test-Path (Join-Path $tp "ffmpeg\lib\avcodec.lib"))) {
  Expand-Archive -Path $zip -DestinationPath $tp -Force
  Rename-Item (Join-Path $tp "ffmpeg-n9.0.1-6-g9d4ca21220-win64-gpl-shared-9.0") "ffmpeg"
}
$mz = Join-Path $tp "miniz"
if (-not (Test-Path (Join-Path $mz "miniz.c"))) {
  $mzip = Join-Path $tp "miniz.zip"
  Invoke-WebRequest -Uri "https://github.com/richgel999/miniz/releases/download/3.0.2/miniz-3.0.2.zip" -OutFile $mzip
  Expand-Archive -Path $mzip -DestinationPath $mz -Force
  Remove-Item $mzip
}

# ── WireGuard (application tunnel) ────────────────────────────────────────────────────────────
# Two pinned upstream components, both from WireGuard LLC:
#   * WireGuardNT 1.1        wireguard.dll  — the kernel data path
#   * wireguard-windows v0.6.1 tunnel.dll   — the "embeddable-dll-service" tunnel, built from source
# tunnel.dll has no official prebuilt download, so it is built with upstream's own build.bat, which
# fetches and sha256-verifies its Go + llvm-mingw toolchain itself.
$wgDir = Join-Path $tp "wireguard"
$wgNtUrl = "https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip"
$wgNtSha = "dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace"
$wgWinRepo = "https://git.zx2c4.com/wireguard-windows"
$wgWinCommit = "f8256e035eb65460ac4eba93d7487163353e0326"   # tag v0.6.1
New-Item -ItemType Directory -Force $wgDir | Out-Null

if (-not (Test-Path (Join-Path $wgDir "wireguard.dll"))) {
  $ntZip = Join-Path $tp "wireguard-nt-1.1.zip"
  if (-not (Test-Path $ntZip)) { Invoke-WebRequest -Uri $wgNtUrl -OutFile $ntZip }
  $h = (Get-FileHash $ntZip -Algorithm SHA256).Hash.ToLower()
  if ($h -ne $wgNtSha) { throw "wireguard-nt zip sha256 mismatch: $h" }
  $ntTmp = Join-Path $tp "wireguard-nt-tmp"
  if (Test-Path $ntTmp) { Remove-Item -Recurse -Force $ntTmp }
  Expand-Archive -Path $ntZip -DestinationPath $ntTmp -Force
  Copy-Item (Join-Path $ntTmp "wireguard-nt\bin\amd64\wireguard.dll") $wgDir -Force
  Copy-Item (Join-Path $ntTmp "wireguard-nt\LICENSE.txt") (Join-Path $wgDir "LICENSE.wireguard-nt.txt") -Force
  Remove-Item -Recurse -Force $ntTmp
  Write-Host "wireguard.dll (WireGuardNT 1.1) ready"
}

if (-not (Test-Path (Join-Path $wgDir "tunnel.dll"))) {
  if (-not (Get-Command git -ErrorAction SilentlyContinue)) { throw "git is required to build tunnel.dll from wireguard-windows $wgWinCommit" }
  $src = Join-Path $tp "wireguard-windows"
  if (-not (Test-Path (Join-Path $src ".git"))) {
    if (Test-Path $src) { Remove-Item -Recurse -Force $src }
    git clone --quiet $wgWinRepo $src
    if ($LASTEXITCODE -ne 0) { throw "cloning $wgWinRepo failed" }
  }
  git -C $src fetch --quiet --all
  git -C $src checkout --quiet $wgWinCommit
  if ($LASTEXITCODE -ne 0) { throw "checking out $wgWinCommit failed" }
  $head = (git -C $src rev-parse HEAD).Trim()
  if ($head -ne $wgWinCommit) { throw "wireguard-windows HEAD is $head, expected $wgWinCommit" }
  Write-Host "building tunnel.dll (upstream build.bat downloads and verifies its own Go/mingw toolchain; this takes a while)"
  Push-Location (Join-Path $src "embeddable-dll-service")
  try {
    cmd /c "build.bat"
    if ($LASTEXITCODE -ne 0) { throw "embeddable-dll-service build.bat failed ($LASTEXITCODE)" }
  } finally { Pop-Location }
  Copy-Item (Join-Path $src "embeddable-dll-service\amd64\tunnel.dll") $wgDir -Force
  Copy-Item (Join-Path $src "COPYING") (Join-Path $wgDir "LICENSE.wireguard-windows.txt") -Force
  Write-Host "tunnel.dll (wireguard-windows v0.6.1) ready"
}

Write-Host "deps ready under $tp"
