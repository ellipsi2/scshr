# Stage a user-distributable folder + zip (+ SHA-256 sums) from an existing Release build.
# Usage: .\tools\package.ps1 [-Version 0.1.0]   (run .\build.ps1 first; default version = git describe)
param([string]$Version = "")
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$rel = Join-Path $root "build\Release"
$tp = Join-Path $root "third_party"

function Require-File($path) {
  if (-not (Test-Path $path)) { throw "package.ps1: required file missing: $path" }
}

Require-File (Join-Path $rel "scshr.exe")

$version = $Version
if (-not $version) { $version = (git -C $root describe --tags --always --dirty 2>$null) }
if (-not $version) { $version = "0.0.0-unknown" }
$version = $version.Trim()

$stageRoot = Join-Path $root "dist"
$stage = Join-Path $stageRoot "scshr-$version-win64"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force $stage | Out-Null

$files = @(
  "scshr.exe", "avcodec-63.dll", "avutil-61.dll", "swscale-10.dll", "swresample-7.dll",
  "libcrypto-3-x64.dll", "tunnel.dll", "wireguard.dll"
)
foreach ($f in $files) {
  Require-File (Join-Path $rel $f)
  Copy-Item (Join-Path $rel $f) $stage -Force
}

$fdkDll = Join-Path $rel "fdk-aac.dll"
if (Test-Path $fdkDll) { Copy-Item $fdkDll $stage -Force }
else { Write-Warning "fdk-aac.dll not found in $rel; packaging without audio support" }

$macDir = Join-Path $rel "mac"
Require-File $macDir
Copy-Item $macDir (Join-Path $stage "mac") -Recurse -Force
foreach ($m in @("scshr-macos-tunnel.sh", "scshr-tunnel-darwin-arm64", "scshr-tunnel-darwin-amd64")) {
  Require-File (Join-Path $stage "mac\$m")
}
# The macOS script must stay LF: a CRLF copy fails on the Mac with "bad interpreter".
$shText = Get-Content -Raw (Join-Path $stage "mac\scshr-macos-tunnel.sh")
if ($shText.Contains("`r`n")) { throw "package.ps1: mac\scshr-macos-tunnel.sh has CRLF line endings" }

$guide = Join-Path $root "docs\USER-GUIDE.md"
if (Test-Path $guide) { Copy-Item $guide (Join-Path $stage "README.txt") -Force }

$licDir = Join-Path $stage "LICENSES"
New-Item -ItemType Directory -Force $licDir | Out-Null

$licenseSources = @{
  "wireguard\LICENSE.wireguard-nt.txt"      = "LICENSE.wireguard-nt.txt"
  "wireguard\LICENSE.wireguard-windows.txt" = "LICENSE.wireguard-windows.txt"
  "libssh2\LICENSE"                         = "LICENSE.libssh2.txt"
  "fdk-aac\NOTICE"                          = "NOTICE.fdk-aac.txt"
  "miniz\LICENSE"                           = "LICENSE.miniz.txt"
}
foreach ($rel2 in $licenseSources.Keys) {
  $src = Join-Path $tp $rel2
  Require-File $src
  Copy-Item $src (Join-Path $licDir $licenseSources[$rel2]) -Force
}

@"
scshr bundles the following third-party components:

  * FFmpeg (avcodec, avutil, swscale, swresample) — LGPL v2.1+, see https://ffmpeg.org
    Built as a shared (DLL) dependency (the LGPL variant, no GPL-only components such as
    libx264/libx265 are enabled or linked); no FFmpeg source is modified.
  * OpenSSL (libcrypto) — Apache License 2.0, see https://www.openssl.org
  * WireGuardNT / wireguard-windows (wireguard.dll, tunnel.dll) — MIT, see LICENSE.wireguard-*.txt
  * libssh2 — BSD-3-Clause, see LICENSE.libssh2.txt (statically linked)
  * fdk-aac — Fraunhofer FDK AAC license, see NOTICE.fdk-aac.txt
  * miniz — MIT, see LICENSE.miniz.txt
"@ | Set-Content -Encoding UTF8 (Join-Path $licDir "THIRD-PARTY.txt")

$zip = Join-Path $stageRoot "scshr-$version-win64.zip"
if (Test-Path $zip) { Remove-Item -Force $zip }
Compress-Archive -Path $stage -DestinationPath $zip -Force   # zip root = the scshr-<version>-win64 folder

# SHA-256 of the zip and of every staged file, in the usual `sha256sum` layout.
$sums = Join-Path $stageRoot "SHA256SUMS.txt"
$items = @(Get-Item $zip) + @(Get-ChildItem -Recurse -File $stage)
$lines = foreach ($item in $items) {
  $h = (Get-FileHash $item.FullName -Algorithm SHA256).Hash.ToLower()
  $name = $item.FullName.Substring($stageRoot.Length + 1) -replace '\\', '/'
  "$h  $name"
}
$lines | Set-Content -Encoding ascii $sums

Write-Host "packaged: $zip"
Write-Host "unpacked: $stage"
Write-Host "checksums: $sums"
