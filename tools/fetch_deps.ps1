$ErrorActionPreference = "Stop"
$tp = Join-Path (Split-Path $PSScriptRoot -Parent) "third_party"
New-Item -ItemType Directory -Force $tp | Out-Null
# LGPL variant of the same autobuild tag: scshr only decodes (native H.264/HEVC decoders, D3D11VA,
# swscale) so it doesn't need the GPL-only encoders/libx264/libx265, and staying LGPL keeps the FDK
# licensed fdk-aac.dll (GPL-incompatible) shippable in the same distribution.
$ffUrl = "https://github.com/BtbN/FFmpeg-Builds/releases/download/autobuild-2026-08-25-13-06/ffmpeg-n9.0.1-6-g9d4ca21220-win64-lgpl-shared-9.0.zip"
$ffSha = "beea327434de459b16f4a8d1ad3a56c13dd787962d010b029bf767c3afb33542"
$zip = Join-Path $tp "ffmpeg-9.0.1-lgpl-shared.zip"
if (-not (Test-Path $zip)) { Invoke-WebRequest -Uri $ffUrl -OutFile $zip }
$h = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
if ($h -ne $ffSha) { throw "ffmpeg zip sha256 mismatch: $h" }
if (-not (Test-Path (Join-Path $tp "ffmpeg\lib\avcodec.lib"))) {
  Expand-Archive -Path $zip -DestinationPath $tp -Force
  Rename-Item (Join-Path $tp "ffmpeg-n9.0.1-6-g9d4ca21220-win64-lgpl-shared-9.0") "ffmpeg"
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

if (-not ((Test-Path (Join-Path $wgDir "wireguard.dll")) -and (Test-Path (Join-Path $wgDir "wireguard.h")))) {
  $ntZip = Join-Path $tp "wireguard-nt-1.1.zip"
  if (-not (Test-Path $ntZip)) { Invoke-WebRequest -Uri $wgNtUrl -OutFile $ntZip }
  $h = (Get-FileHash $ntZip -Algorithm SHA256).Hash.ToLower()
  if ($h -ne $wgNtSha) { throw "wireguard-nt zip sha256 mismatch: $h" }
  $ntTmp = Join-Path $tp "wireguard-nt-tmp"
  if (Test-Path $ntTmp) { Remove-Item -Recurse -Force $ntTmp }
  Expand-Archive -Path $ntZip -DestinationPath $ntTmp -Force
  Copy-Item (Join-Path $ntTmp "wireguard-nt\bin\amd64\wireguard.dll") $wgDir -Force
  # The adapter API header: scshr reads peer/handshake state straight from the driver, because
  # tunnel.dll drives WireGuardNT and exposes no userspace-API pipe.
  Copy-Item (Join-Path $ntTmp "wireguard-nt\include\wireguard.h") $wgDir -Force
  Copy-Item (Join-Path $ntTmp "wireguard-nt\LICENSE.txt") (Join-Path $wgDir "LICENSE.wireguard-nt.txt") -Force
  Remove-Item -Recurse -Force $ntTmp
  Write-Host "wireguard.dll + wireguard.h (WireGuardNT 1.1) ready"
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

# ── MSVC discovery (same probe as build.ps1) ──────────────────────────────────
function Find-VS {
  $vs = @("C:\Program Files\Microsoft Visual Studio\18\Community", "C:\Program Files\Microsoft Visual Studio\2022\Community") |
    Where-Object { Test-Path "$_\VC\Auxiliary\Build\vcvars64.bat" } | Select-Object -First 1
  if (-not $vs) { throw "Visual Studio with C++ tools not found" }
  return $vs
}

# ── libssh2 (static, OpenSSL backend) — pairing wizard only ───────────────────
$sshDir = Join-Path $tp "libssh2"
$sshLib = Join-Path $sshDir "lib\libssh2.lib"
if (-not (Test-Path $sshLib)) {
  $vs = Find-VS
  $sshUrl = "https://github.com/libssh2/libssh2/releases/download/libssh2-1.11.1/libssh2-1.11.1.zip"
  $sshSha = "1452bed856eb7f82d6e18db481f34dc18c435dd77d56f884725f72fc3757f30a"
  $sshZip = Join-Path $tp "libssh2-1.11.1.zip"
  if (-not (Test-Path $sshZip)) { Invoke-WebRequest -Uri $sshUrl -OutFile $sshZip }
  $h = (Get-FileHash $sshZip -Algorithm SHA256).Hash.ToLower()
  if ($h -ne $sshSha) { throw "libssh2 zip sha256 mismatch: $h" }
  $sshSrc = Join-Path $tp "libssh2-src"
  if (Test-Path $sshSrc) { Remove-Item -Recurse -Force $sshSrc }
  Expand-Archive -Path $sshZip -DestinationPath $tp -Force
  Rename-Item (Join-Path $tp "libssh2-1.11.1") $sshSrc
  New-Item -ItemType Directory -Force $sshDir | Out-Null
  Copy-Item (Join-Path $sshSrc "COPYING") (Join-Path $sshDir "LICENSE") -Force
  $sshBld = Join-Path $sshSrc "build"
  Write-Host "building libssh2 1.11.1 (static, OpenSSL backend)..."
  $cmd = "call `"$vs\VC\Auxiliary\Build\vcvars64.bat`" >nul && " +
    "cmake -S `"$sshSrc`" -B `"$sshBld`" -G Ninja -DCMAKE_BUILD_TYPE=Release " +
    "-DBUILD_SHARED_LIBS=OFF -DCRYPTO_BACKEND=OpenSSL -DOPENSSL_ROOT_DIR=`"C:/Program Files/OpenSSL-Win64`" " +
    "-DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF -DENABLE_ZLIB_COMPRESSION=OFF " +
    "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL -DCMAKE_INSTALL_PREFIX=`"$sshDir`" && " +
    "cmake --build `"$sshBld`" --config Release --parallel && " +
    "cmake --install `"$sshBld`" --config Release"
  cmd /c $cmd
  if ($LASTEXITCODE -ne 0) { throw "libssh2 build failed ($LASTEXITCODE)" }
  Remove-Item -Recurse -Force $sshSrc
  if (-not (Test-Path $sshLib)) { throw "libssh2 build did not produce $sshLib" }
  Write-Host "libssh2.lib (static) ready"
}

# ── fdk-aac (shared DLL, built from source with MSVC) — AAC-ELD audio ─────────
$fdkDir = Join-Path $tp "fdk-aac"
$fdkDll = Join-Path $fdkDir "bin\fdk-aac.dll"
if (-not (Test-Path $fdkDll)) {
  $vs = Find-VS
  $fdkUrl = "https://github.com/mstorsjo/fdk-aac/archive/refs/tags/v2.0.3.zip"
  $fdkSha = "8b73e924bd9f12ea0dd1d809e5acd6805e82dc184bc55e99f7964f6850e378ef"
  $fdkZip = Join-Path $tp "fdk-aac-2.0.3.zip"
  if (-not (Test-Path $fdkZip)) { Invoke-WebRequest -Uri $fdkUrl -OutFile $fdkZip }
  $h = (Get-FileHash $fdkZip -Algorithm SHA256).Hash.ToLower()
  if ($h -ne $fdkSha) { throw "fdk-aac zip sha256 mismatch: $h" }
  $fdkSrc = Join-Path $tp "fdk-aac-src"
  if (Test-Path $fdkSrc) { Remove-Item -Recurse -Force $fdkSrc }
  Expand-Archive -Path $fdkZip -DestinationPath $tp -Force
  Rename-Item (Join-Path $tp "fdk-aac-2.0.3") $fdkSrc
  New-Item -ItemType Directory -Force $fdkDir | Out-Null
  Copy-Item (Join-Path $fdkSrc "NOTICE") (Join-Path $fdkDir "NOTICE") -Force
  $fdkBld = Join-Path $fdkSrc "build"
  Write-Host "building fdk-aac v2.0.3 (shared DLL)..."
  $cmd = "call `"$vs\VC\Auxiliary\Build\vcvars64.bat`" >nul && " +
    "cmake -S `"$fdkSrc`" -B `"$fdkBld`" -G Ninja -DCMAKE_BUILD_TYPE=Release " +
    "-DBUILD_SHARED_LIBS=ON -DBUILD_PROGRAMS=OFF -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=ON " +
    "-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL && " +
    "cmake --build `"$fdkBld`" --config Release --parallel"
  cmd /c $cmd
  if ($LASTEXITCODE -ne 0) { throw "fdk-aac build failed ($LASTEXITCODE)" }
  New-Item -ItemType Directory -Force (Join-Path $fdkDir "bin") | Out-Null
  $builtDll = Get-ChildItem -Recurse -Path $fdkBld -Filter "*.dll" | Select-Object -First 1
  if (-not $builtDll) { throw "fdk-aac build did not produce a DLL" }
  Copy-Item $builtDll.FullName $fdkDll -Force
  Remove-Item -Recurse -Force $fdkSrc
  if (-not (Test-Path $fdkDll)) { throw "fdk-aac build did not produce $fdkDll" }
  Write-Host "fdk-aac.dll ready"
}

# ── macOS tunnel helper (Go cross-compile) ────────────────────────────────────
$macTunnelSrc = Join-Path $PSScriptRoot "mac-tunnel"
$macDir = Join-Path $tp "mac"
$macArm = Join-Path $macDir "scshr-tunnel-darwin-arm64"
$macAmd = Join-Path $macDir "scshr-tunnel-darwin-amd64"
if (-not (Test-Path (Join-Path $macTunnelSrc "go.mod"))) {
  Write-Host "tools/mac-tunnel/go.mod not found; skipping macOS tunnel helper cross-compile"
} elseif ((Test-Path $macArm) -and (Test-Path $macAmd) -and
          -not (Get-ChildItem $macTunnelSrc -Include *.go, go.mod, go.sum -Recurse | Where-Object { $_.LastWriteTime -gt (Get-Item $macArm).LastWriteTime })) {
  Write-Host "macOS tunnel helper binaries already present and newer than tools/mac-tunnel"
} else {
  $goExe = Join-Path $tp "wireguard-windows\.deps\bin\go.exe"
  if (-not (Test-Path $goExe)) {
    $goDir = Join-Path $tp "go"
    $goExe = Join-Path $goDir "go\bin\go.exe"
    if (-not (Test-Path $goExe)) {
      $goUrl = "https://go.dev/dl/go1.27.1.windows-amd64.zip"
      $goSha = "a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d"
      $goZip = Join-Path $tp "go1.27.1.windows-amd64.zip"
      if (-not (Test-Path $goZip)) { Invoke-WebRequest -Uri $goUrl -OutFile $goZip }
      $h = (Get-FileHash $goZip -Algorithm SHA256).Hash.ToLower()
      if ($h -ne $goSha) { throw "go toolchain zip sha256 mismatch: $h" }
      New-Item -ItemType Directory -Force $goDir | Out-Null
      Expand-Archive -Path $goZip -DestinationPath $goDir -Force
    }
  }
  New-Item -ItemType Directory -Force $macDir | Out-Null
  foreach ($arch in @("arm64", "amd64")) {
    Write-Host "cross-compiling scshr-tunnel-darwin-$arch (GOOS=darwin GOARCH=$arch)..."
    Push-Location $macTunnelSrc
    try {
      $env:GOOS = "darwin"; $env:GOARCH = $arch; $env:CGO_ENABLED = "0"
      & $goExe build -trimpath -ldflags "-s -w" -o (Join-Path $macDir "scshr-tunnel-darwin-$arch") .
      if ($LASTEXITCODE -ne 0) { throw "go build (darwin/$arch) failed ($LASTEXITCODE)" }
    } finally {
      Remove-Item Env:\GOOS, Env:\GOARCH, Env:\CGO_ENABLED -ErrorAction SilentlyContinue
      Pop-Location
    }
  }
  Write-Host "macOS tunnel helper binaries ready"
}

Write-Host "deps ready under $tp"
