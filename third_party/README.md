# Pinned native dependencies

| Dependency | Version / source | Verification |
|---|---|---|
| FFmpeg (shared, LGPL 2.1+) | BtbN autobuild tag `autobuild-2026-08-25-13-06`, asset `ffmpeg-n9.0.1-6-g9d4ca21220-win64-lgpl-shared-9.0.zip` | sha256 `beea327434de459b16f4a8d1ad3a56c13dd787962d010b029bf767c3afb33542` |
| OpenSSL | 3.6.1 (Shining Light Win64 installer, `C:\Program Files\OpenSSL-Win64`) | `openssl version` |
| WireGuardNT (`wireguard.dll`) | 1.1, `https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip` | sha256 `dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace` |
| wireguard-windows embeddable tunnel (`tunnel.dll`) | tag `v0.6.1` = commit `f8256e035eb65460ac4eba93d7487163353e0326`, built from source with upstream `embeddable-dll-service/build.bat` | git commit pin verified after checkout; upstream build.bat sha256-verifies its own Go/llvm-mingw toolchain |
| miniz | 3.0.2 (`miniz-3.0.2.zip` release amalgamation) | vendored in `miniz/` |
| libssh2 (static, OpenSSL backend) | 1.11.1, `https://github.com/libssh2/libssh2/releases/download/libssh2-1.11.1/libssh2-1.11.1.zip` | sha256 `1452bed856eb7f82d6e18db481f34dc18c435dd77d56f884725f72fc3757f30a`; built from source with MSVC+Ninja |
| fdk-aac (shared DLL) | v2.0.3, `https://github.com/mstorsjo/fdk-aac/archive/refs/tags/v2.0.3.zip` | sha256 `8b73e924bd9f12ea0dd1d809e5acd6805e82dc184bc55e99f7964f6850e378ef`; built from source with MSVC+Ninja |
| Go toolchain (macOS tunnel helper cross-compile) | uses `third_party/wireguard-windows/.deps/bin/go.exe` if present, else pinned `go1.27.1.windows-amd64.zip` | sha256 `a3911b5e0e1b1053f25ed0675f4c1c6aad1e2bfcf253df2b9be4caabd2edd95d` |

`tools/fetch_deps.ps1` re-downloads FFmpeg + miniz into this directory and checks the FFmpeg sha256. It
also builds libssh2 (static) and fdk-aac (shared DLL) from their pinned, sha256-verified source archives,
and cross-compiles the macOS tunnel helper (`tools/mac-tunnel`) for `darwin/arm64` and `darwin/amd64` with
Go, skipping that step with a message if `tools/mac-tunnel/go.mod` does not exist yet. libssh2's `LICENSE`
and fdk-aac's `NOTICE` are copied alongside their build outputs.

Both WireGuard components are MIT/permissive-licensed by WireGuard LLC; the upstream notices are copied
to `wireguard/LICENSE.wireguard-nt.txt` and `wireguard/LICENSE.wireguard-windows.txt` by `tools/fetch_deps.ps1`.
WireGuard and the WireGuard logo are registered trademarks of Jason A. Donenfeld.

FFmpeg is pinned to the **LGPL** variant (not GPL) of the BtbN autobuild, deliberately: scshr only
decodes (native H.264/HEVC decoders, D3D11VA, swscale/swresample) and never links `libx264`/`libx265`
or any other GPL-only component, so the LGPL build is sufficient, and staying LGPL keeps it
license-compatible for redistribution alongside the FDK-licensed `fdk-aac.dll` in the same package
(the FDK license and GPL are not compatible). Full license summary: FFmpeg LGPL 2.1+, OpenSSL
Apache-2.0, fdk-aac Fraunhofer FDK AAC license, libssh2 BSD-3-Clause, WireGuard components MIT, miniz
MIT.
