# Pinned native dependencies

| Dependency | Version / source | Verification |
|---|---|---|
| FFmpeg (shared, GPL) | BtbN autobuild tag `autobuild-2026-08-25-13-06`, asset `ffmpeg-n9.0.1-6-g9d4ca21220-win64-gpl-shared-9.0.zip` | sha256 `83399212173269cb27991f02ac467f792d1066c6de2d695980f338775bc09c58` |
| OpenSSL | 3.6.1 (Shining Light Win64 installer, `C:\Program Files\OpenSSL-Win64`) | `openssl version` |
| WireGuardNT (`wireguard.dll`) | 1.1, `https://download.wireguard.com/wireguard-nt/wireguard-nt-1.1.zip` | sha256 `dceb30a9bc4be48cce0f74160fc88a585a2c2627366e8f846fc6658f9038dace` |
| wireguard-windows embeddable tunnel (`tunnel.dll`) | tag `v0.6.1` = commit `f8256e035eb65460ac4eba93d7487163353e0326`, built from source with upstream `embeddable-dll-service/build.bat` | git commit pin verified after checkout; upstream build.bat sha256-verifies its own Go/llvm-mingw toolchain |
| miniz | 3.0.2 (`miniz-3.0.2.zip` release amalgamation) | vendored in `miniz/` |

`tools/fetch_deps.ps1` re-downloads FFmpeg + miniz into this directory and checks the FFmpeg sha256.

Both WireGuard components are MIT/permissive-licensed by WireGuard LLC; the upstream notices are copied
to `wireguard/LICENSE.wireguard-nt.txt` and `wireguard/LICENSE.wireguard-windows.txt` by `tools/fetch_deps.ps1`.
WireGuard and the WireGuard logo are registered trademarks of Jason A. Donenfeld.
