# scshr — native Windows client for Apple Screen Sharing High Performance mode

**Using it (no technical knowledge needed): read [docs/USER-GUIDE.md](docs/USER-GUIDE.md).** Unzip, double-click
`scshr.exe`, type the Mac's address and an administrator login, click **Set up**; the wizard reaches the Mac over
SSH, installs the tunnel on both sides, turns on Screen Sharing and tests the link. Then **Connect** shows the Mac's
screen with mouse, keyboard, sound and clipboard. The rest of this file is for developers.

Native C++20 port of [iShareScreen](https://github.com/renegadelink/iShareScreen)'s desktop receiver, built
around a bounded, GPU-resident media path:

```
Winsock UDP (IOCP, preposted receives, packet pool)
  → SRTP AES-256-CM + HMAC-SHA1-80 (OpenSSL, in place)
  → RTP sequence tracking / (SSRC,ts) group assembly / NACK repair window   [same semantics as the Python reference]
  → Apple-variant NAL reassembly (H.264 DON-less FU-A; HEVC RFC 7798 + DONL everywhere)
  → libavcodec + D3D11VA (AV_PIX_FMT_D3D11, frame pool created with BIND_DECODER|BIND_SHADER_RESOURCE)
  → decoder texture-array slice → shader-resource view → pixel shader YUV→RGB (+ cursor overlay)
  → DXGI flip-model swapchain, frame-latency waitable object, max latency 1 → Present
```

No Python, no PyAV, no CPU readback of decoded frames on the hardware path. One D3D11 device is shared by the
decoder and the renderer (FFmpeg's D3D11VA device context is created from the renderer's device with a shared
lock). The decoder keeps exactly one newest frame per tile; the render loop waits for the swapchain first and
then takes the freshest frames, so stale frames are replaced instead of queued.

## Build

Requirements: Visual Studio 2022/2026 C++ tools, CMake ≥ 3.25, Ninja, Windows 10/11 SDK, OpenSSL 3.x
(Shining Light Win64 installer at `C:\Program Files\OpenSSL-Win64`), git. Everything else is pinned and fetched or
built from source by `tools/fetch_deps.ps1` (see `third_party/README.md`): FFmpeg 9.0.1 shared, miniz, WireGuardNT +
the wireguard-windows embeddable tunnel, libssh2 (static, for the pairing wizard), fdk-aac (AAC-ELD audio DLL), and
the macOS tunnel helper cross-compiled with Go (`tools/mac-tunnel`).

```powershell
.\tools\fetch_deps.ps1      # fetch/build every pinned dependency into third_party/
.\build.ps1                 # Release build into build\Release (Ninja + MSVC)
.\build\Release\scshr_tests.exe
bash tests\tunnel_shell_test.sh
.\tools\package.ps1        # dist\scshr-<version>-win64.zip: the user-distributable folder
```

`scshr.exe` is a GUI-subsystem executable with a `requireAdministrator` manifest (the tunnel state and the WireGuard
driver are Administrators-only). Started without arguments it opens the launcher; with arguments it re-attaches to the
parent console and behaves as the CLI below. Run the CLI from an **elevated** console: from a non-elevated one every
call goes through UAC into a new process, redirected stdin/stdout (`--password-stdin`, `> log`) do not follow it, and
the shell does not wait for it. This applies to `--direct` development sessions and `--list-adapters` too.

## Run

Sessions run over a dedicated one-Windows-to-one-Mac WireGuard tunnel (see [TUNNEL.md](TUNNEL.md)).
Pair once, then the Mac's public address is never needed again. The built-in wizard does both sides over SSH
(the GUI's **Set up**, or on the command line):

```powershell
.\build\Release\scshr.exe setup --mac my-mac.example.net --mac-user admin   # prompts for the password
.\build\Release\scshr.exe check                                             # link status through the tunnel
.\build\Release\scshr.exe unpair [--mac H --mac-user U] [--reset-identity]  # remove one or both halves
```

The manual code exchange still works when SSH is unavailable (the helper bundle is the `mac/` folder next to
`scshr.exe`, copied to the Mac by any means):

```bash
# macOS, once
sudo ./mac/scshr-macos-tunnel.sh init --endpoint my-mac.example.net    # prints SCST1:<code>
sudo ./mac/scshr-macos-tunnel.sh pair 'SCCL1:<code Windows printed>'
```

```powershell
.\build\Release\scshr.exe init            # paste the SCST1 code; prints SCCL1:<code>
.\build\Release\scshr.exe status          # tunnel state, handshake, route validation
echo $PW | .\build\Release\scshr.exe -u me --password-stdin
.\build\Release\scshr.exe -u me                                    # prompts for the password
.\build\Release\scshr.exe --list-adapters                          # hybrid-GPU diagnostics
.\build\Release\scshr.exe --adapter 1 --present lowlat             # force an adapter / lowest-latency presentation
```

Production sessions fail closed if the tunnel is missing, stopped, mis-routed or bound to a different
peer — there is no fallback to the Mac's public or LAN address. `--direct --host H` bypasses the
tunnel for development and replay work only.

Options mirror the Python `iss` CLI: `--advertise WxH[@SCALE]|auto`, `--hidpi auto|on|off|N`,
`--dynamic/--no-dynamic`, `--codec auto|hevc|avc`, `--decoder auto|sw`, `--curtain/--no-curtain`,
`--share-console`, `--alt-session`, `--audio/--no-audio`, `--display N|all|combined`, `--record FILE.scshr`,
`--auto-quit-secs N`, `--stats-interval S`, `-v`, `--log-file PATH`. Added here: `--direct --host H`
(bypass the tunnel; development only) and the `setup` / `check` / `unpair` / `init` / `status` / `tunnel uninstall`
subcommands.

`--codec auto` offers HEVC 4:4:4 only when the GPU + FFmpeg build can hardware-decode it (a real probe decode),
otherwise H.264 4:2:0 — the same ladder as the reference. On current FFmpeg/D3D11VA there is no HEVC RExt 4:4:4
profile, so Windows sessions use H.264 4:2:0 in hardware; HEVC 4:4:4 decodes in software (explicitly labelled
`cpu-upload` in the stats line).

A compact statistics line is logged every `--stats-interval` seconds: packet rate, pool usage, reorder depth,
reconstructed/incomplete/dropped frames, loss, decoder queue depth, decode latency percentiles, present interval
percentiles, AU→Present latency, zero-copy/GPU-copy/CPU-upload frame counters, process CPU and working set.

## Audio

AAC-ELD-SBR is decoded with fdk-aac: `fdk-aac.dll`, built from the pinned upstream source by `tools/fetch_deps.ps1`
and bundled next to `scshr.exe` (an MSYS2 `libfdk-aac-2.dll` is still found as a fallback). Output goes through
WASAPI shared mode with a 40 ms jitter target. Without the DLL video runs and audio is skipped.

## Tools

| Tool | Purpose |
|---|---|
| `scshr_vectors` + `tests/diff_vectors.py` | byte-exact differential vectors vs the Python reference (SRTP/KDF, record layer, RFB/RTCP builders, bplist, offers, SRP math, NAL reassembly, …) |
| `scshr_synth` | Annex-B H.264/HEVC → Apple-format SRTP `.scshr` recording with impairments (loss, reorder, dup, seq wrap, SSRC switch, restart, corruption) |
| `scshr_replay` + `tests/replay_oracle.py` + `tests/diff_replay.py` | deterministic replay of a recording through the native packet core vs the Python session code, event-for-event comparison; `--decode sw|hw` also runs the decoder |
| `scshr_sender` | real-time UDP replay of a recording with emulated one-way delay / jitter / loss |
| `scshr --replay-key HEX` | full viewer fed by `scshr_sender` (no TCP handshake) — the end-to-end performance harness |
| `scshr_bench` | packet-path throughput microbenchmark |
| `tools/e2e.sh` | one-shot viewer + sender run with summary lines |
| `tools/scshr-macos-tunnel.sh` | macOS identity/pairing/lifecycle + mandatory Screen Sharing PF isolation (bash 3.2, no Homebrew) |
| `tools/mac-tunnel/` | Go: self-contained macOS tunnel daemon (wireguard-go) + keys/status, cross-compiled into `mac/` |
| `tests/tunnel_shell_test.sh` | static tests for the macOS script (syntax, config/PF/plist goldens, strict descriptor decoding) |
| `tools/package.ps1` | builds the distributable zip |

Tunnel tests need no macOS host:

```powershell
.\build\Release\scshr_tests.exe tunnel   # descriptors, route policy, config generation, status, redaction
bash tests\tunnel_shell_test.sh          # macOS script syntax + config/PF goldens + strict decoding
```

Run the oracle-based tests with the Python venv that has the reference package installed:

```powershell
.\.venv-oracle\Scripts\python tests\diff_vectors.py
.\.venv-oracle\Scripts\python tests\diff_replay.py
```

## Multi-monitor hosts

When the host reports several displays (`--display all`, the default), the viewer opens one window per host
monitor; all windows are fed from the single decoded canvas (one decode, one swapchain per window, each cropped
to its monitor's rectangle). Dynamic resolution is pinned in that mode. `--display N` shows only monitor N.

## Regenerating the test recordings

`tools/gen_testdata.sh` rebuilds every `testdata/*.scshr` from the Annex-B streams with fixed seeds.
