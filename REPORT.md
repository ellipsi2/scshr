# scshr — port report

Evidence sources: `build/e2e_matrix3.txt`, `build/e2e_*.log`, `scshr_tests`, `tests/diff_vectors.py`,
`tests/diff_replay.py`, `scshr_bench`. All numbers below were measured on the **dev box** (Ryzen 9 3900X,
RTX 3080 Ti, Windows 11, 60 Hz panel). The target laptop (5800H + 3050 Ti) and a live macOS host were not
available in this environment: every row that needs them says `not measured`.

## Outcome

Native C++20 Windows client (~9.2k lines incl. tools/tests) replacing the Python receiver. Hardware path is
GPU-resident end to end (verified by counters: `zero-copy=N gpu-copy=0 cpu-upload=0`). Packet core is
byte-/event-exact with the Python reference on 10 impairment recordings (`replay differential: ALL MATCH`)
and 79 protocol vectors. 10-minute 1080p60 soak: flat memory (105–110 MB), no queue growth, present-interval
p99 17.0 ms, AU→present p50 0.39 ms. Live-host interoperability **not verified** (no Mac available).

## Final hot path

```
NIC → Winsock IOCP (preposted WSARecvFrom into 8192×2 KB PacketPool slots, GetQueuedCompletionStatusEx batches)
    → packet thread: SRTP AES-256-CM decrypt in place + HMAC-SHA1-80 (OpenSSL EVP, ROC candidates)
    → RtpAssembler: seq tracking / (SSRC,ts) groups / 75 ms AVC repair window / NACK / dedup   (Python semantics)
    → NAL reassembly into one Annex-B buffer per AU (FU-A DON-less AVC; HEVC AP/FU + DONL)
    → SPSC ring (64) → decoder worker: avcodec_send_packet per NAL, D3D11VA (AV_PIX_FMT_D3D11)
       frames pool created in get_format with BIND_DECODER|BIND_SHADER_RESOURCE  → no copy
    → newest-frame-per-tile slot (older frame dropped, counted `stale`)
    → main thread: wait swapchain waitable → take newest → SRV on decoder texture-array slice
       (R8 + R8G8 views of NV12) → pixel shader YUV→RGB + cursor quad → Present (FLIP_DISCARD, max latency 1)
```

No Python, no PyAV, no CPU readback. Software decode (HEVC 4:4:4 on D3D11VA, or `--decoder sw`) uses a
dynamic-texture upload and is reported as `cpu-upload=N`.

## Major changes vs the Python client

| Area | Python | C++ |
|---|---|---|
| Socket | asyncio datagram + Python loop | IOCP, preposted receives, zero allocation per packet |
| SRTP | pycryptodome per packet, bytes copies | OpenSSL EVP in place, per-SSRC ROC state |
| Assembly | dict-of-lists, bytes joins | packet-pool slot indices, insertion-ordered group vectors (same iteration order as Python dicts — required for parity) |
| Decode | PyAV, frames to numpy | libavcodec D3D11VA on the renderer's device (`AVD3D11VADeviceContext` lock = renderer lock) |
| Render | wgpu, CPU upload each frame | D3D11 SRV on decoder surface, flip model, waitable object |
| Queues | unbounded asyncio queues | bounded ring (64) + one newest frame per tile; overflow counted |
| Multi-monitor | per-display windows | per-host-monitor windows from one decode (`--display all`, default) |
| Recording | pcap | `.scshr` (post-decrypt SRTP packets + timestamps), replayable by `scshr_sender`/`scshr_replay` |

Session recovery logic (FIR/NACK/LTR ack, SSRC adoption, quality gate, DPB-break escalation, stall watchdog,
AVC SPS DPB patch, HW→SW fallback latch) ported 1:1; tests port the reference pytest cases.

## Zero-copy status

- **AVC 4:2:0 D3D11VA (production path on Windows): zero-copy.** `D3D11VA bound: surfaces=nv12 pool=25 …
  BIND_DECODER|BIND_SHADER_RESOURCE → zero-copy`; soak: `zero-copy=32006 gpu-copy=0 cpu-upload=0`.
- **HEVC Main 4:2:0 D3D11VA: zero-copy** (same code path; the synthetic HEVC stream is 4:4:4 so this was
  exercised only by unit-level probe, `not measured` end to end).
- **HEVC 4:4:4:** no D3D11VA profile in FFmpeg 9.0.1/driver → software decode, CPU upload (`cpu-upload=617`),
  explicitly labelled in the log. `--codec auto` therefore offers H.264 on Windows (probe decode decides).
- GPU-copy fallback exists for drivers that refuse `BIND_SHADER_RESOURCE` on decoder surfaces; never triggered here.

## Performance (dev box, emulated network, `scshr_sender` loopback; 1080p60 x264 source ~30 Mbps)

| Metric | Contract (target laptop) | Python baseline | C++ dev box | Notes |
|---|---|---|---|---|
| Stable 1080p60 ≥ 10 min | required | not measured | **10 min, 35 959 AUs, 33 720 presented, ws 105–110 MB flat, pool 256/8192, q=0** | `e2e_soak.log` |
| AU→Present p50 / p95 / p99 | ≤ 8 / 12 / 16.7 ms | not measured | **0.39 / 12.9 / 16.7 ms** (soak); 0.36 / 0.66 / 0.96 ms (12 s run) | p95 in soak includes 19 sender loop seams |
| decoded→present | ≤ 2 ms | not measured | **0.03 ms p50**, 0.06 p95 (12 s), 12.4 p95 (soak, seams) | |
| Present interval p99 | ≤ 20 ms | not measured | **17.0 ms** (soak), 17.2–17.3 (RTT runs) | max 1–2 s = first-frame wait at start |
| Decode latency (HW) | — | not measured | 0.29 / 0.39 / 0.51 ms p50/p95/p99 | |
| SRTP throughput | ≥ 100k pkt/s | not measured | **552 860 pkt/s** (SRTP), 496 146 pkt/s full packet core | `scshr_bench` |
| CPU (process) | ≤ 10–12 % | not measured | 0.3–0.5 % of 24 threads (≈ 8–12 % of one core) | HEVC SW: 2.8 % |
| Memory | bounded, < 512 MB | not measured | 105–163 MB working set | |
| RTT 30 / 60 / 100 ms (emulated) | — | not measured | AU→present p50 0.35 / 0.34 / 0.33 ms, interval p99 17.3 ms all | receiver adds no RTT-dependent latency |
| RTT 30 + jitter σ5 ms (emulated) | — | not measured | AU→present p99 0.82 ms; interval p95/p99 22.3 / 24.8 ms | no jitter buffer by policy; jitter shows in cadence |
| RTT 30 + 0.5 % loss / RTT 60 + 1 % loss (emulated) | — | not measured | recovery fires (fir=17/19, restarts 1/2), video stalls between keyframes | sender cannot retransmit or produce on-demand IDRs — measures recovery logic, not live quality |
| HEVC 4:4:4 (software) | — | not measured | decode 9.4 / 10.4 / 11.5 ms, AU→present p50 10.2 ms, interval p99 18.3 ms | labelled SW path |
| Glass-to-glass, target laptop, live Mac | — | not measured | not measured | no hardware available |

## Compatibility verification

- `scshr_tests`: 21/21 (assembler wrap/reorder/repair/marker TTL, seq tracking, quality gate sticky/grace,
  NAL edge cases, record layer, SRP, bplist, offers, clipboard).
- `tests/diff_vectors.py`: 79/79 byte-exact vs Python (SRTP KDF/decrypt/encrypt, SRTCP, enc1103 record layer,
  RFB builders incl. 0x1c/0x1d/0x451 parse, bplist, MediaBlob, SRP math with fixed `a`, NAL reassembly).
- `tests/diff_replay.py`: 10/10 recordings event-for-event (burst, flush order/incomplete flags, drop reasons,
  seq events, auth failures) — clean/loss/reorder+dup/seq wrap/SSRC switch/restart/corrupt/30 s AVC, clean/loss HEVC.
- H.264 and HEVC both exercised (HEVC via 4:4:4 software path; HEVC D3D11VA path shares code, not exercised end to end).
- Live macOS host handshake (SRP/RSA, enc1103, 0x1c offer acceptance, cursor/clipboard/audio): **not verified**.

## Application tunnel

Sessions run over a dedicated one-Windows ↔ one-macOS WireGuard peering (`10.77.77.2 → 10.77.77.1`,
exact `/32` routes only, no DNS/default-route/NAT/forwarding change) with mandatory PF isolation of
Screen Sharing on the Mac. Windows embeds upstream `tunnel.dll` (wireguard-windows v0.6.1
embeddable-dll-service) over WireGuardNT 1.1; the media hot path is unchanged and unaware of it.
Production sessions fail closed with no public/LAN fallback. See [TUNNEL.md](TUNNEL.md).

Verified statically: 34/34 `scshr_tests` (13 tunnel cases), 24/24 `tests/tunnel_shell_test.sh`,
79/79 protocol vectors, 10/10 replay differentials, and a loopback e2e run
(`zero-copy=325 gpu-copy=0 cpu-upload=0`). **Live macOS interoperability is unverified** — no Mac was
available; the deferred hardware checklist is in TUNNEL.md.

## Remaining limitations

1. No live-host test; protocol correctness rests on the executable-spec differential only.
2. HEVC 4:4:4 hardware decode unavailable on D3D11VA → Windows sessions negotiate H.264 4:2:0.
3. Loss tests are bounded by the emulated sender (no NACK service, keyframes only at recording cadence).
4. Multi-window mode compiled and reviewed but not exercised (needs a multi-monitor host); secondary windows
   present without blocking the primary (skipped when their swapchain is busy).
5. Recording is `.scshr`, not pcap.
6. Target-laptop numbers not measured; dev-box GPU is much faster than a 3050 Ti — decode/present headroom
   there is unknown, though the pipeline has no CPU frame work to scale with GPU speed.
7. Synth recording timestamps fixed this session (`packets % 7` spread was non-monotone; caused spurious
   reordering when the sender applied delay). Recordings regenerated via `tools/gen_testdata.sh`.

## Build / run

```powershell
.\tools\fetch_deps.ps1 ; .\build.ps1
.\build\Release\scshr_tests.exe
.\.venv-oracle\Scripts\python tests\diff_vectors.py ; .\.venv-oracle\Scripts\python tests\diff_replay.py
.\build\Release\scshr.exe --host mac.local -u me            # live
bash tools/e2e.sh testdata/avc_30s.scshr 600 soak --stats-interval 30     # loopback soak
bash tools/e2e.sh testdata/avc_clean.scshr 12 rtt60 -- --delay-ms 30 --jitter-ms 5 --loss 0.5   # emulated WAN
```
