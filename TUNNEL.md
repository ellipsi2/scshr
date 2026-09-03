# scshr application tunnel

A dedicated one-Windows ↔ one-macOS WireGuard peering that carries scshr traffic and nothing else.

```
Windows scshr  →  10.77.77.2/32  →  WireGuard  →  10.77.77.1  →  Screen Sharing / scshr protocols
```

It is **not** a VPN. Ordinary Windows traffic keeps using the normal network; the Mac never forwards,
NATs or acts as an exit node. The only routes installed are:

| Machine | Route |
|---|---|
| Windows | `10.77.77.1/32` via the `scshr` WireGuard adapter |
| macOS | `10.77.77.2/32` via the `scshr` WireGuard interface |

## Setup

The built-in wizard (`scshr.exe` → **Set up**, or `scshr setup --mac HOST --mac-user USER`) does every step
below from Windows over SSH: it uploads the `mac/` helper bundle, runs `preflight` / `init` / `pair` /
`enable-screen-sharing` through `sudo -S` (password on stdin, never on a command line or in a log),
installs the Windows half, then verifies the handshake (ICMP to the peer) and the RFB banner on TCP 5900
through the tunnel. The SSH host key is pinned on first use (SHA-256 in the settings file) and a later
mismatch aborts before authentication. The manual exchange remains available:

```bash
# macOS
sudo ./mac/scshr-macos-tunnel.sh init --endpoint my-mac.example.net
# → SCST1:<server-code>
```

```powershell
# Windows
.\scshr.exe init
# paste the SCST1 code
# → SCCL1:<client-code>
```

```bash
# macOS
sudo ./tools/scshr-macos-tunnel.sh pair 'SCCL1:<client-code>'
```

```powershell
# Windows
.\scshr.exe status
.\scshr.exe -u me            # no host argument: production sessions always use the paired peer
```

If the Mac is behind NAT, forward `udp/51820` to it. Nothing else needs to be reachable from outside.

## What each side owns

**Windows** (`scshr init`, all of it inside `scshr.exe`):

* validates the bundled WireGuard components (`tunnel.dll`, `wireguard.dll`),
* elevates through normal UAC when required,
* generates a Curve25519 identity locally and stores the private half DPAPI-protected
  (`CRYPTPROTECT_LOCAL_MACHINE`) under `%ProgramData%\scshr`, ACL'd to SYSTEM + Administrators only,
* strictly decodes the `SCST1` descriptor,
* renders `%ProgramData%\scshr\scshr.conf` with `AllowedIPs = 10.77.77.1/32` and no `DNS`, `Table` or `MTU`,
* installs/reconciles the service `WireGuardTunnel$scshr` →
  `scshr.exe /wireguard-service <conf>` → `tunnel.dll!WireGuardTunnelService`,
* verifies afterwards that the peer address routes over the tunnel as a `/32`, that no default route
  is bound to the adapter, that public traffic still leaves over the normal network, and that the
  adapter publishes no DNS servers — rolling the installation back if any of that fails,
* prints the public `SCCL1` descriptor.

Re-running `scshr init` reconciles the existing configuration and never rotates the identity.

**macOS** (`tools/scshr-macos-tunnel.sh` + `tools/mac-tunnel`, shipped as the `mac/` folder): self-contained
on a stock Mac — bash 3.2, no Homebrew. `scshr-tunnel-darwin-{arm64,amd64}` is a static Go binary
(wireguard-go in userspace) that generates keys, validates the configuration (fail closed: one `/32`
peer inside `10.77.77.0/24`, no DNS/MTU/Table/Endpoint keys), runs the tunnel in the foreground and
answers `status` over its UAPI socket `/var/run/wireguard/scshr.sock`. The script owns identity,
settings, configuration, the LaunchDaemon (`net.scshr.tunnel`, KeepAlive, runs `<script> run`, which
activates PF first and refuses to start the tunnel otherwise), the mandatory PF isolation anchor,
`preflight` / `enable-screen-sharing` for the wizard, status and uninstall.

## Screen Sharing isolation (mandatory)

The Mac-side ports scshr uses are TCP 5900 (control/RFB record layer), UDP 5900 (audio + RTCP) and
UDP 5901 (video). A dedicated PF anchor `/etc/pf.anchors/scshr`, loaded from two appended lines in
`/etc/pf.conf`, allows them only from the tunnel peer:

```
pass  in quick proto udp from any        to any        port 51820          # WireGuard, public
pass  in quick proto tcp from 127.0.0.1  to 127.0.0.1  port { 5900 }       # local loopback
pass  in quick proto udp from 127.0.0.1  to 127.0.0.1  port { 5900 5901 }
pass  in quick proto tcp from 10.77.77.2 to 10.77.77.1 port { 5900 }       # the paired peer
pass  in quick proto udp from 10.77.77.2 to 10.77.77.1 port { 5900 5901 }
block drop in quick proto tcp from any to any port { 5900 }                # everyone else
block drop in quick proto udp from any to any port { 5900 5901 }
```

Rules are address-based, never interface-based, because the `utunN` number is not stable.
`/etc/pf.conf` is backed up before the edit, the whole ruleset is validated with `pfctl -n -f`
before activation, and a failed activation restores the backup. If isolation cannot be installed,
`init` fails instead of reporting success with Screen Sharing exposed.

## Fail-closed behaviour

Before every production session scshr requires: stored pairing state, the service running, the peer
`/32` route resolving to the scshr adapter, no default route on the adapter, and a live tunnel whose
peer public key and `AllowedIPs` match the stored pairing. Any failure aborts the session — there is
no fallback to the Mac's public or LAN address.

`--direct --host H` bypasses all of it for development, and `--replay-key` (loopback replay) is
likewise exempt. Direct mode is never entered implicitly.

Application-level authentication, the enc1103 record layer and SRTP are unchanged: WireGuard sits
below the socket layer and the media hot path (IOCP → SRTP → RTP → D3D11VA) is untouched.

## Status and removal

`status` and production sessions read Administrator-only state (`%ProgramData%\scshr`, ACL'd to
SYSTEM + Administrators) and query the WireGuardNT driver, so both need an elevated console.

```powershell
.\scshr.exe status                              # state, addresses, endpoint, key fingerprints,
                                                # handshake age, byte counters, route validation
.\scshr.exe tunnel uninstall [--reset-identity]
```

```bash
sudo /usr/local/libexec/scshr-macos-tunnel.sh status
sudo /usr/local/libexec/scshr-macos-tunnel.sh uninstall [--reset-identity]
```

`scshr unpair` (or the GUI's **Remove**) removes the Windows half and, given the Mac's administrator
password, runs the Mac-side `uninstall` over SSH as well.

Uninstall removes only scshr-owned state: our service/interface, our config, our PF anchor and the two
lines it added to `/etc/pf.conf`, our LaunchDaemon, the installed helper and script under
`/usr/local/libexec`, and on Windows the settings file and the remembered Screen Sharing password. Other WireGuard tunnels, other PF anchors and the
WireGuard software itself are never touched. Identity keys are preserved unless `--reset-identity`.

## Pairing descriptors

Public only — a private key never crosses a machine, never appears in a descriptor, a log or a
diagnostic. Both are `<prefix>:<base64url>` over a fixed, strictly ordered field list; the `1` in the
prefix is the format version and any other prefix is rejected.

| | Fields |
|---|---|
| `SCST1` (macOS → Windows) | mac public key, endpoint host, listen port, mac tunnel IP, expected Windows tunnel IP |
| `SCCL1` (Windows → macOS) | Windows public key, Windows tunnel IP |

Decoding rejects invalid base64url, padding, unknown/duplicate/reordered/extra fields, trailing data,
non-canonical or wrong-length keys, malformed endpoints, loopback/multicast/broadcast/unspecified
endpoint literals, out-of-range ports, addresses outside `10.77.77.0/24`, and any route wider than
`/32`.

## Tests

```powershell
.\build\Release\scshr_tests.exe tunnel     # descriptors, route policy, config, status, redaction
```

```bash
bash tests/tunnel_shell_test.sh            # macOS script: syntax, config/PF goldens, strict decoding
```

`tests/tunnel_shell_test.sh` compares the shell encoder's `SCST1`/`SCCL1` output against the same
golden strings the C++ encoder is checked against, so the two implementations verify each other. It also
checks the LaunchDaemon plist golden, the `preflight` key set the Windows parser expects, and that the
script depends on neither wireguard-tools nor bash 4. `go test ./tools/mac-tunnel` covers the helper's
configuration parser/validator and UAPI rendering; `scshr_tests setup` covers the Windows-side parsing
(SCST1 extraction from script output, preflight, settings, SSH host syntax).

## Deferred real-Mac validation

**No macOS system was available; live interoperability is unverified.** The following must be run on
real hardware before this is considered working end to end:

1. Clean install on a fresh Mac (`init` with no prior state).
2. Key persistence across reboot; `init` re-run does not rotate the identity.
3. Windows `init` + `SCST1`/`SCCL1` exchange in both directions.
4. WireGuard handshake completes (`wg show` / `scshr status`).
5. `10.77.77.2 ↔ 10.77.77.1` ICMP/UDP/TCP connectivity.
6. Windows default route and DNS unchanged (`route print`, `ipconfig /all`) before vs after.
7. Ordinary Windows Internet traffic still leaves over the physical NIC (traceroute).
8. `sysctl net.inet.ip.forwarding` still `0`; no NAT anchor added on the Mac.
9. Screen Sharing refused on the Mac's LAN and public addresses (from a third machine).
10. Screen Sharing reachable on `10.77.77.1` from the paired peer.
11. An unpaired WireGuard peer is rejected (no handshake).
12. An ordinary LAN client cannot reach TCP 5900 / UDP 5900-5901.
13. Full session: video, audio, input, cursor, clipboard.
14. Reconnect after a WAN interruption (keepalive 25 s).
15. Endpoint/network change on either side (roaming).
16. Reboot recovery on both machines (service + LaunchDaemon).
17. `uninstall` on both sides removes only scshr state; `/etc/pf.conf` returns to its prior content.
18. CPU, throughput, latency and pacing measured with the tunnel in the path.
19. 1080p60 ten-minute soak over the tunnel.
20. Emulated ~30 / 60 / 100 ms RTT.
21. Representative Korea↔Japan jitter and loss.
22. The wizard end to end from a non-elevated desktop: UAC prompt, SSH password and keyboard-interactive
    authentication against macOS sshd, SCP upload, every `sudo -S` step, host-key pin persisted and a
    changed key refused.
23. `launchctl load -w` of `net.scshr.tunnel` and of `com.apple.screensharing` on macOS 14 and 15
    (bootstrap semantics, already-loaded case, behaviour when Screen Sharing was never enabled in the GUI).
24. The Go helper on a real utun: `ifconfig … alias`, `route add -interface`, UAPI socket creation under
    `/var/run/wireguard`, SIGTERM teardown, restart by KeepAlive after a crash.
25. macOS Application Firewall simply *on* (not only "block all incoming"/stealth): `init` registers the
    helper with `socketfilterfw --add/--unblockapp`; confirm UDP 51820 reaches the daemon with the firewall
    on, and that `uninstall`'s `--remove` leaves no entry behind.
27. Re-running `init`/`pair` while the daemon is up: the script waits for the old helper to release
    `/var/run/wireguard/scshr.sock` before reloading; confirm no "unix socket in use" restart loop.
28. A cancelled or failed wizard run after `init`: the Mac must be rolled back (`uninstall` over the same
    SSH session) so other Screen Sharing clients are not left blocked.
26. `fdk-aac.dll` decoding live AAC-ELD-SBR audio (only synthetic data has been through the decoder path).

MTU is left at the platform default. Any explicit MTU change must be treated as provisional until
item 21 has been measured on a real WAN.
