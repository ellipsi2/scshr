#pragma once
// Built-in pairing: everything needed to go from "I can SSH into the Mac" to "the tunnel is up and
// Screen Sharing answers through it", driven entirely from Windows.
//
//   1. SSH to the Mac (password or keyboard-interactive; host key pinned on first use)
//   2. upload the macOS helper bundle (mac/ next to scshr.exe) to a private temp dir
//   3. `preflight`  on the Mac (macOS version, CPU, Screen Sharing state, PF present)
//   4. `init`       on the Mac (identity, tunnel daemon, firewall isolation, LaunchDaemon) → SCST1
//   5. install the Windows half from that SCST1 (tunnel::* via tunnel_cli) → SCCL1
//   6. `pair`       on the Mac with the SCCL1
//   7. `enable-screen-sharing` on the Mac (idempotent)
//   8. verify: WireGuard handshake + ICMP to the peer + TCP 5900 RFB banner through the tunnel
//
// Every remote privileged step runs `sudo -S -p '' <script> …` with the SSH password on stdin, so
// the user types one password once. Nothing here ever prints or logs a password.
#include "app/settings.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace scshr::app {

struct SetupRequest {
    std::string ssh_host;              // as typed: "host" or "host:port"
    std::string ssh_user;
    std::string password;              // used for SSH and sudo; never stored
    std::string endpoint_override;     // WireGuard endpoint if different from the SSH host ("" = same)
    uint16_t listen_port = 51820;      // Mac-side WireGuard UDP port
    std::string expected_hostkey;      // from previous settings ("" = trust on first use)
};

struct SetupProgress {
    // step is 1-based; total is the number of steps for a progress bar.
    std::function<void(int step, int total, const std::string& title)> on_step;
    std::function<void(const std::string& line)> on_log;      // detailed, safe to show verbatim
    std::function<bool()> cancelled;                          // polled between steps (may be empty)
};

struct SetupOutcome {
    bool ok = false;
    std::string headline;              // one plain-language sentence for the user
    std::string detail;                // what to do next / why it failed (plain language)
    std::vector<std::string> warnings; // non-fatal findings (e.g. "UDP port not reachable yet")
    bool handshake_seen = false;
    bool screen_sharing_reachable = false;
    std::string hostkey_sha256;        // fingerprint actually seen (persist it on success)
    std::string mac_arch, macos_version;
};

// Runs the whole flow on the calling thread (use a worker thread from the GUI). Never throws;
// all failures are reported in the outcome with user-facing wording. Requires Administrator.
SetupOutcome run_setup(const SetupRequest& req, const SetupProgress& progress);

// ── status / verification (no SSH needed) ────────────────────────────────────────────────────
struct LinkStatus {
    bool configured = false;           // Windows tunnel state + settings present
    bool service_running = false;
    bool handshake_recent = false;     // last WireGuard handshake < 3 minutes ago
    int64_t last_handshake_unix = 0;
    bool peer_pings = false;           // ICMP echo to the Mac's tunnel address answered
    bool screen_sharing_reachable = false;   // TCP 5900 through the tunnel returned an RFB banner
    std::string rfb_banner;            // e.g. "RFB 003.889"
    std::string problem;               // plain-language description when something is off
};
LinkStatus check_link(int timeout_ms = 3000);

// Sends ICMP echo requests to `ip` for up to `total_ms`; true on the first reply. `cancelled`, when
// supplied, is polled between echoes and abandons the wait.
bool ping_peer(const std::string& ip, int total_ms, const std::function<bool()>& cancelled = {});
// Connects to ip:port and reads the RFB version banner. True if it starts with "RFB ".
bool probe_rfb(const std::string& ip, uint16_t port, std::string& banner, int timeout_ms,
               const std::function<bool()>& cancelled = {});

// Removes the Windows half (service, config, state, settings, remembered password). If `req` is
// given, also runs `uninstall` on the Mac over SSH. Never throws; returns human-readable lines.
std::vector<std::string> run_unpair(const SetupRequest* req, bool reset_identity);

// Pulls the SCST1 code out of arbitrary command output ("" if absent). Unit-tested.
std::string extract_server_code(const std::string& text);
// Parses `key=value` lines produced by the macOS `preflight` command into the outcome fields.
struct Preflight { std::string macos_version, arch, screen_sharing, pf_conf, helper, firewall; bool ok = false; std::string error; };
Preflight parse_preflight(const std::string& text);

}  // namespace scshr::app
