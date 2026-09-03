#pragma once
// Windows side of the scshr application tunnel.
//
// Architecture (upstream WireGuard "embeddable-dll-service"):
//
//   scshr.exe init                       elevates, owns identity + config + service lifecycle
//        │
//        ├── tunnel.dll   (wireguard-windows v0.6.1, embeddable-dll-service)
//        │     WireGuardTunnelService(conf)   → runs the tunnel inside our own service process
//        │     WireGuardGenerateKeypair()     → Curve25519 keypair, generated locally
//        └── wireguard.dll (WireGuardNT 1.1)  → the kernel data path, loaded by tunnel.dll
//
//   Service "WireGuardTunnel$scshr"  →  "scshr.exe /wireguard-service <conf>"  →  tunnel.dll
//
// This layer sits strictly below the session: nothing here touches sockets, media or the record
// layer. The session simply connects to the peer's tunnel address and the OS routes it.
#include "tunnel/wgconfig.h"

#include <optional>
#include <string>
#include <vector>

namespace scshr::tunnel {

// Non-secret, persisted so repeated `scshr init` reconciles instead of re-pairing.
struct TunnelState {
    std::string local_public_key;
    std::string peer_public_key;
    std::string endpoint_host;
    uint16_t endpoint_port = kDefaultListenPort;
    std::string win_ip = kDefaultWinTunnelIp;
    std::string mac_ip = kDefaultMacTunnelIp;
};

struct Paths {
    std::wstring dir;         // %ProgramData%\scshr           (SYSTEM + Administrators only)
    std::wstring conf;        // %ProgramData%\scshr\scshr.conf
    std::wstring identity;    // DPAPI-protected private key blob
    std::wstring pubkey;      // local public key (not secret)
    std::wstring state;       // TunnelState
};
Paths paths();

// ── process ───────────────────────────────────────────────────────────────────────────────
bool is_elevated();
// Re-runs this executable with the same arguments through the UAC "runas" verb and waits.
// Returns the child's exit code. Throws std::runtime_error if elevation was refused.
int relaunch_elevated(int argc, char** argv);

// ── bundled components ────────────────────────────────────────────────────────────────────
struct Components { std::wstring tunnel_dll, wireguard_dll; };
// Locates tunnel.dll + wireguard.dll next to the executable. Throws with the fetch instructions
// if either is missing. Called before anything is mutated.
Components validate_components();

// Generates a Curve25519 keypair with tunnel.dll (never leaves this machine).
struct KeyPair { std::string public_key, private_key; };
KeyPair generate_keypair(const Components& c);

// ── identity (survives repeated init; never rotated automatically) ─────────────────────────
// Loads the stored identity, creating one on first use. `created` reports which happened.
KeyPair load_or_create_identity(const Components& c, bool& created);

// ── secure files (SYSTEM + Administrators only; used for state, settings and host-key pins) ─
void ensure_secure_dir(const std::wstring& dir);
void write_secure_file(const std::wstring& path, const std::string& data);
std::optional<std::string> read_file(const std::wstring& path);
std::string narrow(const std::wstring& w);   // UTF-16 → UTF-8
std::wstring widen(const std::string& s);    // UTF-8 → UTF-16
std::wstring exe_dir();

// ── state ─────────────────────────────────────────────────────────────────────────────────
std::optional<TunnelState> load_state();
void save_state(const TunnelState& s);

// ── service ───────────────────────────────────────────────────────────────────────────────
enum class ServiceState { Absent, Stopped, StartPending, Running, Other };
ServiceState service_state();
// Installs the service if absent, or corrects its binary path if it drifted. Idempotent.
void install_service();
void start_service();
void stop_service();
void delete_service();

// ── config ────────────────────────────────────────────────────────────────────────────────
// Writes the conf only when the rendered bytes differ. Returns true if the file changed.
bool write_conf_if_changed(const std::string& rendered);
// Current on-disk configuration, for restoring it if installation fails half-way.
std::optional<std::string> read_conf();
void restore_conf(const std::optional<std::string>& previous);

// ── runtime status / route validation ─────────────────────────────────────────────────────
// Queries the tunnel through the WireGuard userspace API named pipe. False if the tunnel is not
// running or the pipe is unavailable (that is a normal state, not an error).
bool query_status(TunnelStatus& out, std::string& error);

struct RouteAudit {
    bool tunnel_interface_present = false;
    bool peer_route_via_tunnel = false;      // 10.77.77.1 resolves to the scshr adapter, prefix /32
    bool no_default_route_on_tunnel = false; // no 0.0.0.0/0 or ::/0 bound to the scshr adapter
    bool internet_bypasses_tunnel = false;   // a public address still routes off the scshr adapter
    bool no_dns_on_tunnel = false;           // the scshr adapter publishes no DNS servers
    std::vector<std::string> problems;
    bool ok() const { return problems.empty(); }
};
RouteAudit audit_routes(const std::string& peer_ip);

// ── service entry point (scshr.exe /wireguard-service <conf>) ─────────────────────────────
int run_tunnel_service(const wchar_t* conf_path);

// ── uninstall ─────────────────────────────────────────────────────────────────────────────
// Removes the scshr service, config and state. Keeps the identity unless `reset_identity`.
void uninstall(bool reset_identity, std::vector<std::string>& removed);

}  // namespace scshr::tunnel
