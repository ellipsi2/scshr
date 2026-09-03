#pragma once
// WireGuard configuration rendering for the scshr tunnel.
//
// Rendering is deterministic (same inputs → byte-identical file) so `scshr init` can be idempotent:
// it rewrites the tunnel only when the rendered text actually differs from what is on disk.
// Platform-independent and dependency-free so it is unit-testable.
#include "tunnel/pairing.h"

#include <cstdint>
#include <string>

namespace scshr::tunnel {

struct WindowsTunnelConfig {
    std::string private_key;      // local, never leaves this machine
    std::string win_ip = kDefaultWinTunnelIp;
    std::string peer_public_key;  // the mac
    std::string peer_ip = kDefaultMacTunnelIp;
    std::string endpoint_host;
    uint16_t endpoint_port = kDefaultListenPort;
};

// Throws std::invalid_argument if anything fails validation (including the route policy on the
// peer AllowedIPs). Emits no DNS, no MTU, no Table and no default route by construction.
std::string render_windows_conf(const WindowsTunnelConfig& c);

// Non-secret half of the config, safe to log/print.
std::string describe_windows_conf(const WindowsTunnelConfig& c);

// Short, stable, non-secret identifier for a public key: first 16 hex digits of SHA-256(key bytes).
std::string key_fingerprint(const std::string& public_key_b64);

// ── live tunnel status (read from the WireGuardNT driver by win_tunnel.cpp) ────────────────
struct TunnelStatus {
    bool valid = false;
    std::string interface_public_key;
    uint16_t listen_port = 0;
    std::string peer_public_key;
    std::string endpoint;             // as reported by the driver, "ip:port"
    std::string allowed_ip;           // the peer's first allowed IP, "ip/cidr"
    uint64_t rx_bytes = 0, tx_bytes = 0;
    int64_t last_handshake_unix = 0;  // 0 = never
    uint16_t persistent_keepalive = 0;
};

}  // namespace scshr::tunnel
