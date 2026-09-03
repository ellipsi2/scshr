#pragma once
// scshr pairing descriptors + route policy.
//
// Two versioned, strictly-decoded public descriptors carry everything the two machines need to
// build a one-peer WireGuard tunnel. They never contain private key material.
//
//   SCST1:<base64url>   macOS/server → Windows   (mac public key, public endpoint, listen port, tunnel IPs)
//   SCCL1:<base64url>   Windows/client → macOS   (windows public key, windows tunnel IP)
//
// The "1" in the prefix is the format version; any other prefix is rejected.
// This translation unit is platform-independent and has no WireGuard dependency: it is pure
// parsing/validation so it can be unit-tested on any host.
#include <cstdint>
#include <string>

namespace scshr::tunnel {

// ── defaults (RFC1918 /24 reserved for scshr; only two hosts ever live in it) ─────────────
inline constexpr const char* kDefaultMacTunnelIp = "10.77.77.1";
inline constexpr const char* kDefaultWinTunnelIp = "10.77.77.2";
inline constexpr uint16_t kDefaultListenPort = 51820;
inline constexpr int kPersistentKeepalive = 25;
inline constexpr const char* kTunnelName = "scshr";          // adapter name, conf basename, service suffix
inline constexpr const char* kTunnelSubnet = "10.77.77.0/24";

// ── primitives ────────────────────────────────────────────────────────────────────────────
std::string base64url_encode(const std::string& raw);
// Standard (padded) base64 — the spelling WireGuard itself uses for keys.
std::string base64_std_encode(const std::string& raw);
// Strict: rejects padding, '+', '/', whitespace and any non-alphabet byte. false on failure.
bool base64url_decode(const std::string& in, std::string& out);

// A WireGuard key is 32 bytes in canonical padded standard base64 (44 chars, trailing '=').
// Non-canonical encodings (trailing bits set) are rejected so a key has exactly one spelling.
bool valid_wg_key(const std::string& b64);
// Decodes a validated key to its 32 raw bytes; false if the key does not validate.
bool wg_key_bytes(const std::string& b64, std::string& raw32);

// Hostname (RFC 1123 labels), IPv4 literal, or bracketed IPv6 literal. Rejects unspecified,
// loopback, multicast and broadcast literals; rejects empty/oversized/ill-formed names.
bool valid_endpoint_host(const std::string& host);

// Must be a literal IPv4 address inside kTunnelSubnet and not the network/broadcast address.
bool valid_tunnel_ip(const std::string& ip);

// Route policy: the ONLY shape this feature ever installs is a single host route to the peer.
// Rejects default routes, every RFC1918 block, multicast, and anything wider than /32.
bool route_allowed(const std::string& cidr, std::string* why = nullptr);

// Replaces WireGuard private/preshared key material with "<redacted>" (used before any log/print).
std::string redact_secrets(const std::string& text);

// ── descriptors ───────────────────────────────────────────────────────────────────────────
struct ServerDescriptor {
    std::string public_key;      // mac WireGuard public key
    std::string endpoint_host;   // public hostname or IP of the mac
    uint16_t listen_port = kDefaultListenPort;
    std::string mac_ip = kDefaultMacTunnelIp;
    std::string win_ip = kDefaultWinTunnelIp;   // tunnel IP the mac expects the windows peer to use
};

struct ClientDescriptor {
    std::string public_key;      // windows WireGuard public key
    std::string win_ip = kDefaultWinTunnelIp;
};

// Encoders throw std::invalid_argument if the descriptor does not validate (never emit junk).
std::string encode_server(const ServerDescriptor& d);
std::string encode_client(const ClientDescriptor& d);

// Decoders are strict: exact prefix, exact key set in exact order, no unknown fields, no
// duplicate fields, no trailing data. `error` receives a short reason on failure.
bool decode_server(const std::string& code, ServerDescriptor& out, std::string& error);
bool decode_client(const std::string& code, ClientDescriptor& out, std::string& error);

}  // namespace scshr::tunnel
