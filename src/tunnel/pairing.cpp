#include "tunnel/pairing.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace scshr::tunnel {
namespace {

const char kUrlAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const char kStdAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int alphabet_index(const char* alphabet, char c) {
    if (c == 0) return -1;
    const char* p = std::strchr(alphabet, c);
    return p ? int(p - alphabet) : -1;
}

std::string b64_encode(const std::string& raw, const char* alphabet, bool pad) {
    std::string out;
    out.reserve((raw.size() + 2) / 3 * 4);
    size_t i = 0;
    for (; i + 3 <= raw.size(); i += 3) {
        const uint32_t v = (uint32_t(uint8_t(raw[i])) << 16) | (uint32_t(uint8_t(raw[i + 1])) << 8) | uint8_t(raw[i + 2]);
        out.push_back(alphabet[(v >> 18) & 63]); out.push_back(alphabet[(v >> 12) & 63]);
        out.push_back(alphabet[(v >> 6) & 63]);  out.push_back(alphabet[v & 63]);
    }
    if (i < raw.size()) {
        const size_t rem = raw.size() - i;
        uint32_t v = uint32_t(uint8_t(raw[i])) << 16;
        if (rem == 2) v |= uint32_t(uint8_t(raw[i + 1])) << 8;
        out.push_back(alphabet[(v >> 18) & 63]);
        out.push_back(alphabet[(v >> 12) & 63]);
        if (rem == 2) out.push_back(alphabet[(v >> 6) & 63]);
        else if (pad) out.push_back('=');
        if (pad) out.push_back('=');
    }
    return out;
}

// Strict decode: no whitespace, no stray padding, canonical trailing bits.
bool b64_decode(const std::string& in, const char* alphabet, bool require_pad, std::string& out) {
    std::string body = in;
    size_t pad = 0;
    if (require_pad) {
        if (body.empty() || body.size() % 4 != 0) return false;
        while (!body.empty() && body.back() == '=') { body.pop_back(); ++pad; }
        if (pad > 2) return false;
    } else {
        if (body.find('=') != std::string::npos) return false;
    }
    if (body.size() % 4 == 1) return false;
    out.clear();
    out.reserve(body.size() * 3 / 4);
    uint32_t acc = 0;
    int bits = 0;
    for (char c : body) {
        const int v = alphabet_index(alphabet, c);
        if (v < 0) return false;
        acc = (acc << 6) | uint32_t(v);
        bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back(char((acc >> bits) & 0xff)); }
    }
    if (bits >= 6) return false;
    if (bits && (acc & ((1u << bits) - 1)) != 0) return false;   // non-canonical trailing bits
    return true;
}

bool parse_ipv4(const std::string& s, uint32_t& out) {
    uint32_t v = 0;
    int octets = 0;
    size_t i = 0;
    if (s.empty()) return false;
    while (i < s.size()) {
        if (!std::isdigit(uint8_t(s[i]))) return false;
        int digits = 0, n = 0;
        while (i < s.size() && std::isdigit(uint8_t(s[i]))) {
            if (++digits > 3) return false;
            n = n * 10 + (s[i++] - '0');
        }
        if (digits > 1 && n < 10) return false;        // reject leading zeros
        if (n > 255) return false;
        v = (v << 8) | uint32_t(n);
        if (++octets > 4) return false;
        if (i < s.size()) {
            if (s[i] != '.') return false;
            ++i;
            if (i == s.size()) return false;
        }
    }
    if (octets != 4) return false;
    out = v;
    return true;
}

// Bracketless IPv6, hex groups with at most one "::". Deliberately minimal: enough to reject
// junk in a pairing descriptor; the OS still does the real resolution.
bool parse_ipv6(const std::string& s, std::array<uint8_t, 16>& out) {
    if (s.empty() || s.size() > 45) return false;
    std::vector<uint16_t> head, tail;
    bool after_gap = false;
    size_t i = 0;
    if (s.compare(0, 2, "::") == 0) { after_gap = true; i = 2; if (i == s.size()) { out.fill(0); return true; } }
    else if (s[0] == ':') return false;
    size_t groups_seen = 0;
    while (i < s.size()) {
        int digits = 0;
        uint32_t g = 0;
        while (i < s.size() && std::isxdigit(uint8_t(s[i]))) {
            if (++digits > 4) return false;
            const char c = char(std::tolower(uint8_t(s[i++])));
            g = g * 16 + uint32_t(c <= '9' ? c - '0' : c - 'a' + 10);
        }
        if (digits == 0) return false;
        (after_gap ? tail : head).push_back(uint16_t(g));
        if (++groups_seen > 8) return false;
        if (i == s.size()) break;
        if (s[i] != ':') return false;
        ++i;
        if (i < s.size() && s[i] == ':') {
            if (after_gap) return false;
            after_gap = true;
            ++i;
            if (i == s.size()) break;
        } else if (i == s.size()) {
            return false;                              // trailing single colon
        }
    }
    const size_t total = head.size() + tail.size();
    if (after_gap) { if (total > 7) return false; }
    else if (total != 8) return false;
    std::vector<uint16_t> full(head);
    full.insert(full.end(), 8 - total, 0);
    full.insert(full.end(), tail.begin(), tail.end());
    for (size_t k = 0; k < 8; ++k) { out[2 * k] = uint8_t(full[k] >> 8); out[2 * k + 1] = uint8_t(full[k] & 0xff); }
    return true;
}

bool ipv4_usable_endpoint(uint32_t v) {
    if (v == 0 || v == 0xffffffffu) return false;                  // unspecified / limited broadcast
    if ((v >> 24) == 127) return false;                            // loopback
    if ((v >> 28) == 0xE) return false;                            // 224.0.0.0/4 multicast
    if ((v >> 28) == 0xF) return false;                            // 240.0.0.0/4 reserved
    return true;
}

bool valid_hostname(const std::string& h) {
    if (h.empty() || h.size() > 253) return false;
    if (h.front() == '.' || h.back() == '.') return false;
    size_t label = 0;
    for (size_t i = 0; i < h.size(); ++i) {
        const char c = h[i];
        if (c == '.') {
            if (label == 0) return false;
            label = 0;
            continue;
        }
        if (!(std::isalnum(uint8_t(c)) || c == '-')) return false;
        if (c == '-' && (label == 0 || i + 1 == h.size() || h[i + 1] == '.')) return false;
        if (++label > 63) return false;
    }
    if (label == 0) return false;
    // All-digits-and-dots would have been an IPv4 literal; reject so "999.1.2.3" cannot pass as a name.
    if (h.find_first_not_of("0123456789.") == std::string::npos) return false;
    return true;
}

bool split_cidr(const std::string& cidr, uint32_t& addr, int& len) {
    const size_t slash = cidr.find('/');
    if (slash == std::string::npos) return false;
    const std::string a = cidr.substr(0, slash), l = cidr.substr(slash + 1);
    if (l.empty() || l.size() > 2 || l.find_first_not_of("0123456789") != std::string::npos) return false;
    if (l.size() > 1 && l[0] == '0') return false;
    len = std::stoi(l);
    if (len > 32) return false;
    return parse_ipv4(a, addr);
}

struct Field { const char* key; std::string value; };

// Strict line decoder: exactly the expected keys, in order, one "k=v" per line, nothing else.
bool parse_fields(const std::string& body, std::vector<Field>& fields, std::string& error) {
    size_t pos = 0, idx = 0;
    while (true) {
        const size_t nl = body.find('\n', pos);
        const std::string line = body.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos);
        if (idx >= fields.size()) { error = "unexpected extra field"; return false; }
        const std::string want = std::string(fields[idx].key) + "=";
        if (line.size() <= want.size() || line.compare(0, want.size(), want) != 0) {
            error = std::string("expected field ") + fields[idx].key;
            return false;
        }
        fields[idx].value = line.substr(want.size());
        ++idx;
        if (nl == std::string::npos) break;
        pos = nl + 1;
        if (pos == body.size()) { error = "trailing newline"; return false; }
    }
    if (idx != fields.size()) { error = "missing fields"; return false; }
    return true;
}

bool parse_port(const std::string& s, uint16_t& out) {
    if (s.empty() || s.size() > 5 || s.find_first_not_of("0123456789") != std::string::npos) return false;
    if (s.size() > 1 && s[0] == '0') return false;
    const long v = std::stol(s);
    if (v < 1 || v > 65535) return false;
    out = uint16_t(v);
    return true;
}

bool decode_prefixed(const std::string& code, const char* prefix, std::string& body, std::string& error) {
    const size_t plen = std::strlen(prefix);
    if (code.size() <= plen || code.compare(0, plen, prefix) != 0) {
        // Precise reason for the common "pasted a code from a newer/older format" case.
        if (code.size() > plen && code.compare(0, plen - 2, prefix, plen - 2) == 0 && code[plen - 1] == ':')
            error = "unsupported descriptor version";
        else
            error = "not a " + std::string(prefix, plen - 1) + " descriptor";
        return false;
    }
    const std::string payload = code.substr(plen);
    if (payload.size() > 1024) { error = "descriptor too long"; return false; }
    if (!base64url_decode(payload, body)) { error = "invalid base64url payload"; return false; }
    if (body.empty()) { error = "empty payload"; return false; }
    return true;
}

}  // namespace

std::string base64url_encode(const std::string& raw) { return b64_encode(raw, kUrlAlphabet, /*pad=*/false); }
std::string base64_std_encode(const std::string& raw) { return b64_encode(raw, kStdAlphabet, /*pad=*/true); }
bool base64url_decode(const std::string& in, std::string& out) { return b64_decode(in, kUrlAlphabet, /*require_pad=*/false, out); }

bool valid_wg_key(const std::string& b64) {
    if (b64.size() != 44 || b64[43] != '=' || b64[42] == '=') return false;
    std::string raw;
    if (!b64_decode(b64, kStdAlphabet, /*require_pad=*/true, raw)) return false;
    return raw.size() == 32;
}

bool wg_key_bytes(const std::string& b64, std::string& raw32) {
    if (!valid_wg_key(b64)) return false;
    return b64_decode(b64, kStdAlphabet, /*require_pad=*/true, raw32) && raw32.size() == 32;
}

bool valid_endpoint_host(const std::string& host) {
    if (host.empty() || host.size() > 255) return false;
    if (host.front() == '[') {
        if (host.size() < 4 || host.back() != ']') return false;
        std::array<uint8_t, 16> a{};
        if (!parse_ipv6(host.substr(1, host.size() - 2), a)) return false;
        if (std::all_of(a.begin(), a.end(), [](uint8_t b) { return b == 0; })) return false;   // ::
        if (a[0] == 0xff) return false;                                                        // ff00::/8 multicast
        bool loopback = a[15] == 1;
        for (size_t i = 0; i < 15 && loopback; ++i) loopback = a[i] == 0;
        return !loopback;                                                                      // ::1
    }
    uint32_t v = 0;
    if (parse_ipv4(host, v)) return ipv4_usable_endpoint(v);
    return valid_hostname(host);
}

bool valid_tunnel_ip(const std::string& ip) {
    uint32_t v = 0, net = 0;
    int len = 0;
    if (!parse_ipv4(ip, v)) return false;
    if (!split_cidr(kTunnelSubnet, net, len)) return false;
    const uint32_t mask = len == 0 ? 0 : (0xffffffffu << (32 - len));
    if ((v & mask) != (net & mask)) return false;
    if (v == (net & mask)) return false;                 // network address
    if (v == ((net & mask) | ~mask)) return false;       // subnet broadcast
    return true;
}

bool route_allowed(const std::string& cidr, std::string* why) {
    auto fail = [&](const char* r) { if (why) *why = r; return false; };
    uint32_t addr = 0;
    int len = 0;
    if (!split_cidr(cidr, addr, len)) return fail("not a valid IPv4 CIDR");
    if (len != 32) return fail("only exact /32 host routes are permitted");
    if (addr == 0) return fail("unspecified address");
    if ((addr >> 24) == 127) return fail("loopback address");
    if ((addr >> 28) == 0xE) return fail("multicast address");
    if (addr == 0xffffffffu) return fail("broadcast address");
    if (!valid_tunnel_ip(cidr.substr(0, cidr.find('/')))) return fail("outside the scshr tunnel subnet 10.77.77.0/24");
    if (why) why->clear();
    return true;
}

std::string redact_secrets(const std::string& text) {
    static const char* kKeys[] = {"PrivateKey", "private_key", "PresharedKey", "preshared_key"};
    std::string out = text;
    for (const char* k : kKeys) {
        const size_t klen = std::strlen(k);
        size_t p = 0;
        while ((p = out.find(k, p)) != std::string::npos) {
            size_t v = p + klen;
            while (v < out.size() && (out[v] == ' ' || out[v] == '=' || out[v] == '\t')) ++v;
            size_t e = v;
            while (e < out.size() && out[e] != '\n' && out[e] != '\r') ++e;
            out.replace(v, e - v, "<redacted>");
            p = v + 10;
        }
    }
    return out;
}

std::string encode_server(const ServerDescriptor& d) {
    if (!valid_wg_key(d.public_key)) throw std::invalid_argument("server descriptor: invalid WireGuard public key");
    if (!valid_endpoint_host(d.endpoint_host)) throw std::invalid_argument("server descriptor: invalid endpoint host");
    if (d.listen_port == 0) throw std::invalid_argument("server descriptor: invalid listen port");
    if (!valid_tunnel_ip(d.mac_ip)) throw std::invalid_argument("server descriptor: invalid mac tunnel IP");
    if (!valid_tunnel_ip(d.win_ip)) throw std::invalid_argument("server descriptor: invalid windows tunnel IP");
    if (d.mac_ip == d.win_ip) throw std::invalid_argument("server descriptor: tunnel IPs must differ");
    const std::string body = "k=" + d.public_key + "\ne=" + d.endpoint_host + "\np=" + std::to_string(d.listen_port) +
                             "\ns=" + d.mac_ip + "\nc=" + d.win_ip;
    return "SCST1:" + base64url_encode(body);
}

std::string encode_client(const ClientDescriptor& d) {
    if (!valid_wg_key(d.public_key)) throw std::invalid_argument("client descriptor: invalid WireGuard public key");
    if (!valid_tunnel_ip(d.win_ip)) throw std::invalid_argument("client descriptor: invalid windows tunnel IP");
    return "SCCL1:" + base64url_encode("k=" + d.public_key + "\nc=" + d.win_ip);
}

bool decode_server(const std::string& code, ServerDescriptor& out, std::string& error) {
    std::string body;
    if (!decode_prefixed(code, "SCST1:", body, error)) return false;
    std::vector<Field> f{{"k", ""}, {"e", ""}, {"p", ""}, {"s", ""}, {"c", ""}};
    if (!parse_fields(body, f, error)) return false;
    ServerDescriptor d;
    d.public_key = f[0].value;
    d.endpoint_host = f[1].value;
    if (!parse_port(f[2].value, d.listen_port)) { error = "invalid listen port"; return false; }
    d.mac_ip = f[3].value;
    d.win_ip = f[4].value;
    if (!valid_wg_key(d.public_key)) { error = "invalid WireGuard public key"; return false; }
    if (!valid_endpoint_host(d.endpoint_host)) { error = "invalid endpoint host"; return false; }
    if (!valid_tunnel_ip(d.mac_ip)) { error = "mac tunnel IP outside " + std::string(kTunnelSubnet); return false; }
    if (!valid_tunnel_ip(d.win_ip)) { error = "windows tunnel IP outside " + std::string(kTunnelSubnet); return false; }
    if (d.mac_ip == d.win_ip) { error = "tunnel IPs must differ"; return false; }
    if (!route_allowed(d.mac_ip + "/32", &error)) return false;
    out = d;
    error.clear();
    return true;
}

bool decode_client(const std::string& code, ClientDescriptor& out, std::string& error) {
    std::string body;
    if (!decode_prefixed(code, "SCCL1:", body, error)) return false;
    std::vector<Field> f{{"k", ""}, {"c", ""}};
    if (!parse_fields(body, f, error)) return false;
    ClientDescriptor d;
    d.public_key = f[0].value;
    d.win_ip = f[1].value;
    if (!valid_wg_key(d.public_key)) { error = "invalid WireGuard public key"; return false; }
    if (!valid_tunnel_ip(d.win_ip)) { error = "windows tunnel IP outside " + std::string(kTunnelSubnet); return false; }
    if (!route_allowed(d.win_ip + "/32", &error)) return false;
    out = d;
    error.clear();
    return true;
}

}  // namespace scshr::tunnel
