#pragma once
// Blocking TCP client socket with per-call timeouts (control channel only; not on the media hot path).
#include "common/bytes.h"

#include <optional>
#include <string>

namespace scshr::net {

void winsock_init();  // idempotent WSAStartup

class TcpSocket {
public:
    TcpSocket() = default;
    ~TcpSocket();
    TcpSocket(const TcpSocket&) = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;
    TcpSocket(TcpSocket&& o) noexcept { s_ = o.s_; o.s_ = ~0ull; }
    TcpSocket& operator=(TcpSocket&& o) noexcept { if (this != &o) { close(); s_ = o.s_; o.s_ = ~0ull; } return *this; }

    // Connects (IPv4 literal or resolvable host). Throws std::runtime_error with a friendly message on failure.
    static TcpSocket connect(const std::string& host, uint16_t port, double timeout_s);
    bool valid() const { return s_ != ~0ull; }
    void close();
    void close_rst();  // SO_LINGER {1,0} → RST so screensharingd tears the session down promptly

    void set_timeout(double seconds);
    void send_all(ByteView data);                               // throws on error
    Bytes recv_exact(size_t n);                                 // throws on timeout / EOF
    // Up to `max` bytes or empty on timeout; throws on error/EOF.
    Bytes recv_some(size_t max, bool* timed_out = nullptr);
    Bytes peek(size_t n, double timeout_s);                     // MSG_PEEK; empty on timeout
    uintptr_t native() const { return s_; }
private:
    uintptr_t s_ = ~0ull;
};

// Resolve to an IPv4 dotted literal (the UDP media transport is IPv4-only). Throws with guidance if no A record.
std::string resolve_ipv4(const std::string& host);

}  // namespace scshr::net
