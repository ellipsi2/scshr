#pragma once
// Blocking TCP client socket with per-call timeouts (control channel only; not on the media hot path).
#include "common/bytes.h"

#include <functional>
#include <optional>
#include <string>
#include <utility>

namespace scshr::net {

void winsock_init();  // idempotent WSAStartup

class TcpSocket {
public:
    TcpSocket() = default;
    ~TcpSocket();
    TcpSocket(const TcpSocket&) = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;
    TcpSocket(TcpSocket&& o) noexcept { *this = std::move(o); }
    TcpSocket& operator=(TcpSocket&& o) noexcept { if (this != &o) { close(); s_ = o.s_; timeout_s_ = o.timeout_s_; cancel_ = std::move(o.cancel_); o.s_ = ~0ull; } return *this; }

    // Connects (IPv4 literal or resolvable host). Throws std::runtime_error with a friendly message on failure.
    static TcpSocket connect(const std::string& host, uint16_t port, double timeout_s, const std::function<bool()>& cancelled = {});
    bool valid() const { return s_ != ~0ull; }
    void close();
    void close_rst();  // SO_LINGER {1,0} → RST so screensharingd tears the session down promptly

    void set_timeout(double seconds);                           // logical timeout for the read calls below
    // Polled while a read waits (the connect timeouts here run to a minute); when it returns true the
    // wait throws instead of running out, so a closing window is not held up by the handshake.
    void set_cancel(std::function<bool()> c) { cancel_ = std::move(c); }
    void send_all(ByteView data);                               // throws on error
    Bytes recv_exact(size_t n);                                 // throws on timeout / EOF
    // Up to `max` bytes or empty on timeout; throws on error/EOF.
    Bytes recv_some(size_t max, bool* timed_out = nullptr);
    Bytes peek(size_t n, double timeout_s);                     // MSG_PEEK; empty on timeout
    uintptr_t native() const { return s_; }
private:
    // Waits for readability in slices, polling cancel_. false = the logical timeout expired.
    bool wait_readable(double timeout_s);
    uintptr_t s_ = ~0ull;
    double timeout_s_ = 15.0;
    std::function<bool()> cancel_;
};

// Resolve to an IPv4 dotted literal (the UDP media transport is IPv4-only). Throws with guidance if no A record.
std::string resolve_ipv4(const std::string& host);

}  // namespace scshr::net
