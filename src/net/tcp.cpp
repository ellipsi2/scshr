#include "net/tcp.h"
#include "common/log.h"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <mutex>
#include <stdexcept>

namespace scshr::net {

void winsock_init() {
    static std::once_flag once;
    std::call_once(once, [] { WSADATA w; WSAStartup(MAKEWORD(2, 2), &w); });
}

namespace {
[[noreturn]] void fail(const std::string& what) { throw std::runtime_error(what + " (WSAGetLastError=" + std::to_string(WSAGetLastError()) + ")"); }
}

std::string resolve_ipv4(const std::string& host) {
    winsock_init();
    addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res)
        throw std::runtime_error(host + " did not resolve to an IPv4 address. The screen-share UDP transport is IPv4-only; connect using the Mac's IPv4 address instead of a hostname.");
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr, buf, sizeof buf);
    freeaddrinfo(res);
    return buf;
}

TcpSocket::~TcpSocket() { close(); }

void TcpSocket::close() {
    if (valid()) { closesocket(SOCKET(s_)); s_ = ~0ull; }
}

void TcpSocket::close_rst() {
    if (!valid()) return;
    linger l{1, 0};
    setsockopt(SOCKET(s_), SOL_SOCKET, SO_LINGER, reinterpret_cast<const char*>(&l), sizeof l);
    close();
}

TcpSocket TcpSocket::connect(const std::string& host, uint16_t port, double timeout_s) {
    winsock_init();
    const std::string ip = resolve_ipv4(host);
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) fail("socket()");
    sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
    int rc = ::connect(s, reinterpret_cast<sockaddr*>(&sa), sizeof sa);
    if (rc == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK) { closesocket(s); fail("connect()"); }
    fd_set wr, ex; FD_ZERO(&wr); FD_ZERO(&ex); FD_SET(s, &wr); FD_SET(s, &ex);
    timeval tv{long(timeout_s), long((timeout_s - long(timeout_s)) * 1e6)};
    rc = select(0, nullptr, &wr, &ex, &tv);
    if (rc == 0) { closesocket(s); throw std::runtime_error(host + ":" + std::to_string(port) + " did not respond. The host may be off, on a different network, behind a firewall, or its IP may have changed."); }
    if (rc < 0 || FD_ISSET(s, &ex)) {
        int err = 0; int len = sizeof err; getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len);
        closesocket(s);
        if (err == WSAECONNREFUSED) throw std::runtime_error(host + ":" + std::to_string(port) + " actively rejected the connection. Check that Screen Sharing is enabled in System Settings > General > Sharing, or that the port is right.");
        throw std::runtime_error("can't connect to " + host + ":" + std::to_string(port) + " (error " + std::to_string(err) + ")");
    }
    nb = 0; ioctlsocket(s, FIONBIO, &nb);
    BOOL one = TRUE; setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&one), sizeof one);
    TcpSocket t; t.s_ = uintptr_t(s);
    t.set_timeout(timeout_s);
    return t;
}

void TcpSocket::set_timeout(double seconds) {
    DWORD ms = DWORD(seconds * 1000.0);
    setsockopt(SOCKET(s_), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof ms);
    setsockopt(SOCKET(s_), SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&ms), sizeof ms);
}

void TcpSocket::send_all(ByteView d) {
    size_t off = 0;
    while (off < d.size()) {
        int n = ::send(SOCKET(s_), reinterpret_cast<const char*>(d.data() + off), int(d.size() - off), 0);
        if (n <= 0) fail("send()");
        off += size_t(n);
    }
}

Bytes TcpSocket::recv_exact(size_t n) {
    Bytes out(n);
    size_t off = 0;
    while (off < n) {
        int r = ::recv(SOCKET(s_), reinterpret_cast<char*>(out.data() + off), int(n - off), 0);
        if (r == 0) throw std::runtime_error("peer closed during recv_exact");
        if (r < 0) { if (WSAGetLastError() == WSAETIMEDOUT) throw std::runtime_error("recv timeout"); fail("recv()"); }
        off += size_t(r);
    }
    return out;
}

Bytes TcpSocket::recv_some(size_t max, bool* timed_out) {
    Bytes out(max);
    if (timed_out) *timed_out = false;
    int r = ::recv(SOCKET(s_), reinterpret_cast<char*>(out.data()), int(max), 0);
    if (r == 0) throw std::runtime_error("peer closed");
    if (r < 0) {
        if (WSAGetLastError() == WSAETIMEDOUT) { if (timed_out) *timed_out = true; return {}; }
        fail("recv()");
    }
    out.resize(size_t(r));
    return out;
}

Bytes TcpSocket::peek(size_t n, double timeout_s) {
    DWORD ms = DWORD(timeout_s * 1000.0);
    setsockopt(SOCKET(s_), SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&ms), sizeof ms);
    Bytes out(n);
    int r = ::recv(SOCKET(s_), reinterpret_cast<char*>(out.data()), int(n), MSG_PEEK);
    set_timeout(15.0);
    if (r <= 0) return {};
    out.resize(size_t(r));
    return out;
}

}  // namespace scshr::net
