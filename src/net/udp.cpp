#include "net/udp.h"
#include "common/clock.h"
#include "common/log.h"
#include "net/tcp.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>

#include <stdexcept>

namespace scshr::net {

UdpSocket::~UdpSocket() { close(); }

void UdpSocket::bind(const std::string& host, uint16_t port, int rcvbuf) {
    winsock_init();
    SOCKET s = WSASocketW(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (s == INVALID_SOCKET) throw std::runtime_error("UDP socket() failed");
    BOOL one = TRUE;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&one), sizeof one);
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char*>(&rcvbuf), sizeof rcvbuf);
    // Don't surface ICMP port-unreachable as WSAECONNRESET on the next recv (firewall punches hit closed ports).
    DWORD bytes = 0; BOOL off = FALSE;
    WSAIoctl(s, SIO_UDP_CONNRESET, &off, sizeof off, nullptr, 0, &bytes, nullptr, nullptr);
    sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons(port);
    if (host.empty()) sa.sin_addr.s_addr = INADDR_ANY; else inet_pton(AF_INET, host.c_str(), &sa.sin_addr);
    if (::bind(s, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0) {
        const int err = WSAGetLastError(); closesocket(s);
        throw std::runtime_error("UDP bind " + (host.empty() ? std::string("0.0.0.0") : host) + ":" + std::to_string(port) + " failed (error " + std::to_string(err) + ")");
    }
    s_ = uintptr_t(s);
}

void UdpSocket::close() { if (valid()) { closesocket(SOCKET(s_)); s_ = ~0ull; } }

void UdpSocket::send_to(ByteView d, const std::string& ip, uint16_t port) {
    sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = htons(port);
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    ::sendto(SOCKET(s_), reinterpret_cast<const char*>(d.data()), int(d.size()), 0, reinterpret_cast<sockaddr*>(&sa), sizeof sa);
}

int UdpSocket::recv(uint8_t* buf, size_t cap, int timeout_ms) {
    fd_set rd; FD_ZERO(&rd); FD_SET(SOCKET(s_), &rd);
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    const int rc = select(0, &rd, nullptr, nullptr, &tv);
    if (rc == 0) return 0;
    if (rc < 0) return -1;
    sockaddr_in from{}; int fl = sizeof from;
    const int n = ::recvfrom(SOCKET(s_), reinterpret_cast<char*>(buf), int(cap), 0, reinterpret_cast<sockaddr*>(&from), &fl);
    return n < 0 ? -1 : n;
}

// ── IOCP receiver ───────────────────────────────────────────────────────────
struct IocpReceiver::Op {
    OVERLAPPED ov{};
    WSABUF buf{};
    sockaddr_in from{};
    int from_len = sizeof(sockaddr_in);
    DWORD flags = 0;
    uint32_t slot = UINT32_MAX;
};

IocpReceiver::IocpReceiver(UdpSocket& sock, PacketPool& pool, uint32_t depth) : sock_(sock), pool_(pool) {
    iocp_ = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 1);
    if (!iocp_ || !CreateIoCompletionPort(reinterpret_cast<HANDLE>(sock.native()), iocp_, 1, 0)) throw std::runtime_error("CreateIoCompletionPort failed");
    // Skip the completion-port post when the receive completes synchronously? No: we always want
    // completions queued so a single wait loop drains everything in order.
    for (uint32_t i = 0; i < depth; ++i) { Op* op = new Op(); ops_.push_back(op); post(*op); }
}

IocpReceiver::~IocpReceiver() {
    stop();
    for (Op* op : ops_) delete op;
    if (iocp_) CloseHandle(iocp_);
}

void IocpReceiver::stop() {
    stopping_ = true;
    if (iocp_) PostQueuedCompletionStatus(iocp_, 0, 0, nullptr);
}

void IocpReceiver::post(Op& op) {
    if (stopping_) return;
    if (op.slot == UINT32_MAX) {
        op.slot = pool_.acquire();
        if (op.slot == UINT32_MAX) { ++pool_exhausted; unposted_.push_back(&op); return; }
    }
    PacketSlot& s = pool_[op.slot];
    op.buf.buf = reinterpret_cast<char*>(s.data);
    op.buf.len = PACKET_SLOT_BYTES;
    op.flags = 0;
    op.from_len = sizeof op.from;
    std::memset(&op.ov, 0, sizeof op.ov);
    DWORD recvd = 0;
    const int rc = WSARecvFrom(SOCKET(sock_.native()), &op.buf, 1, &recvd, &op.flags, reinterpret_cast<sockaddr*>(&op.from), &op.from_len, &op.ov, nullptr);
    if (rc == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
        ++recv_errors;
        // Retry later from wait(); keep the slot.
        unposted_.push_back(&op);
    }
}

bool IocpReceiver::wait(int timeout_ms, RecvBatch& out) {
    out.items.clear();
    // Repost any ops that were starved of pool slots or failed transiently.
    if (!unposted_.empty()) {
        std::vector<Op*> retry; retry.swap(unposted_);
        for (Op* op : retry) post(*op);
    }
    OVERLAPPED_ENTRY entries[64];
    ULONG n = 0;
    if (!GetQueuedCompletionStatusEx(iocp_, entries, 64, &n, DWORD(timeout_ms), FALSE)) {
        return GetLastError() == WAIT_TIMEOUT ? !stopping_ : !stopping_;
    }
    const int64_t t = now_ns();
    for (ULONG i = 0; i < n; ++i) {
        if (!entries[i].lpOverlapped) { if (entries[i].lpCompletionKey == 0) return false; continue; }
        Op* op = reinterpret_cast<Op*>(entries[i].lpOverlapped);
        DWORD nbytes = 0, flags = 0;
        const BOOL ok = WSAGetOverlappedResult(SOCKET(sock_.native()), &op->ov, &nbytes, FALSE, &flags);
        if (ok && nbytes > 0 && op->slot != UINT32_MAX) {
            PacketSlot& s = pool_[op->slot];
            s.len = nbytes; s.t_recv_ns = t; s.payload_off = 0; s.payload_len = 0;
            out.items.push_back({op->slot});
            ++datagrams; this->bytes += nbytes;
            op->slot = UINT32_MAX;   // ownership passed to caller
        } else if (!ok) {
            ++recv_errors;
        }
        post(*op);
    }
    return !stopping_;
}

}  // namespace scshr::net
