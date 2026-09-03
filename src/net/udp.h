#pragma once
// IOCP-driven UDP receiver: N overlapped WSARecvFrom preposted into PacketPool slots; the packet
// thread waits on the completion port and gets datagram slots back with receive timestamps.
// A single completion-port wait per packet (or batched via GetQueuedCompletionStatusEx).
#include "common/bytes.h"
#include "media/packet_pool.h"

#include <cstdint>
#include <string>
#include <vector>

namespace scshr::net {

class UdpSocket {
public:
    UdpSocket() = default;
    ~UdpSocket();
    UdpSocket(const UdpSocket&) = delete;
    UdpSocket& operator=(const UdpSocket&) = delete;

    // Binds IPv4 UDP on `bind_host` (empty = INADDR_ANY) : `port`, SO_RCVBUF = rcvbuf.
    void bind(const std::string& bind_host, uint16_t port, int rcvbuf = 8 << 20);
    void close();
    bool valid() const { return s_ != ~0ull; }
    uintptr_t native() const { return s_; }
    void send_to(ByteView data, const std::string& ip, uint16_t port);
    // Blocking receive with timeout (ms). Returns bytes received, 0 on timeout, <0 on error.
    int recv(uint8_t* buf, size_t cap, int timeout_ms);
private:
    uintptr_t s_ = ~0ull;
};

struct RecvBatch {
    struct Item { uint32_t slot; };
    std::vector<Item> items;
};

class IocpReceiver {
public:
    // `depth` = number of receives kept in flight. Slots come from `pool` (must outlive the receiver).
    IocpReceiver(UdpSocket& sock, PacketPool& pool, uint32_t depth);
    ~IocpReceiver();
    IocpReceiver(const IocpReceiver&) = delete;
    IocpReceiver& operator=(const IocpReceiver&) = delete;

    // Wait up to timeout_ms for completions; returns completed slots (ownership passes to caller).
    // Slot fields len / t_recv_ns are filled. Caller must eventually pool.release() or hand the slot on.
    // Returns false on shutdown. `pool_exhausted` counts receives that could not be reposted.
    bool wait(int timeout_ms, RecvBatch& out);
    void stop();
    uint64_t pool_exhausted = 0, recv_errors = 0, datagrams = 0, bytes = 0;

private:
    struct Op;
    void post(Op& op);
    UdpSocket& sock_;
    PacketPool& pool_;
    void* iocp_ = nullptr;
    std::vector<Op*> ops_;
    std::vector<Op*> unposted_;   // ops waiting for a free slot
    bool stopping_ = false;
};

}  // namespace scshr::net
