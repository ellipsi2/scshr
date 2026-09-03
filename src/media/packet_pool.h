#pragma once
// Fixed-size preallocated packet buffers. The UDP receiver posts receives into free slots; a slot stays
// owned by the RTP assembler while its payload is part of a pending access-unit group, then returns
// to the free list. No per-packet heap allocation anywhere on the media path.
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace scshr {

constexpr size_t PACKET_SLOT_BYTES = 2048;   // > any UDP datagram Apple emits (~1300 B); 64 KiB jumbo not expected

struct PacketSlot {
    alignas(64) uint8_t data[PACKET_SLOT_BYTES];
    uint32_t len = 0;             // datagram length
    int64_t t_recv_ns = 0;        // receive completion timestamp
    uint32_t payload_off = 0;     // set after SRTP decrypt
    uint32_t payload_len = 0;
};

class PacketPool {
public:
    explicit PacketPool(uint32_t count) : slots_(new PacketSlot[count]), count_(count) {
        free_.reserve(count);
        for (uint32_t i = count; i-- > 0;) free_.push_back(i);
    }
    uint32_t capacity() const { return count_; }
    uint32_t free_count() const { return uint32_t(free_.size()); }
    uint32_t in_use() const { return count_ - uint32_t(free_.size()); }
    // Returns UINT32_MAX when exhausted.
    uint32_t acquire() { if (free_.empty()) return UINT32_MAX; uint32_t i = free_.back(); free_.pop_back(); return i; }
    void release(uint32_t i) { free_.push_back(i); }
    PacketSlot& operator[](uint32_t i) { return slots_[i]; }
    const PacketSlot& operator[](uint32_t i) const { return slots_[i]; }
private:
    std::unique_ptr<PacketSlot[]> slots_;
    uint32_t count_;
    std::vector<uint32_t> free_;
};

}  // namespace scshr
