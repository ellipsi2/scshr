#pragma once
// RTP (SSRC, timestamp) group assembly with the exact ordering / repair-window / eviction semantics of
// proxy/session.py (_queue_video_group_packet, _group_complete, _ordered_group_keys, _flush_ready_groups,
// _flush_group, _drop_incomplete_group, _evict_stale_groups, _track_seq). Time is injected (ns) so the
// replay tool is deterministic. Packet payloads live in PacketPool slots owned by the assembler until
// the group flushes or drops.
#include "common/bytes.h"
#include "media/packet_pool.h"

#include <functional>
#include <set>
#include <unordered_map>
#include <vector>

namespace scshr {

enum class VideoCodec { Hevc, Avc };

struct GroupPacket { uint16_t seq; bool marker; uint32_t slot; };

struct FlushedGroup {
    uint32_t ssrc, ts;
    std::vector<GroupPacket> packets;      // circularly sequence-ordered
    std::vector<ByteView> payloads;        // same order (views into pool slots; valid during the callback only)
    bool incomplete;                       // sequence gap inside the group
    int64_t t_first_ns, t_last_ns;         // first/last packet receive time
    size_t bytes;
};

struct DroppedGroup { uint32_t ssrc, ts; bool had_marker; const char* reason; size_t packets; int64_t age_ns; };

struct SeqEvent { uint32_t ssrc; uint16_t seq; int lost; bool late; bool dup; };  // per packet, from track_seq

class RtpAssembler {
public:
    explicit RtpAssembler(PacketPool& pool, VideoCodec codec);

    // Sequence tracking (all SSRCs). Fills NACK candidates and loss counters.
    SeqEvent track_seq(uint32_t ssrc, uint16_t seq, int64_t now_ns);
    // Queue one decrypted packet whose payload lives in pool slot `slot` (assembler takes ownership of the slot).
    void queue_packet(uint32_t ssrc, uint32_t ts, uint16_t seq, bool marker, uint32_t slot, int64_t now_ns);
    void evict_stale(int64_t now_ns);
    void reset();                          // session teardown / restart

    std::function<void(FlushedGroup&)> on_flush;
    std::function<void(const DroppedGroup&)> on_drop;

    // NACK candidates drained by the TX loop.
    std::unordered_map<uint32_t, std::set<uint16_t>>& nack_pending() { return nack_pending_; }
    struct SsrcSeq { uint16_t max_seq = 0; uint32_t roc = 0; };
    const std::unordered_map<uint32_t, SsrcSeq>& seq_state() const { return seq_; }
    uint64_t received_pkts = 0, lost_pkts = 0;
    int64_t last_video_pkt_ns = 0;
    size_t pending_groups() const { return groups_.size(); }
    size_t reorder_depth() const;          // packets held in pending groups
    uint64_t incomplete_flushed = 0, dropped_groups = 0;

    // Tunables (ns) — same defaults as the reference.
    int64_t avc_repair_wait_ns = 75'000'000;
    int64_t pending_group_ttl_ns = 200'000'000;
    int64_t flushed_dedup_ttl_ns = 2'000'000'000;

private:
    struct Group {
        uint32_t ssrc, ts;
        std::vector<GroupPacket> pkts;
        int64_t arrival_ns;
        int64_t repair_deadline_ns = 0;   // 0 = none
        bool has_marker = false;
    };
    using Key = uint64_t;
    static Key key(uint32_t ssrc, uint32_t ts) { return (uint64_t(ssrc) << 32) | ts; }
    Group* find(Key k);
    std::vector<GroupPacket> sorted_packets(const Group& g) const;
    bool group_complete(const Group& g, const std::vector<GroupPacket>& sorted) const;
    std::vector<Key> ordered_keys(uint32_t ssrc) const;
    void flush_group(Key k, int64_t now_ns);
    void flush_ready(uint32_t ssrc, int64_t now_ns);
    void drop_group(Key k, const char* reason, int64_t now_ns, std::set<uint32_t>& unblocked);
    void release_group(Group& g);

    PacketPool& pool_;
    VideoCodec codec_;
    std::unordered_map<Key, Group> groups_;
    std::vector<Key> group_order_;      // insertion order (reference iterates dicts in insertion order)
    std::vector<Key> deadline_order_;   // order repair deadlines were armed
    std::unordered_map<Key, int64_t> recently_flushed_;
    std::unordered_map<uint32_t, uint16_t> last_marker_seq_;   // per SSRC
    std::unordered_map<uint32_t, SsrcSeq> seq_;
    std::unordered_map<uint32_t, std::set<uint16_t>> nack_pending_;
    std::vector<ByteView> payload_scratch_;
};

}  // namespace scshr
