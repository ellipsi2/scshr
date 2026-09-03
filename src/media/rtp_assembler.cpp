#include "media/rtp_assembler.h"

#include <algorithm>

namespace scshr {

RtpAssembler::RtpAssembler(PacketPool& pool, VideoCodec codec) : pool_(pool), codec_(codec) {}

void RtpAssembler::reset() {
    for (auto& kv : groups_) release_group(kv.second);
    groups_.clear(); group_order_.clear(); deadline_order_.clear(); recently_flushed_.clear(); last_marker_seq_.clear(); seq_.clear(); nack_pending_.clear();
}

size_t RtpAssembler::reorder_depth() const { size_t n = 0; for (auto& kv : groups_) n += kv.second.pkts.size(); return n; }

RtpAssembler::Group* RtpAssembler::find(Key k) { auto it = groups_.find(k); return it == groups_.end() ? nullptr : &it->second; }

void RtpAssembler::release_group(Group& g) { for (auto& p : g.pkts) pool_.release(p.slot); g.pkts.clear(); }

SeqEvent RtpAssembler::track_seq(uint32_t ssrc, uint16_t seq, int64_t now_ns) {
    SeqEvent ev{ssrc, seq, 0, false, false};
    ++received_pkts;
    last_video_pkt_ns = now_ns;
    auto it = seq_.find(ssrc);
    if (it == seq_.end()) { seq_[ssrc] = SsrcSeq{seq, 0}; return ev; }
    SsrcSeq& st = it->second;
    const uint16_t diff = uint16_t(seq - st.max_seq);
    if (diff == 0) { ev.dup = true; return ev; }
    if (diff > 0x8000) { nack_pending_[ssrc].erase(seq); ev.late = true; return ev; }
    const int missed_max = std::min<int>(diff, 32);
    for (int m = 1; m < missed_max; ++m) { nack_pending_[ssrc].insert(uint16_t(st.max_seq + m)); ++lost_pkts; ++ev.lost; }
    if (seq < st.max_seq) ++st.roc;
    st.max_seq = seq;
    return ev;
}

std::vector<GroupPacket> RtpAssembler::sorted_packets(const Group& g) const {
    std::vector<GroupPacket> p = g.pkts;
    std::sort(p.begin(), p.end(), [](const GroupPacket& a, const GroupPacket& b) { return a.seq < b.seq; });
    if (p.size() < 2 || uint16_t(p.back().seq - p.front().seq) <= 0x8000) return p;
    // Start right after the largest circular gap (handles 65534,65535,0,1 etc.).
    size_t gap_idx = 0; uint16_t best = 0;
    for (size_t i = 0; i < p.size(); ++i) {
        const uint16_t gap = uint16_t(p[(i + 1) % p.size()].seq - p[i].seq);
        if (gap >= best) { best = gap; gap_idx = i; }   // >= keeps Python's max() tie-break (last max index)
    }
    const size_t start = (gap_idx + 1) % p.size();
    std::vector<GroupPacket> out(p.begin() + ptrdiff_t(start), p.end());
    out.insert(out.end(), p.begin(), p.begin() + ptrdiff_t(start));
    return out;
}

bool RtpAssembler::group_complete(const Group& g, const std::vector<GroupPacket>& s) const {
    if (s.empty() || !g.has_marker) return false;
    if (!s.back().marker) return false;
    for (size_t i = 0; i + 1 < s.size(); ++i) if (uint16_t(s[i + 1].seq - s[i].seq) > 1) return false;
    auto it = last_marker_seq_.find(g.ssrc);
    return it == last_marker_seq_.end() || s.front().seq == uint16_t(it->second + 1);
}

std::vector<RtpAssembler::Key> RtpAssembler::ordered_keys(uint32_t ssrc) const {
    std::vector<std::pair<std::pair<double, int64_t>, Key>> ks;
    auto it = last_marker_seq_.find(ssrc);
    for (Key key : group_order_) {
        auto git = groups_.find(key);
        if (git == groups_.end() || git->second.ssrc != ssrc) continue;
        const Group& g = git->second;
        double dist;
        if (it == last_marker_seq_.end()) dist = 0;  // arrival order only
        else if (g.pkts.empty()) dist = 1e18;
        else { const uint16_t first = sorted_packets(g).front().seq; dist = double(uint16_t(first - uint16_t(it->second + 1))); }
        ks.push_back({{dist, g.arrival_ns}, key});
    }
    std::stable_sort(ks.begin(), ks.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
    std::vector<Key> out; out.reserve(ks.size());
    for (auto& k : ks) out.push_back(k.second);
    return out;
}

void RtpAssembler::queue_packet(uint32_t ssrc, uint32_t ts, uint16_t seq, bool marker, uint32_t slot, int64_t now_ns) {
    const Key k = key(ssrc, ts);
    if (recently_flushed_.count(k)) { pool_.release(slot); return; }
    Group* g = find(k);
    if (!g) { g = &groups_.emplace(k, Group{ssrc, ts, {}, now_ns}).first->second; group_order_.push_back(k); }
    bool dup = false;
    for (auto& p : g->pkts) if (p.seq == seq) { dup = true; break; }
    if (dup) { pool_.release(slot); }
    else { g->pkts.push_back({seq, marker, slot}); if (marker) g->has_marker = true; }
    if (!g->has_marker) return;
    if (codec_ != VideoCodec::Avc) { flush_group(k, now_ns); return; }

    std::vector<Key> ordered = ordered_keys(ssrc);
    size_t my_idx = 0;
    for (; my_idx < ordered.size(); ++my_idx) if (ordered[my_idx] == k) break;
    for (size_t i = 0; i < my_idx; ++i) {
        Group* other = find(ordered[i]);
        if (other && !other->has_marker && other->repair_deadline_ns == 0) { other->repair_deadline_ns = now_ns + avc_repair_wait_ns; deadline_order_.push_back(ordered[i]); }
    }
    bool earlier_block = false;
    for (size_t i = 0; i < my_idx; ++i) { Group* other = find(ordered[i]); if (other && other->repair_deadline_ns != 0) { earlier_block = true; break; } }
    if (earlier_block) return;
    auto sorted = sorted_packets(*g);
    if (!group_complete(*g, sorted)) { if (g->repair_deadline_ns == 0) { g->repair_deadline_ns = now_ns + avc_repair_wait_ns; deadline_order_.push_back(k); } return; }
    g->repair_deadline_ns = 0;
    flush_group(k, now_ns);
    flush_ready(ssrc, now_ns);
}

void RtpAssembler::flush_ready(uint32_t ssrc, int64_t now_ns) {
    for (;;) {
        std::vector<Key> keys = ordered_keys(ssrc);
        if (keys.empty()) return;
        Group* g = find(keys[0]);
        if (!g) return;
        auto sorted = sorted_packets(*g);
        if (!group_complete(*g, sorted)) { if (g->repair_deadline_ns == 0) { g->repair_deadline_ns = now_ns + avc_repair_wait_ns; deadline_order_.push_back(keys[0]); } return; }
        g->repair_deadline_ns = 0;
        flush_group(keys[0], now_ns);
    }
}

void RtpAssembler::flush_group(Key k, int64_t now_ns) {
    auto it = groups_.find(k);
    if (it == groups_.end()) return;
    Group g = std::move(it->second);
    groups_.erase(it);
    group_order_.erase(std::remove(group_order_.begin(), group_order_.end(), k), group_order_.end());
    deadline_order_.erase(std::remove(deadline_order_.begin(), deadline_order_.end(), k), deadline_order_.end());
    recently_flushed_[k] = now_ns;
    auto sorted = sorted_packets(g);
    for (auto rit = sorted.rbegin(); rit != sorted.rend(); ++rit) if (rit->marker) { last_marker_seq_[g.ssrc] = rit->seq; break; }
    FlushedGroup fg;
    fg.ssrc = g.ssrc; fg.ts = g.ts; fg.packets = sorted;
    fg.incomplete = false;
    for (size_t i = 0; i + 1 < sorted.size(); ++i) if (uint16_t(sorted[i + 1].seq - sorted[i].seq) > 1) { fg.incomplete = true; break; }
    fg.t_first_ns = INT64_MAX; fg.t_last_ns = 0; fg.bytes = 0;
    payload_scratch_.clear();
    for (auto& p : sorted) {
        const PacketSlot& s = pool_[p.slot];
        payload_scratch_.emplace_back(s.data + s.payload_off, s.payload_len);
        fg.bytes += s.payload_len;
        fg.t_first_ns = std::min(fg.t_first_ns, s.t_recv_ns); fg.t_last_ns = std::max(fg.t_last_ns, s.t_recv_ns);
    }
    fg.payloads = payload_scratch_;
    if (fg.incomplete) ++incomplete_flushed;
    if (on_flush) on_flush(fg);
    release_group(g);
}

void RtpAssembler::drop_group(Key k, const char* reason, int64_t now_ns, std::set<uint32_t>& unblocked) {
    auto it = groups_.find(k);
    if (it == groups_.end()) return;
    Group g = std::move(it->second);
    groups_.erase(it);
    group_order_.erase(std::remove(group_order_.begin(), group_order_.end(), k), group_order_.end());
    deadline_order_.erase(std::remove(deadline_order_.begin(), deadline_order_.end(), k), deadline_order_.end());
    recently_flushed_[k] = now_ns;
    auto sorted = sorted_packets(g);
    bool had_marker = false;
    for (auto rit = sorted.rbegin(); rit != sorted.rend(); ++rit) if (rit->marker) { last_marker_seq_[g.ssrc] = rit->seq; had_marker = true; break; }
    if (!had_marker) last_marker_seq_.erase(g.ssrc);
    ++dropped_groups;
    if (on_drop) on_drop(DroppedGroup{g.ssrc, g.ts, had_marker, reason, g.pkts.size(), now_ns - g.arrival_ns});
    release_group(g);
    unblocked.insert(g.ssrc);
}

void RtpAssembler::evict_stale(int64_t now_ns) {
    std::set<uint32_t> unblocked;
    // Same iteration order as the reference: deadlines in arming order, then groups in arrival order.
    std::vector<Key> expired;
    for (Key k : deadline_order_) { auto it = groups_.find(k); if (it != groups_.end() && it->second.repair_deadline_ns != 0 && now_ns >= it->second.repair_deadline_ns) expired.push_back(k); }
    for (Key k : expired) drop_group(k, "NACK/reorder timeout", now_ns, unblocked);
    std::vector<Key> ttl;
    for (Key k : group_order_) { auto it = groups_.find(k); if (it != groups_.end() && it->second.repair_deadline_ns == 0 && now_ns - it->second.arrival_ns > pending_group_ttl_ns) ttl.push_back(k); }
    for (Key k : ttl) drop_group(k, "RTP marker timeout", now_ns, unblocked);
    for (uint32_t ssrc : unblocked) flush_ready(ssrc, now_ns);
    if (!recently_flushed_.empty())
        for (auto it = recently_flushed_.begin(); it != recently_flushed_.end();) { if (now_ns - it->second > flushed_dedup_ttl_ns) it = recently_flushed_.erase(it); else ++it; }
}

}  // namespace scshr
