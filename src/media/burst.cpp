#include "media/burst.h"
#include "common/log.h"
#include "media/bitstream.h"

#include <algorithm>
#include <set>

namespace scshr {

int hevc_pps_id(ByteView pps) {
    if (pps.size() <= 2) return 0;
    Bytes rbsp = remove_emulation_prevention(pps.subspan(2, std::min<size_t>(pps.size() - 2, 8)));
    return int(BitReader(view(rbsp)).read_ue());
}

InitialBurst gather_initial_burst(const std::vector<std::pair<Bytes, int64_t>>& raw, SrtpDecryptor& dec, VideoCodec codec, int tiles_per_frame, int quality_tier) {
    LOG_INFO("burst", "initial-burst packets: %zu", raw.size());
    InitialBurst ib;
    struct Pkt { uint16_t seq; bool marker; Bytes payload; int64_t t; };
    std::map<uint64_t, std::vector<Pkt>> groups;   // (ssrc<<32|ts) → packets, insertion-ordered by key (std::map) — see note
    std::vector<uint64_t> order;                    // first-seen order of keys (Python dict order)
    std::set<uint8_t> raw_hdr, hdr_bytes;
    for (auto& [pkt, t] : raw) {
        Bytes buf = pkt;
        RtpHeaderInfo h;
        if (!dec.decrypt(buf.data(), buf.size(), h)) continue;
        const uint64_t k = (uint64_t(h.ssrc) << 32) | h.timestamp;
        auto it = groups.find(k);
        if (it == groups.end()) { order.push_back(k); it = groups.emplace(k, std::vector<Pkt>{}).first; }
        it->second.push_back({h.seq, h.marker, Bytes(buf.begin() + ptrdiff_t(h.header_len), buf.begin() + ptrdiff_t(h.header_len + h.payload_len)), t});
    }
    std::vector<uint32_t> primary = dec.primary_ssrc_group(tiles_per_frame, quality_tier);
    std::sort(primary.begin(), primary.end());
    for (size_t i = 0; i < primary.size(); ++i) ib.ssrc_to_tile[primary[i]] = int(i);
    if (!primary.empty()) {
        std::string s; for (uint32_t x : primary) { char b[16]; snprintf(b, sizeof b, "0x%08x ", x); s += b; }
        LOG_INFO("burst", "SSRC group (tier %d): %s", quality_tier, s.c_str());
    }
    std::set<uint64_t> completed;
    std::map<int, bool> saw;
    if (!ib.ssrc_to_tile.empty()) {
        for (uint64_t k : order) {
            auto& grp = groups[k];
            bool has_marker = false; for (auto& p : grp) if (p.marker) { has_marker = true; break; }
            if (!has_marker) continue;
            const uint32_t ssrc = uint32_t(k >> 32);
            auto tit = ib.ssrc_to_tile.find(ssrc);
            if (tit == ib.ssrc_to_tile.end()) { completed.insert(k); continue; }
            const int ti = tit->second;
            // Sort by seq with wraparound awareness (burst.py: base = min seq when span > 0x8000).
            std::vector<Pkt*> packets; for (auto& p : grp) packets.push_back(&p);
            uint16_t mn = 0xFFFF, mx = 0; for (auto* p : packets) { mn = std::min(mn, p->seq); mx = std::max(mx, p->seq); }
            if (mx - mn > 0x8000) std::sort(packets.begin(), packets.end(), [&](Pkt* a, Pkt* b) { return uint16_t(a->seq - mn) < uint16_t(b->seq - mn); });
            else std::sort(packets.begin(), packets.end(), [](Pkt* a, Pkt* b) { return a->seq < b->seq; });
            std::vector<ByteView> payloads;
            for (auto* p : packets) { if (!p->payload.empty()) raw_hdr.insert(p->payload[0]); payloads.push_back(view(p->payload)); }
            Bytes out; std::vector<NalRange> ranges;
            if (codec == VideoCodec::Avc) {
                for (auto* p : packets) if (!p->payload.empty() && p->payload[0] == APPLE_AVC_CONFIG_MARKER) { auto cfg = parse_avc_config(view(p->payload)); if (cfg) { ib.sps = cfg->sps; ib.all_pps[0] = cfg->pps; } }
                reassemble_h264(payloads, out, ranges);
                for (auto& r : ranges) {
                    ByteView nal(out.data() + r.off, r.len);
                    if (nal.empty()) continue;
                    hdr_bytes.insert(nal[0]);
                    const int t = avc_nal_type(nal[0]);
                    if (t == AVC_NAL_IDR) { ib.last_idr[ti] = to_bytes(nal); ib.tile_nalus[ti] = {to_bytes(nal)}; }
                    else if (t >= 1 && t <= 5) ib.tile_nalus[ti].push_back(to_bytes(nal));
                }
                completed.insert(k);
                continue;
            }
            reassemble_hevc(payloads, out, ranges);
            for (auto& r : ranges) {
                ByteView nal(out.data() + r.off, r.len);
                if (nal.size() < 2) continue;
                const int nt = hevc_nal_type(nal[0]);
                hdr_bytes.insert(nal[0]);
                if (nt == HEVC_NAL_VPS) ib.vps = to_bytes(nal);
                else if (nt == HEVC_NAL_SPS) ib.sps = to_bytes(nal);
                else if (nt == HEVC_NAL_PPS) ib.all_pps[hevc_pps_id(nal)] = to_bytes(nal);
                else if (hevc_is_irap(nt)) { ib.last_idr[ti] = to_bytes(nal); ib.tile_nalus[ti] = {to_bytes(nal)}; }
                else ib.tile_nalus[ti].push_back(to_bytes(nal));
            }
            completed.insert(k);
        }
    }
    for (uint64_t k : order) {
        if (completed.count(k)) continue;
        for (auto& p : groups[k]) ib.pending.push_back({uint32_t(k >> 32), uint32_t(k & 0xFFFFFFFF), p.seq, p.marker, p.payload, p.t});
    }
    // Codec detection from observed NAL/RTP header bytes (diagnostic).
    std::set<uint8_t> all = raw_hdr; all.insert(hdr_bytes.begin(), hdr_bytes.end());
    bool hevc_params = false, hevc_ap = false, hevc_fu = false, h264 = false;
    for (uint8_t b : all) { const int nt = (b >> 1) & 0x3F; if (nt == 32 || nt == 33 || nt == 34) hevc_params = true; if (nt == 48) hevc_ap = true; if (nt == 49) hevc_fu = true; }
    for (uint8_t b : all) { const int t = b & 0x1F; if (!(b & 0x80) && (t == 1 || t == 5 || t == 7 || t == 8 || t == 24 || t == 28 || t == 29)) h264 = true; }
    h264 = h264 && !hevc_params;
    bool is_hevc = hevc_params || hevc_ap || hevc_fu;
    if (hevc_fu && !hevc_params && !hevc_ap && !h264 && codec == VideoCodec::Avc) { is_hevc = false; h264 = true; }
    ib.detected_codec = h264 ? "H.264/AVC" : is_hevc ? "HEVC" : "unknown";
    LOG_INFO("burst", "CODEC-DETECT: %s (%zu distinct header bytes)", ib.detected_codec.c_str(), all.size());
    const bool missing = codec == VideoCodec::Avc ? (ib.sps.empty() || ib.all_pps.empty()) : (ib.vps.empty() || ib.sps.empty() || ib.all_pps.empty());
    if (missing) throw BurstStarved(raw.size(), raw.size() < 20 ? "no-video-rtp" : "missing-param-sets");
    LOG_INFO("burst", "PPS pool: %zu; IDRs from burst: %zu tile(s)", ib.all_pps.size(), ib.last_idr.size());
    return ib;
}

}  // namespace scshr
