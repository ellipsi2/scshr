#include "protocol/rtcp.h"
#include "common/clock.h"

#include <algorithm>

namespace scshr::rtcp {

namespace {
constexpr uint64_t NTP_EPOCH_DELTA = 2208988800ULL;
}

Bytes build_fir(uint32_t sender, uint32_t target, uint8_t seq) {
    Writer w; w.u8(0x80 | 4).u8(206).u16(4).u32(sender).u32(0).u32(target).u8(seq).zeros(3); return w.out;
}
Bytes build_fir_legacy(uint32_t target) { Writer w; w.u8(0x80).u8(192).u16(1).u32(target); return w.out; }
Bytes build_pli(uint32_t sender, uint32_t media) { Writer w; w.u8(0x80 | 1).u8(206).u16(2).u32(sender).u32(media); return w.out; }

Bytes build_nack(uint32_t sender, uint32_t media, const std::set<uint16_t>& lost) {
    if (lost.empty()) return {};
    std::vector<uint16_t> seqs(lost.begin(), lost.end());  // std::set is sorted ascending like Python's sorted(set)
    Writer fcis;
    size_t i = 0;
    while (i < seqs.size()) {
        const uint16_t pid = seqs[i];
        uint16_t blp = 0;
        size_t j = i + 1;
        while (j < seqs.size()) {
            const uint16_t diff = uint16_t(seqs[j] - pid);
            if (diff >= 1 && diff <= 16) { blp |= uint16_t(1u << (diff - 1)); ++j; } else break;
        }
        fcis.u16(pid).u16(blp);
        i = j;
    }
    const uint16_t n_fcis = uint16_t(fcis.size() / 4);
    Writer w; w.u8(0x80 | 1).u8(205).u16(uint16_t(2 + n_fcis)).u32(sender).u32(media).raw(view(fcis.out));
    return w.out;
}

Bytes build_rtcp_app_ltrp(uint32_t sender, uint32_t ltr_id) {
    Writer w; w.u8(0x80).u8(204).u16(3).u32(sender).u32(5).u32(ltr_id); return w.out;
}

Bytes build_empty_sr(uint32_t sender) {
    const int64_t ns = wall_time_ns();
    const uint64_t sec = uint64_t(ns / 1000000000LL);
    const double frac = double(ns % 1000000000LL) / 1e9;
    const uint32_t ntp_sec = uint32_t(sec + NTP_EPOCH_DELTA);
    const uint32_t ntp_frac = uint32_t(uint64_t(frac * 4294967296.0) & 0xFFFFFFFFu);
    const uint32_t rtp_ts = uint32_t((uint64_t(double(ns) / 1e9 * 90000.0)) & 0xFFFFFFFFu);
    Writer w; w.u8(0x80).u8(200).u16(6).u32(sender).u32(ntp_sec).u32(ntp_frac).u32(rtp_ts).u32(0).u32(0);
    return w.out;
}

Bytes build_rr(uint32_t sender, const std::vector<uint32_t>& sources, const std::map<uint32_t, SsrcStat>& stats, const std::map<uint32_t, SrArrival>& sr) {
    if (sources.empty()) { Writer w; w.u8(0x80).u8(201).u16(1).u32(sender); return w.out; }
    const size_t rc = std::min<size_t>(sources.size(), 31);
    Writer w; w.u8(uint8_t(0x80 | rc)).u8(201).u16(uint16_t(1 + rc * 6)).u32(sender);
    const double now = double(wall_time_ns()) / 1e9;
    for (size_t i = 0; i < rc; ++i) {
        const uint32_t ssrc = sources[i];
        SsrcStat st; if (auto it = stats.find(ssrc); it != stats.end()) st = it->second;
        const uint32_t ext_seq = ((st.roc & 0xFFFF) << 16) | st.max_seq;
        uint32_t lsr = 0, dlsr = 0;
        if (auto it = sr.find(ssrc); it != sr.end()) { lsr = it->second.ntp_mid32; dlsr = uint32_t(int64_t((now - it->second.arrival_s) * 65536.0) & 0xFFFFFFFF); }
        w.u32(ssrc).u32(0).u32(ext_seq).u32(0).u32(lsr).u32(dlsr);
    }
    return w.out;
}

Bytes compound_with_rr(uint32_t sender, ByteView payload) {
    Bytes b = build_rr(sender);
    b.insert(b.end(), payload.begin(), payload.end());
    return b;
}

std::vector<std::pair<uint32_t, uint32_t>> parse_sr(ByteView d) {
    std::vector<std::pair<uint32_t, uint32_t>> out;
    size_t pos = 0;
    while (pos + 4 <= d.size()) {
        const uint8_t pt = d[pos + 1];
        const size_t len = (size_t(be16(d.data() + pos + 2)) + 1) * 4;
        if (pos + len > d.size()) break;
        if (pt == 200 && len >= 28) {
            const uint32_t ssrc = be32(d.data() + pos + 4), ntp_sec = be32(d.data() + pos + 8), ntp_frac = be32(d.data() + pos + 12);
            out.emplace_back(ssrc, ((ntp_sec & 0xFFFF) << 16) | ((ntp_frac >> 16) & 0xFFFF));
        }
        pos += len;
    }
    return out;
}

}  // namespace scshr::rtcp
