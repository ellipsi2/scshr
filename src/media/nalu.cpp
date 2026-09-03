#include "media/nalu.h"

namespace scshr {

namespace {
const uint8_t START_CODE[4] = {0, 0, 0, 1};
void emit(Bytes& out, std::vector<NalRange>& r, ByteView a, ByteView b = {}) {
    out.insert(out.end(), START_CODE, START_CODE + 4);
    const size_t off = out.size();
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    r.push_back({off, a.size() + b.size()});
}
}  // namespace

void reassemble_hevc(const std::vector<ByteView>& payloads, Bytes& out, std::vector<NalRange>& ranges) {
    Bytes fu_buf;
    bool fu_active = false;
    size_t fu_off = 0;
    for (ByteView pay : payloads) {
        if (pay.size() < 2) continue;
        const int nt = hevc_nal_type(pay[0]);
        if (nt == HEVC_NAL_AP) {
            // header(2) + DONL(2) + [size(2) + data]... (no per-unit DOND — Apple deviation)
            size_t pos = 4;
            const size_t n = pay.size();
            while (pos + 2 <= n) {
                const size_t size = be16(pay.data() + pos);
                pos += 2;
                if (size == 0 || pos + size > n) break;
                emit(out, ranges, pay.subspan(pos, size));
                pos += size;
            }
        } else if (nt == HEVC_NAL_FU) {
            // header(2) + FU_hdr(1) + DONL(2) in EVERY fragment + payload
            if (pay.size() < 6) continue;
            const uint8_t fu_hdr = pay[2];
            const bool start = fu_hdr & 0x80, end = fu_hdr & 0x40;
            const int inner_type = fu_hdr & 0x3F;
            if (start) {
                const uint8_t hdr0 = uint8_t((pay[0] & 0x81) | (inner_type << 1));
                out.insert(out.end(), START_CODE, START_CODE + 4);
                fu_off = out.size();
                out.push_back(hdr0); out.push_back(pay[1]);
                out.insert(out.end(), pay.begin() + 5, pay.end());
                fu_active = true;
            } else if (fu_active) {
                out.insert(out.end(), pay.begin() + 5, pay.end());
                if (end) { ranges.push_back({fu_off, out.size() - fu_off}); fu_active = false; }
            }
        } else {
            // Single NAL with a leading 2-byte DONL after the NAL header.
            if (pay.size() < 4) continue;
            emit(out, ranges, pay.subspan(0, 2), pay.subspan(4));
        }
    }
    if (fu_active) {
        // Unterminated FU (end fragment lost): discard the partial NAL bytes.
        out.resize(fu_off - 4);
    }
}

void reassemble_h264(const std::vector<ByteView>& payloads, Bytes& out, std::vector<NalRange>& ranges) {
    bool fu_active = false;
    size_t fu_off = 0;
    for (ByteView pay : payloads) {
        if (pay.empty()) continue;
        const uint8_t b0 = pay[0];
        if (b0 == APPLE_AVC_CONFIG_MARKER) continue;
        const int t = avc_nal_type(b0);
        if (t == AVC_NAL_FU_A || t == AVC_NAL_FU_B) {
            const size_t data_off = t == AVC_NAL_FU_B ? 4 : 2;  // FU-B carries a DON
            if (pay.size() < data_off) continue;
            const uint8_t fu_hdr = pay[1];
            const bool start = fu_hdr & 0x80, end = fu_hdr & 0x40;
            const int inner_type = fu_hdr & 0x1F;
            if (start) {
                out.insert(out.end(), START_CODE, START_CODE + 4);
                fu_off = out.size();
                out.push_back(uint8_t((b0 & 0xE0) | inner_type));
                out.insert(out.end(), pay.begin() + ptrdiff_t(data_off), pay.end());
                fu_active = true;
            } else if (fu_active) {
                out.insert(out.end(), pay.begin() + ptrdiff_t(data_off), pay.end());
                if (end) { ranges.push_back({fu_off, out.size() - fu_off}); fu_active = false; }
            }
        } else if (t == AVC_NAL_STAP_A) {
            size_t pos = 3;  // indicator(1) + DON(2)
            const size_t n = pay.size();
            while (pos + 2 <= n) {
                const size_t size = be16(pay.data() + pos);
                pos += 2;
                if (size == 0 || pos + size > n) break;
                emit(out, ranges, pay.subspan(pos, size));
                pos += size;
            }
        } else if (t >= 1 && t <= 23) {
            // Single NAL — DON-less (stripping 2 bytes here corrupted single-packet slices).
            if (pay.size() < 2) continue;
            emit(out, ranges, pay);
        }
    }
    if (fu_active) out.resize(fu_off - 4);
}

std::optional<uint16_t> first_donl(const std::vector<ByteView>& payloads) {
    for (ByteView pay : payloads) {
        if (pay.size() < 2) continue;
        if (hevc_nal_type(pay[0]) == HEVC_NAL_FU) { if (pay.size() >= 5) return be16(pay.data() + 3); }
        else if (pay.size() >= 4) return be16(pay.data() + 2);
    }
    return std::nullopt;
}

std::optional<AvcConfig> parse_avc_config(ByteView payload) {
    auto find = [&](const char* s, size_t from) -> size_t {
        const size_t n = std::strlen(s);
        for (size_t i = from; i + n <= payload.size(); ++i) if (std::memcmp(payload.data() + i, s, n) == 0) return i;
        return std::string::npos;
    };
    const size_t a1 = find("avc1", 0);
    const size_t idx = find("avcC", a1 == std::string::npos ? 0 : a1);
    if (idx == std::string::npos) return std::nullopt;
    size_t p = idx + 4;
    if (p + 6 > payload.size()) return std::nullopt;
    const int num_sps = payload[p + 5] & 0x1F;
    p += 6;
    AvcConfig cfg;
    for (int i = 0; i < num_sps; ++i) {
        if (p + 2 > payload.size()) return std::nullopt;
        const size_t ln = be16(payload.data() + p); p += 2;
        if (p + ln > payload.size()) return std::nullopt;
        if (cfg.sps.empty()) cfg.sps = to_bytes(payload.subspan(p, ln));
        p += ln;
    }
    if (p + 1 > payload.size()) return std::nullopt;
    const int num_pps = payload[p]; p += 1;
    for (int i = 0; i < num_pps; ++i) {
        if (p + 2 > payload.size()) return std::nullopt;
        const size_t ln = be16(payload.data() + p); p += 2;
        if (p + ln > payload.size()) return std::nullopt;
        if (cfg.pps.empty()) cfg.pps = to_bytes(payload.subspan(p, ln));
        p += ln;
    }
    if (cfg.sps.empty() || cfg.pps.empty()) return std::nullopt;
    return cfg;
}

}  // namespace scshr
