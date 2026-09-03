#pragma once
// .scshr packet recording: "SCSHRPKT" u32 version=1, u8 codec(0=avc,1=hevc), u8 tiles, 46B video key, 46B audio key,
// then records [u64 t_ns][u16 kind(0=video,1=ctrl)][u16 len][bytes]. Written by `scshr --record`, scshr_synth.
#include "common/bytes.h"

#include <cstdio>
#include <stdexcept>
#include <string>
#include <vector>

namespace scshr::pkt {

struct Header { int codec = 0; int tiles = 1; Bytes video_key, audio_key; };
struct Record { int64_t t_ns; int kind; Bytes data; };

inline void write_header(FILE* f, const Header& h) {
    uint8_t hdr[106] = {};
    std::memcpy(hdr, "SCSHRPKT", 8); put_be32(hdr + 8, 1); hdr[12] = uint8_t(h.codec); hdr[13] = uint8_t(h.tiles);
    if (h.video_key.size() == 46) std::memcpy(hdr + 14, h.video_key.data(), 46);
    if (h.audio_key.size() == 46) std::memcpy(hdr + 60, h.audio_key.data(), 46);
    fwrite(hdr, 1, sizeof hdr, f);
}
inline void write_record(FILE* f, int64_t t, int kind, ByteView d) {
    uint8_t h[12]; put_be64(h, uint64_t(t)); put_be16(h + 8, uint16_t(kind)); put_be16(h + 10, uint16_t(d.size()));
    fwrite(h, 1, 12, f); fwrite(d.data(), 1, d.size(), f);
}
inline bool read_file(const std::string& path, Header& h, std::vector<Record>& recs) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    uint8_t hdr[106];
    if (fread(hdr, 1, 106, f) != 106 || std::memcmp(hdr, "SCSHRPKT", 8) != 0) { fclose(f); return false; }
    h.codec = hdr[12]; h.tiles = hdr[13]; h.video_key.assign(hdr + 14, hdr + 60); h.audio_key.assign(hdr + 60, hdr + 106);
    uint8_t rh[12];
    while (fread(rh, 1, 12, f) == 12) {
        Record r; r.t_ns = int64_t(be64(rh)); r.kind = be16(rh + 8); const size_t n = be16(rh + 10);
        r.data.resize(n);
        if (fread(r.data.data(), 1, n, f) != n) break;
        recs.push_back(std::move(r));
    }
    fclose(f);
    return true;
}

}  // namespace scshr::pkt
