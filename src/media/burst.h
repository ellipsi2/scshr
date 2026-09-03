#pragma once
// Session-start burst harvest (proxy/protocol/burst.py): parameter sets, SSRC→tile map, per-tile NAL
// cache seeded from the first IDR(s), and leftover incomplete groups handed to the streaming assembler.
#include "common/bytes.h"
#include "crypto/srtp.h"
#include "media/nalu.h"
#include "media/rtp_assembler.h"

#include <map>
#include <stdexcept>
#include <vector>

namespace scshr {

struct BurstStarved : std::runtime_error {
    size_t packets; std::string reason;
    BurstStarved(size_t p, std::string r) : std::runtime_error("burst starved: " + r + " (" + std::to_string(p) + " packets)"), packets(p), reason(std::move(r)) {}
};

struct BurstPacket { uint32_t ssrc, ts; uint16_t seq; bool marker; Bytes payload; int64_t t_ns; };

struct InitialBurst {
    std::map<uint32_t, int> ssrc_to_tile;
    Bytes vps, sps;                        // raw NAL (no start code); HEVC: VPS present; AVC: sps from avcC
    std::map<int, Bytes> all_pps;          // pps_id → raw NAL
    std::map<int, Bytes> last_idr;         // tile → IDR NAL
    std::map<int, std::vector<Bytes>> tile_nalus;   // tile → NALs in arrival order (IDR first)
    std::vector<BurstPacket> pending;      // groups that never completed inside the burst (re-queued to the assembler)
    std::string detected_codec;            // "H.264/AVC" | "HEVC" | "unknown"
};

// `raw` = encrypted SRTP datagrams as received (with receive timestamps). Decrypts via `dec`.
InitialBurst gather_initial_burst(const std::vector<std::pair<Bytes, int64_t>>& raw, SrtpDecryptor& dec, VideoCodec codec, int tiles_per_frame, int quality_tier = 0);

// HEVC PPS id from a PPS NAL (ue(v) after the 2-byte header).
int hevc_pps_id(ByteView pps_nal);

}  // namespace scshr
