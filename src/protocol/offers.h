#pragma once
// AVCMediaStreamNegotiator offer build + answer parse (proxy/protocol/offers.py).
#include "common/bytes.h"

#include <optional>
#include <string>

namespace scshr::offers {

enum class Codec { Hevc, Avc, Both };

struct OfferOptions {
    Codec codec = Codec::Both;   // which video banks to advertise (server picks HEVC for Both)
    int tiles_per_frame = 4;     // 1 for AVC single picture, 4 for tiled HEVC
    bool ltrp = true;            // HEVC only; forced off for AVC
    bool audio_enabled = true;   // false → sub-floor audio bitrate (host sends no audio)
    // Deterministic inputs for differential tests; zero = random.
    uint32_t session_id_video = 0, session_id_audio = 0;
    uint64_t timestamp_ns = 0;
    std::string callid_video, callid_audio;  // uppercase UUID strings
};

int default_tiles_per_frame(Codec c);
bool ltrp_enabled_for(Codec c, bool want);

// MediaBlob protobuf (before zlib). mode 7 = video, mode 8 = audio.
Bytes build_mediablob(int mode, uint32_t session_id, uint64_t timestamp, const OfferOptions& o);
Bytes remote_endpoint_info();
// Complete bplist offers (video, audio).
std::pair<Bytes, Bytes> create_offers(const OfferOptions& o);

std::optional<uint32_t> extract_offer_ssrc(ByteView offer_plist, bool is_video);
struct CanvasDims { uint32_t w = 0, h = 0, tiles = 0; int ltrp = -1; };
// From the server's 0x1c answer (delivered as a 0x00 FBU carrying an embedded bplist).
CanvasDims extract_canvas_dims(ByteView answer_msg);

}  // namespace scshr::offers
