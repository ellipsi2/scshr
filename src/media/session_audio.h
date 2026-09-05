#pragma once
// Session audio (tools/mac-tunnel/audio_relay.go): the remote account's own sound, tapped on the Mac
// and sent as raw PCM over the tunnel. Packet: "SCAU" ver=1 ch=2 seq:u16le rate:u32le frames:u16le
// 0:u16le, then frames×2 int16le samples. Pure functions (no OS dependencies) so the tests cover them.
#include "common/bytes.h"

#include <optional>
#include <vector>

namespace scshr {

struct SessionAudioPacket { uint16_t seq = 0; uint32_t sample_rate = 0; std::vector<float> pcm; };   // interleaved stereo
std::optional<SessionAudioPacket> parse_session_audio_packet(ByteView pkt);

// Linear-interpolating stereo resampler to the sink's 48 kHz; carries its phase across packets.
class StereoResampler {
public:
    std::vector<float> to_48k(const float* interleaved_stereo, size_t frames, uint32_t rate);
private:
    uint32_t rate_ = 0; double pos_ = 0; float last_[2]{}; bool have_last_ = false;
};

}  // namespace scshr
