#include "media/session_audio.h"

#include <cstring>

namespace scshr {

std::optional<SessionAudioPacket> parse_session_audio_packet(ByteView p) {
    if (p.size() < 16 || std::memcmp(p.data(), "SCAU", 4) != 0 || p[4] != 1 || p[5] != 2) return std::nullopt;
    SessionAudioPacket out;
    out.seq = uint16_t(p[6] | p[7] << 8);
    out.sample_rate = uint32_t(p[8]) | uint32_t(p[9]) << 8 | uint32_t(p[10]) << 16 | uint32_t(p[11]) << 24;
    const size_t frames = size_t(p[12] | p[13] << 8);
    if (frames == 0 || out.sample_rate < 8000 || p.size() < 16 + frames * 4) return std::nullopt;
    out.pcm.resize(frames * 2);
    for (size_t i = 0; i < frames * 2; ++i) out.pcm[i] = float(int16_t(uint16_t(p[16 + i * 2] | p[17 + i * 2] << 8))) / 32768.0f;
    return out;
}

std::vector<float> StereoResampler::to_48k(const float* in, size_t frames, uint32_t rate) {
    std::vector<float> out;
    if (frames == 0 || rate == 0) return out;
    if (rate == 48000) { out.assign(in, in + frames * 2); return out; }
    if (rate != rate_) { rate_ = rate; pos_ = 0; have_last_ = false; }
    // Work on [last frame, new frames...] so the interpolation continues across packet boundaries.
    std::vector<float> src; src.reserve((frames + 1) * 2);
    if (have_last_) { src.push_back(last_[0]); src.push_back(last_[1]); }
    src.insert(src.end(), in, in + frames * 2);
    const size_t n = src.size() / 2;
    const double step = double(rate) / 48000.0;
    out.reserve(size_t(double(frames) / step) * 2 + 4);
    double t = pos_;
    while (t + 1 < double(n)) {
        const size_t i = size_t(t); const float f = float(t - double(i));
        out.push_back(src[i * 2] * (1 - f) + src[i * 2 + 2] * f);
        out.push_back(src[i * 2 + 1] * (1 - f) + src[i * 2 + 3] * f);
        t += step;
    }
    pos_ = t - double(n - 1);   // relative to the last input frame, kept for the next packet
    last_[0] = src[(n - 1) * 2]; last_[1] = src[(n - 1) * 2 + 1]; have_last_ = true;
    return out;
}

}  // namespace scshr
