#pragma once
// Audio: AAC-ELD-SBR decode via libfdk-aac (loaded at runtime; optional) + WASAPI shared-mode output
// with the reference's wall-clock jitter policy (≈40 ms target, drop chunks older than 100 ms).
#include "common/bytes.h"

#include <memory>
#include <string>
#include <vector>

namespace scshr {

class AacEldDecoder {
public:
    static std::unique_ptr<AacEldDecoder> create(std::string* why_not);   // nullptr if libfdk-aac is unavailable
    ~AacEldDecoder();
    // Returns interleaved stereo float32 @ 48 kHz (may be empty while priming).
    std::vector<float> decode(ByteView au);
private:
    AacEldDecoder() = default;
    void* lib_ = nullptr;
    void* handle_ = nullptr;
    void* fill_ = nullptr; void* decode_ = nullptr; void* info_ = nullptr; void* close_ = nullptr;
    std::vector<int16_t> out_;
};

class AudioSink {
public:
    static std::unique_ptr<AudioSink> create(std::string* why_not);
    ~AudioSink();
    void feed(const float* interleaved_stereo, size_t frames);   // any thread
    void stop();
private:
    AudioSink() = default;
    struct Impl; Impl* p_ = nullptr;
};

}  // namespace scshr
