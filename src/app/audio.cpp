#include "app/audio.h"
#include "common/clock.h"
#include "common/log.h"

#include <windows.h>
#include <audioclient.h>
#include <avrt.h>
#include <mmdeviceapi.h>

#include <atomic>
#include <deque>
#include <mutex>
#include <thread>

namespace scshr {

// ── libfdk-aac (dynamic) ─────────────────────────────────────────────────────
namespace {
// AudioSpecificConfig for AAC-ELD-SBR 48 kHz stereo, 480-sample frames (see aac_eld.py for the bit layout).
const uint8_t AUDIO_SPECIFIC_CONFIG[] = {0xf8, 0xe6, 0x51, 0x32, 0xe0, 0x00};
constexpr int OUT_MAX_SAMPLES = 8192;
typedef void* (*fn_open)(int transport, unsigned layers);
typedef int (*fn_configraw)(void* h, unsigned char** conf, const unsigned* len);
typedef int (*fn_fill)(void* h, unsigned char** buf, const unsigned* size, unsigned* valid);
typedef int (*fn_decode)(void* h, int16_t* out, int out_size, unsigned flags);
typedef void* (*fn_info)(void* h);
typedef void (*fn_close)(void* h);
}  // namespace

std::unique_ptr<AacEldDecoder> AacEldDecoder::create(std::string* why) {
    HMODULE lib = nullptr;
    {
        // fdk-aac.dll bundled next to scshr.exe (tools/fetch_deps.ps1 / tools/package.ps1).
        wchar_t exePath[MAX_PATH];
        DWORD n = GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        if (n > 0 && n < MAX_PATH) {
            std::wstring p(exePath, n);
            size_t slash = p.find_last_of(L"\\/");
            if (slash != std::wstring::npos) {
                p.resize(slash + 1);
                p += L"fdk-aac.dll";
                lib = LoadLibraryW(p.c_str());
            }
        }
    }
    const wchar_t* names[] = {L"libfdk-aac-2.dll", L"fdk-aac.dll", L"libfdk-aac.dll"};
    for (auto n : names) { if (lib) break; lib = LoadLibraryW(n); }
    if (!lib) {
        // Common install locations (MSYS2 / scoop) — same search the reference uses.
        const char* dirs[] = {"C:\\msys64\\mingw64\\bin", "C:\\msys64\\ucrt64\\bin"};
        for (auto d : dirs) { std::string p = std::string(d) + "\\libfdk-aac-2.dll"; lib = LoadLibraryA(p.c_str()); if (lib) break; }
        if (!lib) {
            char* up = getenv("USERPROFILE");
            if (up) { std::string p = std::string(up) + "\\scoop\\apps\\msys2\\current\\mingw64\\bin\\libfdk-aac-2.dll"; lib = LoadLibraryA(p.c_str()); }
        }
    }
    if (!lib) { if (why) *why = "fdk-aac.dll not found next to scshr.exe (audio disabled)"; return nullptr; }
    auto open = reinterpret_cast<fn_open>(GetProcAddress(lib, "aacDecoder_Open"));
    auto cfg = reinterpret_cast<fn_configraw>(GetProcAddress(lib, "aacDecoder_ConfigRaw"));
    auto fill = GetProcAddress(lib, "aacDecoder_Fill");
    auto dec = GetProcAddress(lib, "aacDecoder_DecodeFrame");
    auto info = GetProcAddress(lib, "aacDecoder_GetStreamInfo");
    auto close = GetProcAddress(lib, "aacDecoder_Close");
    if (!open || !cfg || !fill || !dec || !info || !close) { if (why) *why = "libfdk-aac exports missing"; FreeLibrary(lib); return nullptr; }
    void* h = open(0 /*TT_MP4_RAW*/, 1);
    if (!h) { if (why) *why = "aacDecoder_Open failed"; FreeLibrary(lib); return nullptr; }
    unsigned char* conf[1] = {const_cast<unsigned char*>(AUDIO_SPECIFIC_CONFIG)};
    unsigned len[1] = {sizeof AUDIO_SPECIFIC_CONFIG};
    if (cfg(h, conf, len) != 0) { if (why) *why = "aacDecoder_ConfigRaw failed"; reinterpret_cast<fn_close>(close)(h); FreeLibrary(lib); return nullptr; }
    std::unique_ptr<AacEldDecoder> d(new AacEldDecoder());
    d->lib_ = lib; d->handle_ = h; d->fill_ = fill; d->decode_ = dec; d->info_ = info; d->close_ = close;
    d->out_.resize(OUT_MAX_SAMPLES);
    return d;
}

AacEldDecoder::~AacEldDecoder() {
    if (handle_) reinterpret_cast<fn_close>(close_)(handle_);
    if (lib_) FreeLibrary(static_cast<HMODULE>(lib_));
}

std::vector<float> AacEldDecoder::decode(ByteView au) {
    std::vector<float> out;
    if (au.empty()) return out;
    unsigned char* bufs[1] = {const_cast<unsigned char*>(au.data())};
    unsigned sizes[1] = {unsigned(au.size())};
    unsigned valid = unsigned(au.size());
    if (reinterpret_cast<fn_fill>(fill_)(handle_, bufs, sizes, &valid) != 0) return out;
    if (reinterpret_cast<fn_decode>(decode_)(handle_, out_.data(), OUT_MAX_SAMPLES, 0) != 0) return out;
    const int* si = static_cast<const int*>(reinterpret_cast<fn_info>(info_)(handle_));
    if (!si) return out;
    const int sample_rate = si[0], frame_size = si[1], channels = si[2];
    if (frame_size <= 0 || channels <= 0 || frame_size * channels > OUT_MAX_SAMPLES) return out;
    const int rep = (sample_rate > 0 && sample_rate < 48000) ? 48000 / sample_rate : 1;
    out.reserve(size_t(frame_size) * 2 * size_t(rep));
    for (int i = 0; i < frame_size; ++i) {
        const float l = float(out_[size_t(i * channels)]) / 32768.0f;
        const float r = channels > 1 ? float(out_[size_t(i * channels + 1)]) / 32768.0f : l;
        for (int k = 0; k < rep; ++k) { out.push_back(l); out.push_back(r); }
    }
    return out;
}

// ── WASAPI sink ──────────────────────────────────────────────────────────────
struct AudioSink::Impl {
    IMMDeviceEnumerator* enumr = nullptr;
    IMMDevice* dev = nullptr;
    IAudioClient* client = nullptr;
    IAudioRenderClient* render = nullptr;
    HANDLE event = nullptr;
    UINT32 buffer_frames = 0;
    WAVEFORMATEX* fmt = nullptr;
    std::thread thr;
    std::atomic<bool> stop{false};
    std::mutex mu;
    struct Chunk { int64_t t; std::vector<float> pcm; size_t off = 0; };
    std::deque<Chunk> q;
    uint64_t feeds = 0, played = 0, silence = 0;
    static constexpr int64_t JITTER_TARGET_NS = 40'000'000, SLACK_LATE_NS = 60'000'000;
    static constexpr size_t MAX_QUEUE_CHUNKS = 50;
};

std::unique_ptr<AudioSink> AudioSink::create(std::string* why) {
    std::unique_ptr<AudioSink> s(new AudioSink());
    s->p_ = new Impl();
    Impl& p = *s->p_;
    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    HRESULT hr = CoCreateInstance(__uuidof(MMDeviceEnumerator), nullptr, CLSCTX_ALL, IID_PPV_ARGS(&p.enumr));
    if (FAILED(hr)) { if (why) *why = "MMDeviceEnumerator unavailable"; return nullptr; }
    hr = p.enumr->GetDefaultAudioEndpoint(eRender, eConsole, &p.dev);
    if (FAILED(hr)) { if (why) *why = "no default audio output device"; return nullptr; }
    hr = p.dev->Activate(__uuidof(IAudioClient), CLSCTX_ALL, nullptr, reinterpret_cast<void**>(&p.client));
    if (FAILED(hr)) { if (why) *why = "IAudioClient activation failed"; return nullptr; }
    WAVEFORMATEXTENSIBLE wf{};
    wf.Format.wFormatTag = WAVE_FORMAT_EXTENSIBLE; wf.Format.nChannels = 2; wf.Format.nSamplesPerSec = 48000; wf.Format.wBitsPerSample = 32;
    wf.Format.nBlockAlign = 8; wf.Format.nAvgBytesPerSec = 48000 * 8; wf.Format.cbSize = 22;
    wf.Samples.wValidBitsPerSample = 32; wf.dwChannelMask = 3; wf.SubFormat = KSDATAFORMAT_SUBTYPE_IEEE_FLOAT;
    // Shared mode, event-driven, 10 ms period (shared mode resamples if the mix format differs).
    hr = p.client->Initialize(AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_EVENTCALLBACK | AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY, 200000, 0, &wf.Format, nullptr);
    if (FAILED(hr)) { if (why) { char b[64]; snprintf(b, sizeof b, "IAudioClient::Initialize failed 0x%08lx", hr); *why = b; } return nullptr; }
    p.client->GetBufferSize(&p.buffer_frames);
    p.event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    p.client->SetEventHandle(p.event);
    hr = p.client->GetService(IID_PPV_ARGS(&p.render));
    if (FAILED(hr)) { if (why) *why = "IAudioRenderClient unavailable"; return nullptr; }
    p.client->Start();
    Impl* pp = &p;
    p.thr = std::thread([pp] {
        DWORD idx = 0; HANDLE task = AvSetMmThreadCharacteristicsW(L"Pro Audio", &idx);
        while (!pp->stop) {
            if (WaitForSingleObject(pp->event, 200) != WAIT_OBJECT_0) continue;
            UINT32 padding = 0; pp->client->GetCurrentPadding(&padding);
            const UINT32 avail = pp->buffer_frames - padding;
            if (avail == 0) continue;
            BYTE* data = nullptr;
            if (FAILED(pp->render->GetBuffer(avail, &data))) continue;
            float* out = reinterpret_cast<float*>(data);
            UINT32 filled = 0;
            {
                std::lock_guard<std::mutex> lk(pp->mu);
                const int64_t cutoff = now_ns() - (Impl::JITTER_TARGET_NS + Impl::SLACK_LATE_NS);
                while (!pp->q.empty() && pp->q.front().t < cutoff) pp->q.pop_front();   // drop ancient audio; never replay a backlog
                while (filled < avail && !pp->q.empty()) {
                    auto& c = pp->q.front();
                    const size_t have = c.pcm.size() / 2 - c.off;
                    const size_t n = std::min<size_t>(have, avail - filled);
                    std::memcpy(out + size_t(filled) * 2, c.pcm.data() + c.off * 2, n * 2 * sizeof(float));
                    filled += UINT32(n); c.off += n;
                    if (c.off * 2 >= c.pcm.size()) pp->q.pop_front();
                }
            }
            if (filled < avail) { std::memset(out + size_t(filled) * 2, 0, size_t(avail - filled) * 2 * sizeof(float)); pp->silence += avail - filled; }
            pp->played += filled;
            pp->render->ReleaseBuffer(avail, 0);
        }
        if (task) AvRevertMmThreadCharacteristics(task);
    });
    LOG_INFO("audio", "WASAPI sink started: 48 kHz stereo float, buffer=%u frames, 40 ms jitter target", p.buffer_frames);
    return s;
}

void AudioSink::feed(const float* pcm, size_t frames) {
    if (!p_ || frames == 0) return;
    bool silent = true; for (size_t i = 0; i < frames * 2; ++i) if (pcm[i] != 0.0f) { silent = false; break; }
    if (silent) return;   // Apple sends decoded-to-zero PCM when nothing plays; the underflow path already emits silence
    std::lock_guard<std::mutex> lk(p_->mu);
    if (p_->q.size() >= Impl::MAX_QUEUE_CHUNKS) p_->q.pop_front();
    p_->q.push_back({now_ns(), std::vector<float>(pcm, pcm + frames * 2), 0});
    ++p_->feeds;
}

void AudioSink::stop() {
    if (!p_) return;
    p_->stop = true;
    if (p_->thr.joinable()) p_->thr.join();
    if (p_->client) p_->client->Stop();
    LOG_INFO("audio", "sink stopped: %llu feeds, %llu frames played, %llu silence", (unsigned long long)p_->feeds, (unsigned long long)p_->played, (unsigned long long)p_->silence);
}

AudioSink::~AudioSink() {
    if (!p_) return;
    stop();
    if (p_->render) p_->render->Release();
    if (p_->client) p_->client->Release();
    if (p_->dev) p_->dev->Release();
    if (p_->enumr) p_->enumr->Release();
    if (p_->event) CloseHandle(p_->event);
    delete p_;
}

}  // namespace scshr
