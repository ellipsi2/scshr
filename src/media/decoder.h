#pragma once
// Shared-context video decoder (H.264 4:2:0 / HEVC RExt 4:4:4) over libavcodec with D3D11VA hardware
// output kept GPU-resident (AV_PIX_FMT_D3D11 → ID3D11Texture2D array slice). One codec context for all
// tiles (Apple's tiled HEVC has cross-tile references). Ports the lifecycle/recovery semantics of
// media/hevc.py + media/avc.py: keyframe gating, per-tile await-IDR recovery, no-flush wedge recovery,
// suspicious-IDR detection, AVC reference-chain reset on the next intra frame, HW→SW fallback latch.
//
// Threading: feed_nalu() is called by the packet thread (cheap pre-checks + enqueue); one decoder thread
// pulls from a bounded ring and decodes; take_latest() is called by the render thread. "Newest frame
// wins": each tile holds exactly one output frame; an unconsumed older frame is replaced (counted).
#include "common/bytes.h"
#include "common/ring.h"
#include "common/stats.h"
#include "media/hevc_rps.h"
#include "media/quality_gate.h"
#include "media/rtp_assembler.h"

#include <array>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

struct AVFrame;
struct AVCodecContext;
struct AVBufferRef;
struct ID3D11Device;
struct ID3D11DeviceContext;

namespace scshr {

// GPU device shared between decoder and renderer. The lock serialises immediate-context use between
// the decoder thread (FFmpeg D3D11VA submits) and the render thread (draw + Present).
struct GpuDevice {
    ID3D11Device* device = nullptr;              // owned by the renderer (AddRef'd by FFmpeg's hwdevice ctx)
    ID3D11DeviceContext* context = nullptr;
    std::recursive_mutex* lock = nullptr;
};

struct DecodedFrame {
    AVFrame* frame = nullptr;     // owned reference (av_frame_free in release())
    int tile = 0;
    uint64_t index = 0;           // monotonically increasing per session
    int64_t t_au_complete_ns = 0, t_submit_ns = 0, t_output_ns = 0;
    bool had_error = false;
    bool hw = false;              // AV_PIX_FMT_D3D11
    uint16_t donl = 0; bool has_donl = false;
    int frame_width() const; int frame_height() const;
    ~DecodedFrame();
    DecodedFrame() = default;
    DecodedFrame(const DecodedFrame&) = delete;
    DecodedFrame& operator=(const DecodedFrame&) = delete;
};

struct DecoderTelemetry {
    std::atomic<uint64_t> nalus_fed{0}, nalus_dropped_queue{0}, frames_out{0}, frames_replaced{0}, decode_errors{0}, pre_idr_drops{0}, keyframes{0}, restarts{0}, reference_resets{0};
    RollingStats submit_latency_ms{600};   // AU complete → send_packet
    RollingStats decode_latency_ms{600};   // send_packet → frame out
    std::atomic<int> queue_depth{0};
};

struct DecoderConfig {
    VideoCodec codec = VideoCodec::Avc;
    int num_tiles = 1;
    bool prefer_hw = true;
    bool avc_sps_patch = true;
    bool pertile_recovery = true;
    GpuDevice gpu;                  // device==nullptr → software only
    std::string hw_override;        // "" | "d3d11va" | "sw"
};

class VideoDecoder {
public:
    explicit VideoDecoder(const DecoderConfig& cfg);
    ~VideoDecoder();

    void set_params(ByteView vps, ByteView sps, const std::map<int, Bytes>& all_pps);
    void start();      // builds the codec context (HW first) and starts the worker
    void restart();    // teardown + rebuild (SSRC adoption, resize, watchdog)
    void close();

    // Session-start burst: decode synchronously in interleaved tile order (HW sanity check + fallback).
    void feed_burst(const std::map<int, std::vector<Bytes>>& tile_nalus);
    // Steady state: one NAL (no start code) for `tile`. Cheap pre-checks here; decode on the worker.
    void feed_nalu(ByteView nal, int tile, std::optional<uint16_t> donl, int64_t t_au_complete_ns, int64_t now_ns);

    // Render side: newest unconsumed frame for `tile` (nullptr if none since the last call).
    std::unique_ptr<DecodedFrame> take_latest(int tile);
    bool wait_for_frame(int timeout_ms);   // any tile published since the last take

    FrameQualityGate& gate() { return gate_; }
    std::mutex& gate_mutex() { return gate_mu_; }
    DecoderTelemetry& telemetry() { return tel_; }
    HevcRpsTracker& rps() { return rps_; }
    const std::string& hw_name() const { return hw_name_; }   // "d3d11va" | "" (software)
    bool hw_bound() const { return hw_bound_.load(); }
    bool hw_srv_bind() const { return hw_srv_bind_; }
    static int get_format_cb(AVCodecContext* ctx, const int* fmts);
    const std::string& pix_fmt_name() const { return pix_fmt_name_; }
    int num_tiles() const { return cfg_.num_tiles; }
    VideoCodec codec() const { return cfg_.codec; }
    std::optional<uint16_t> last_clean_donl(int tile) const;
    std::vector<uint64_t> good_counts() const;
    std::vector<uint64_t> clean_counts() const;
    bool dpb_has_idr() const { return dpb_has_idr_.load(); }
    bool await_key() const { return await_key_.load(); }
    uint64_t frames_since_keyframe() const { return frames_since_keyframe_.load(); }
    bool reference_reset_pending() const { return reference_reset_pending_.load(); }

    // Recovery hooks (called from the session / libav log callback — lock-free on purpose).
    void mark_reference_chain_broken(const char* trigger);   // AVC: gate deltas until next intra, rebuild ctx there
    void mark_hwaccel_failed(const char* trigger);           // stop retrying hardware on later rebuilds
    void mark_hwaccel_reference_failure(const char* trigger);
    void mark_wedge_recovery();                              // HEVC no-flush recovery (drop P until IDR)
    std::function<void(int tile)> on_frame_published;        // decoder thread
    Bytes current_sps() const;

private:
    struct QueuedNal { Bytes data; int tile = 0; uint16_t donl = 0; bool has_donl = false; int64_t t_au = 0, t_enq = 0; bool sync = false; };
    struct InFlight { int tile = 0; uint16_t donl = 0; bool has_donl = false; int64_t t_au = 0; };
    struct TileSlot { std::unique_ptr<DecodedFrame> frame; uint64_t good = 0, clean = 0; bool saw_idr = false; };

    bool create_codec(bool force_software);
    void destroy_codec();
    void worker_loop();
    void decode_one(QueuedNal& q, int64_t now_ns);
    void publish(AVFrame* f, const InFlight& meta, int64_t t_submit);
    void drain_queue();
    void try_recovery();
    Bytes build_extradata();
    void reset_state();
    int choose_format(AVCodecContext* ctx, const int* fmts);

    DecoderConfig cfg_;
    Bytes vps_, sps_, sps_patched_;
    std::map<int, Bytes> pps_;
    AVCodecContext* ctx_ = nullptr;
    AVBufferRef* hw_device_ref_ = nullptr;
    std::recursive_mutex codec_mu_;
    std::string hw_name_, pix_fmt_name_;
    std::atomic<bool> hw_bound_{false};
    bool hw_srv_bind_ = false;
    bool hw_failed_ = false, hw_verified_ = false;
    std::atomic<bool> dpb_has_idr_{false}, await_key_{true}, reference_reset_pending_{false}, recovery_in_progress_{false};
    std::set<int> tiles_await_idr_;
    std::mutex await_mu_;
    std::vector<TileSlot> tiles_;
    mutable std::mutex tiles_mu_;
    std::condition_variable frame_cv_;
    std::mutex frame_cv_mu_;
    bool frame_pending_ = false;
    FrameQualityGate gate_;
    std::mutex gate_mu_;
    HevcRpsTracker rps_;
    std::mutex rps_mu_;
    std::vector<std::optional<uint16_t>> last_clean_donl_;
    DecoderTelemetry tel_;
    std::vector<int> recent_idr_sizes_;
    uint64_t next_index_ = 0;
    uint64_t next_pts_ = 0;
    std::map<int64_t, InFlight> inflight_;   // pts → source (tile, timestamps)
    int silent_nalus_ = 0, eagain_streak_ = 0;
    std::atomic<uint64_t> frames_since_keyframe_{0};
    std::map<int, std::vector<Bytes>> burst_cache_;
    // Worker queue
    std::unique_ptr<SpscRing<QueuedNal*>> ring_;
    std::vector<std::unique_ptr<QueuedNal>> nal_pool_;
    SpscRing<QueuedNal*> free_ring_;
    std::thread worker_;
    std::atomic<bool> stop_{false};
    std::condition_variable work_cv_;
    std::mutex work_mu_;
    bool sync_mode_ = false;
    std::string reference_break_trigger_;
    int64_t reference_break_ns_ = 0;
};

const char* av_error_string(int err);
// True iff libavcodec offers D3D11VA for an HEVC Main 4:4:4 8-bit stream on this device (real decode of a
// tiny embedded IDR, like hwcaps.py). Drives `--codec auto`: HEVC only when the GPU can hardware-decode 4:4:4.
bool probe_hevc444_hw(const GpuDevice& gpu);

}  // namespace scshr
