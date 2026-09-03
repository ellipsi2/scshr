#include "media/decoder.h"
#include "common/clock.h"
#include "common/log.h"
#include "media/avc_util.h"
#include "media/nalu.h"

// d3d11.h must be seen outside extern "C" (it defines C++ operator overloads); hwcontext_d3d11va.h re-includes it.
#include <d3d11.h>

extern "C" {
#include <libavcodec/avcodec.h>
#include <libavutil/hwcontext.h>
#include <libavutil/hwcontext_d3d11va.h>
#include <libavutil/imgutils.h>
#include <libavutil/pixdesc.h>
}

#include <algorithm>

namespace scshr {

namespace {
constexpr size_t QUEUE_CAP = 64;                // NALs in flight to the worker (bounded; overflow drops)
constexpr int HWACCEL_SILENT_NALU_LIMIT = 60;   // one 60 fps source-frame of NALUs with no output → wedge
constexpr int HWACCEL_BURST_ERROR_THRESHOLD = 20, HWACCEL_BURST_ERROR_WINDOW = 40, HWACCEL_BURST_MIN_FRAMES = 5;
constexpr size_t IDR_HISTORY_LEN = 10;
constexpr double IDR_FAKE_RATIO = 0.40;
const uint8_t START_CODE[4] = {0, 0, 0, 1};

void ff_lock(void* ctx) { static_cast<std::recursive_mutex*>(ctx)->lock(); }
void ff_unlock(void* ctx) { static_cast<std::recursive_mutex*>(ctx)->unlock(); }

enum AVPixelFormat get_format_thunk(AVCodecContext* ctx, const enum AVPixelFormat* fmts);
}  // namespace

const char* av_error_string(int err) {
    static thread_local char buf[AV_ERROR_MAX_STRING_SIZE];
    av_strerror(err, buf, sizeof buf);
    return buf;
}

DecodedFrame::~DecodedFrame() { if (frame) av_frame_free(&frame); }
int DecodedFrame::frame_width() const { return frame ? frame->width : 0; }
int DecodedFrame::frame_height() const { return frame ? frame->height : 0; }

VideoDecoder::VideoDecoder(const DecoderConfig& cfg)
    : cfg_(cfg), tiles_(size_t(cfg.num_tiles)), gate_(cfg.num_tiles), last_clean_donl_(size_t(cfg.num_tiles)), free_ring_(QUEUE_CAP * 2) {
    ring_ = std::make_unique<SpscRing<QueuedNal*>>(QUEUE_CAP);
    for (size_t i = 0; i < QUEUE_CAP; ++i) {
        nal_pool_.push_back(std::make_unique<QueuedNal>());
        nal_pool_.back()->data.reserve(64 * 1024);
        QueuedNal* p = nal_pool_.back().get();
        free_ring_.push(std::move(p));
    }
}

VideoDecoder::~VideoDecoder() { close(); }

void VideoDecoder::set_params(ByteView vps, ByteView sps, const std::map<int, Bytes>& all_pps) {
    vps_ = to_bytes(vps); sps_ = to_bytes(sps); pps_ = all_pps;
    if (cfg_.codec == VideoCodec::Hevc && sps_.size() > 2) { std::lock_guard<std::mutex> lk(rps_mu_); rps_.feed_sps(ByteView(sps_.data() + 2, sps_.size() - 2)); }
    if (cfg_.codec == VideoCodec::Avc) sps_patched_ = cfg_.avc_sps_patch ? avc_patch_sps_dpb(view(sps_)) : sps_;
}

Bytes VideoDecoder::current_sps() const { return sps_; }

Bytes VideoDecoder::build_extradata() {
    Bytes ed;
    auto add = [&](const Bytes& n) { if (n.empty()) return; ed.insert(ed.end(), START_CODE, START_CODE + 4); ed.insert(ed.end(), n.begin(), n.end()); };
    if (cfg_.codec == VideoCodec::Hevc) { add(vps_); add(sps_); for (auto& kv : pps_) add(kv.second); }
    else { add(sps_patched_); if (!pps_.empty()) add(pps_.begin()->second); }
    return ed;
}

namespace {
enum AVPixelFormat get_format_thunk(AVCodecContext* ctx, const enum AVPixelFormat* fmts) {
    return AVPixelFormat(VideoDecoder::get_format_cb(ctx, reinterpret_cast<const int*>(fmts)));
}
}  // namespace

int VideoDecoder::get_format_cb(AVCodecContext* ctx, const int* fmts) {
    return static_cast<VideoDecoder*>(ctx->opaque)->choose_format(ctx, fmts);
}

// Called by libavcodec once it knows the stream profile. Pick AV_PIX_FMT_D3D11 when offered and create
// the hardware frame pool ourselves so the decoder surfaces carry D3D11_BIND_SHADER_RESOURCE: that is what
// lets the renderer sample the decoder texture-array slice directly (no copy). Falls back to the first
// software format when the driver does not expose a decoder profile for this stream (e.g. HEVC 4:4:4).
int VideoDecoder::choose_format(AVCodecContext* ctx, const int* fmts) {
    bool has_d3d11 = false;
    for (const int* f = fmts; *f != AV_PIX_FMT_NONE; ++f) if (*f == AV_PIX_FMT_D3D11) has_d3d11 = true;
    if (has_d3d11 && hw_device_ref_) {
        for (int attempt = 0; attempt < 2; ++attempt) {
            AVBufferRef* frames_ref = nullptr;
            int rc = avcodec_get_hw_frames_parameters(ctx, hw_device_ref_, AV_PIX_FMT_D3D11, &frames_ref);
            if (rc < 0) { LOG_WARN("decoder", "avcodec_get_hw_frames_parameters failed: %s", av_error_string(rc)); break; }
            auto* fc = reinterpret_cast<AVHWFramesContext*>(frames_ref->data);
            auto* d3d = static_cast<AVD3D11VAFramesContext*>(fc->hwctx);
            const bool srv = attempt == 0;
            if (srv) d3d->BindFlags |= D3D11_BIND_SHADER_RESOURCE;
            fc->initial_pool_size += 4;   // DPB + reorder + renderer's current/next + slack
            rc = av_hwframe_ctx_init(frames_ref);
            if (rc >= 0) {
                if (ctx->hw_frames_ctx) av_buffer_unref(&ctx->hw_frames_ctx);
                ctx->hw_frames_ctx = frames_ref;
                hw_bound_ = true;
                hw_srv_bind_ = srv;
                pix_fmt_name_ = std::string("d3d11/") + av_get_pix_fmt_name(fc->sw_format) + (srv ? "" : " (no SRV bind)");
                if (srv) LOG_INFO("decoder", "D3D11VA bound: surfaces=%s pool=%d %dx%d (BIND_DECODER|BIND_SHADER_RESOURCE → zero-copy)", av_get_pix_fmt_name(fc->sw_format), fc->initial_pool_size, fc->width, fc->height);
                else LOG_WARN("decoder", "D3D11VA bound WITHOUT shader-resource bind — renderer will use a GPU→GPU copy");
                return AV_PIX_FMT_D3D11;
            }
            LOG_WARN("decoder", "av_hwframe_ctx_init failed (%s)%s", av_error_string(rc), srv ? "; retrying without SHADER_RESOURCE bind" : "");
            av_buffer_unref(&frames_ref);
        }
    }
    for (const int* f = fmts; *f != AV_PIX_FMT_NONE; ++f) {
        const AVPixFmtDescriptor* d = av_pix_fmt_desc_get(AVPixelFormat(*f));
        if (d && !(d->flags & AV_PIX_FMT_FLAG_HWACCEL)) {
            hw_bound_ = false;
            pix_fmt_name_ = d->name;
            LOG_WARN("decoder", "hardware decode NOT available for this stream (%s: %s) — SOFTWARE decode (CPU) in effect",
                     cfg_.codec == VideoCodec::Hevc ? "hevc" : "h264", has_d3d11 ? "d3d11 offered but frames ctx failed" : "no D3D11VA profile offered by driver/FFmpeg");
            return *f;
        }
    }
    return AV_PIX_FMT_NONE;
}

bool VideoDecoder::create_codec(bool force_software) {
    const AVCodec* codec = avcodec_find_decoder(cfg_.codec == VideoCodec::Hevc ? AV_CODEC_ID_HEVC : AV_CODEC_ID_H264);
    if (!codec) { LOG_ERROR("decoder", "libavcodec has no decoder for this codec"); return false; }
    AVCodecContext* c = avcodec_alloc_context3(codec);
    c->opaque = this;
    Bytes ed = build_extradata();
    c->extradata = static_cast<uint8_t*>(av_mallocz(ed.size() + AV_INPUT_BUFFER_PADDING_SIZE));
    std::memcpy(c->extradata, ed.data(), ed.size());
    c->extradata_size = int(ed.size());
    c->flags |= AV_CODEC_FLAG_LOW_DELAY;
    c->flags2 |= AV_CODEC_FLAG2_FAST;
    const bool want_hw = !force_software && cfg_.prefer_hw && !hw_failed_ && cfg_.gpu.device && cfg_.hw_override != "sw";
    hw_bound_ = false;
    if (want_hw) {
        if (!hw_device_ref_) {
            AVBufferRef* ref = av_hwdevice_ctx_alloc(AV_HWDEVICE_TYPE_D3D11VA);
            auto* hc = reinterpret_cast<AVHWDeviceContext*>(ref->data);
            auto* d3d = static_cast<AVD3D11VADeviceContext*>(hc->hwctx);
            cfg_.gpu.device->AddRef();
            d3d->device = cfg_.gpu.device;
            cfg_.gpu.context->AddRef();
            d3d->device_context = cfg_.gpu.context;
            d3d->lock = ff_lock; d3d->unlock = ff_unlock; d3d->lock_ctx = cfg_.gpu.lock;
            const int rc = av_hwdevice_ctx_init(ref);
            if (rc < 0) { LOG_WARN("decoder", "av_hwdevice_ctx_init(d3d11va) failed: %s", av_error_string(rc)); av_buffer_unref(&ref); }
            else hw_device_ref_ = ref;
        }
        if (hw_device_ref_) {
            c->hw_device_ctx = av_buffer_ref(hw_device_ref_);
            c->get_format = get_format_thunk;
            c->extra_hw_frames = 4;
            c->thread_count = 1;   // hwaccel: no frame threads (adds latency, no gain)
            hw_name_ = "d3d11va";
        }
    }
    if (!c->hw_device_ctx) {
        hw_name_.clear();
        c->thread_type = FF_THREAD_SLICE;   // parallel within a frame; no reordering / added latency
        c->thread_count = 0;
    }
    const int rc = avcodec_open2(c, codec, nullptr);
    if (rc < 0) {
        LOG_WARN("decoder", "avcodec_open2 failed (%s): %s", hw_name_.empty() ? "software" : hw_name_.c_str(), av_error_string(rc));
        avcodec_free_context(&c);
        if (want_hw) { hw_failed_ = true; return create_codec(true); }
        return false;
    }
    ctx_ = c;
    hw_verified_ = false;
    next_pts_ = 0;
    inflight_.clear();
    LOG_INFO("decoder", "%s decoder: shared context (%s)", cfg_.codec == VideoCodec::Hevc ? "HEVC" : "H.264", hw_name_.empty() ? "software" : "d3d11va requested");
    return true;
}

void VideoDecoder::destroy_codec() {
    std::lock_guard<std::recursive_mutex> lk(codec_mu_);
    if (ctx_) avcodec_free_context(&ctx_);
    inflight_.clear();
}

void VideoDecoder::reset_state() {
    {
        std::lock_guard<std::mutex> lk(tiles_mu_);
        for (auto& t : tiles_) { t.frame.reset(); t.good = 0; t.clean = 0; t.saw_idr = false; }
    }
    { std::lock_guard<std::mutex> lk(gate_mu_); gate_.reset(); }
    { std::lock_guard<std::mutex> lk(await_mu_); tiles_await_idr_.clear(); }
    dpb_has_idr_ = false;
    await_key_ = true;
    eagain_streak_ = 0; silent_nalus_ = 0;
    reference_reset_pending_ = false; recovery_in_progress_ = false;
    frames_since_keyframe_ = 0;
    {
        std::lock_guard<std::mutex> lk(rps_mu_);
        rps_.reset();
        if (cfg_.codec == VideoCodec::Hevc && sps_.size() > 2) rps_.feed_sps(ByteView(sps_.data() + 2, sps_.size() - 2));
    }
    for (auto& d : last_clean_donl_) d.reset();
}

void VideoDecoder::drain_queue() {
    while (auto q = ring_->pop()) { QueuedNal* p = *q; p->data.clear(); free_ring_.push(std::move(p)); }
    tel_.queue_depth = 0;
}

void VideoDecoder::start() {
    if (sps_.empty() || pps_.empty() || (cfg_.codec == VideoCodec::Hevc && vps_.empty())) throw std::runtime_error("set_params() must precede start()");
    {
        std::lock_guard<std::recursive_mutex> lk(codec_mu_);
        if (!create_codec(false)) throw std::runtime_error("could not create decoder context");
    }
    if (!worker_.joinable()) { stop_ = false; worker_ = std::thread([this] { worker_loop(); }); }
}

void VideoDecoder::restart() {
    ++tel_.restarts;
    std::lock_guard<std::recursive_mutex> lk(codec_mu_);
    destroy_codec();
    reset_state();
    drain_queue();   // stale P-frames behind a restart only re-wedge the new context
    if (!sps_.empty() && !pps_.empty()) create_codec(hw_failed_);
}

void VideoDecoder::close() {
    stop_ = true;
    { std::lock_guard<std::mutex> lk(work_mu_); }
    work_cv_.notify_all();
    if (worker_.joinable()) worker_.join();
    destroy_codec();
    { std::lock_guard<std::mutex> lk(tiles_mu_); for (auto& t : tiles_) t.frame.reset(); }
    if (hw_device_ref_) av_buffer_unref(&hw_device_ref_);
}

// ── feeding ─────────────────────────────────────────────────────────────────
void VideoDecoder::feed_burst(const std::map<int, std::vector<Bytes>>& cache) {
    burst_cache_ = cache;
    size_t max_burst = 0; for (auto& kv : cache) max_burst = std::max(max_burst, kv.second.size());
    if (max_burst == 0) { LOG_INFO("decoder", "feed_burst: empty cache — gate stays armed"); return; }
    auto refeed_all = [&] {
        for (size_t j = 0; j < max_burst; ++j) for (auto& [t2, n2] : cache) if (j < n2.size()) { QueuedNal q; q.data = n2[j]; q.tile = t2; q.sync = true; q.t_au = q.t_enq = now_ns(); decode_one(q, now_ns()); }
    };
    auto fallback = [&](const char* why) {
        LOG_WARN("decoder", "%s; switching to software", why);
        hw_failed_ = true;
        { std::lock_guard<std::recursive_mutex> lk(codec_mu_); destroy_codec(); reset_state(); create_codec(true); }
        refeed_all();
    };
    sync_mode_ = true;
    const bool is_hw = !hw_name_.empty();
    std::map<int, bool> per_tile_seen_idr;
    size_t fed = 0, expected = 0;
    uint64_t good_at_start = 0; for (auto& g : good_counts()) good_at_start += g;
    for (size_t idx = 0; idx < max_burst; ++idx) {
        for (auto& [ti, nalus] : cache) {
            if (idx >= nalus.size()) continue;
            const Bytes& n = nalus[idx];
            if (cfg_.codec == VideoCodec::Hevc) {
                if (!n.empty() && hevc_is_irap(hevc_nal_type(n[0]))) per_tile_seen_idr[ti] = true;
                if (per_tile_seen_idr[ti]) ++expected;
                // Drive the RPS tracker on burst NALUs so its seen-POC set is populated for the live P-frames that follow.
                if (!n.empty()) { std::lock_guard<std::mutex> lk(rps_mu_); rps_.check_slice(view(n)); rps_.commit_decoded(); }
            } else {
                if (avc_nal_is_keyframe(view(n))) per_tile_seen_idr[ti] = true;
                if (per_tile_seen_idr[ti]) ++expected;
            }
            QueuedNal q; q.data = n; q.tile = ti; q.has_donl = false; q.donl = 0; q.t_au = now_ns(); q.t_enq = q.t_au; q.sync = true;
            decode_one(q, now_ns());
            ++fed;
        }
        if (is_hw && (idx + 1) % 8 == 0 && expected > 0) {
            uint64_t good_now = 0; for (auto& g : good_counts()) good_now += g;
            const int64_t errs = int64_t(expected) - int64_t(good_now - good_at_start);
            if (errs > HWACCEL_BURST_ERROR_THRESHOLD && expected > HWACCEL_BURST_ERROR_WINDOW) {
                char buf[160]; snprintf(buf, sizeof buf, "hwaccel burst failing (%lld errors / %zu expected / %zu fed)", (long long)errs, expected, fed);
                fallback(buf);
                sync_mode_ = false;
                return;
            }
        }
    }
    uint64_t good = 0; for (auto& g : good_counts()) good += g;
    LOG_INFO("decoder", "burst complete: fed %zu NALUs, expected %zu, decoded %llu frames (%s%s)", fed, expected, (unsigned long long)good, hw_name_.empty() ? "software" : hw_name_.c_str(), hw_bound_ ? " bound" : "");
    if (is_hw && expected > HWACCEL_BURST_ERROR_WINDOW && good < HWACCEL_BURST_MIN_FRAMES) {
        char buf[160]; snprintf(buf, sizeof buf, "hwaccel produced only %llu frames from %zu expected NALUs", (unsigned long long)good, expected);
        fallback(buf);
    }
    sync_mode_ = false;
}

void VideoDecoder::feed_nalu(ByteView nal, int tile, std::optional<uint16_t> donl, int64_t t_au, int64_t now) {
    if (nal.empty() || tile < 0 || tile >= cfg_.num_tiles) return;
    if (cfg_.codec == VideoCodec::Hevc) {
        const int nt = hevc_nal_type(nal[0]);
        if (nt < 32 && !hevc_is_irap(nt)) {
            std::set<int> missing;
            { std::lock_guard<std::mutex> lk(rps_mu_); missing = rps_.check_slice(nal); rps_.commit_decoded(); }
            if (missing.empty() && donl) last_clean_donl_[size_t(tile)] = *donl;
            if (!missing.empty()) { std::lock_guard<std::mutex> lk(gate_mu_); gate_.mark_decode_error(tile, now); }
        }
    } else {
        const int t = avc_nal_type(nal[0]);
        if (t == AVC_NAL_SPS || t == AVC_NAL_PPS) return;   // params are out-of-band (avcC); nothing to capture
        if (await_key_.load() && !avc_nal_is_keyframe(nal)) return;   // freeze on last good frame until an intra lands
    }
    auto slot = free_ring_.pop();
    QueuedNal* q = slot ? *slot : nullptr;
    if (q) {
        q->data.assign(nal.begin(), nal.end());
        q->tile = tile; q->has_donl = donl.has_value(); q->donl = donl.value_or(0); q->t_au = t_au; q->t_enq = now; q->sync = false;
    }
    QueuedNal* to_push = q;
    if (!q || !ring_->push(std::move(to_push))) {
        if (q) { QueuedNal* back = q; free_ring_.push(std::move(back)); }
        ++tel_.nalus_dropped_queue;
        // A dropped slice breaks the reference chain for everything after it: arm recovery instead of
        // letting the decoder conceal silently.
        { std::lock_guard<std::mutex> lk(gate_mu_); gate_.mark_decode_error(tile, now); }
        static LogDecimator dec;
        if (dec.tick()) LOG_WARN("decoder", "decode queue FULL — dropped slice for tile %d (drops=%llu); worker not keeping up", tile, (unsigned long long)tel_.nalus_dropped_queue.load());
        return;
    }
    ++tel_.nalus_fed;
    tel_.queue_depth = int(ring_->size());
    { std::lock_guard<std::mutex> lk(work_mu_); }
    work_cv_.notify_one();
}

void VideoDecoder::worker_loop() {
    while (!stop_) {
        auto item = ring_->pop();
        if (!item) {
            std::unique_lock<std::mutex> lk(work_mu_);
            work_cv_.wait_for(lk, std::chrono::milliseconds(5), [&] { return stop_.load() || ring_->size() > 0; });
            continue;
        }
        QueuedNal* q = *item;
        tel_.queue_depth = int(ring_->size());
        decode_one(*q, now_ns());
        q->data.clear();
        free_ring_.push(std::move(q));
    }
}

// ── decode ──────────────────────────────────────────────────────────────────
void VideoDecoder::decode_one(QueuedNal& q, int64_t now) {
    std::lock_guard<std::recursive_mutex> lk(codec_mu_);
    if (!ctx_ || q.data.empty()) return;
    const Bytes& nal = q.data;
    const int tile = q.tile;
    bool is_key = false;
    if (cfg_.codec == VideoCodec::Hevc) {
        if (nal.size() < 3) return;
        const int nt = hevc_nal_type(nal[0]);
        if (nt > 31) return;                    // SEI / EOB / control — decoder does not need them
        if (!(nal[2] & 0x80)) return;           // not first_slice_segment_in_pic_flag → skip (reference behaviour)
        is_key = hevc_is_irap(nt);
        if (is_key) {
            ++tel_.keyframes;
            bool suspicious = false;
            const int size = int(nal.size());
            if (recent_idr_sizes_.size() >= 3) {
                std::vector<int> s = recent_idr_sizes_; std::sort(s.begin(), s.end());
                if (double(size) < double(s[s.size() / 2]) * IDR_FAKE_RATIO) suspicious = true;
            }
            if (!suspicious) { recent_idr_sizes_.push_back(size); if (recent_idr_sizes_.size() > IDR_HISTORY_LEN) recent_idr_sizes_.erase(recent_idr_sizes_.begin()); }
            // Apple emits IDRs on the base SSRC only; one IDR re-roots the shared DPB for every tile.
            { std::lock_guard<std::mutex> g(gate_mu_); for (int t = 0; t < cfg_.num_tiles; ++t) gate_.mark_idr_observed(t, now, suspicious); }
            { std::lock_guard<std::mutex> t(tiles_mu_); tiles_[size_t(tile)].saw_idr = true; }
            dpb_has_idr_ = true;
            { std::lock_guard<std::mutex> a(await_mu_); tiles_await_idr_.clear(); }
            LOG_DEBUG("decoder", "IDR arrival: tile %d nt=%d size=%d suspicious=%d", tile, nt, size, int(suspicious));
        } else {
            bool blocked = !dpb_has_idr_.load();
            if (!blocked && cfg_.pertile_recovery) { std::lock_guard<std::mutex> a(await_mu_); blocked = tiles_await_idr_.count(tile) > 0; }
            if (blocked) {
                ++tel_.pre_idr_drops;
                static LogDecimator dec;
                if (dec.tick()) LOG_INFO("decoder", "dropping pre-IDR P-frame for tile %d (drops=%llu)", tile, (unsigned long long)tel_.pre_idr_drops.load());
                return;
            }
        }
    } else {
        is_key = avc_nal_is_keyframe(view(nal));
        if (await_key_.load() && !is_key) return;
        if (is_key && reference_reset_pending_.load()) {
            // Apple's recovery picture is a non-IDR intra slice: libav will not flush the poisoned DPB by itself.
            // Rebuild the context here and seed it with this independently decodable picture.
            const double waited = reference_break_ns_ ? double(now - reference_break_ns_) / 1e9 : -1.0;
            LOG_WARN("decoder", "AVC recovery: reset poisoned decoder DPB on fresh intra frame (wait=%.3fs resets=%llu trigger=%s)", waited, (unsigned long long)tel_.reference_resets.load() + 1, reference_break_trigger_.c_str());
            destroy_codec();
            reference_reset_pending_ = false;
            ++tel_.reference_resets;
            frames_since_keyframe_ = 0;
            if (!create_codec(hw_failed_)) return;
        }
        if (is_key) {
            await_key_ = false;
            ++tel_.keyframes;
            frames_since_keyframe_ = 0;
            std::lock_guard<std::mutex> g(gate_mu_);
            for (int t = 0; t < cfg_.num_tiles; ++t) gate_.mark_idr_observed(t, now);
        } else {
            ++frames_since_keyframe_;
        }
    }

    AVPacket* pkt = av_packet_alloc();
    av_new_packet(pkt, int(nal.size() + 4));
    std::memcpy(pkt->data, START_CODE, 4);
    std::memcpy(pkt->data + 4, nal.data(), nal.size());
    const int64_t pts = int64_t(next_pts_++);
    pkt->pts = pts; pkt->dts = pts;
    InFlight src; src.tile = tile; src.donl = q.donl; src.has_donl = q.has_donl; src.t_au = q.t_au;
    inflight_[pts] = src;
    if (inflight_.size() > 256) inflight_.erase(inflight_.begin(), std::prev(inflight_.end(), 64));
    const int64_t t_submit = now_ns();
    tel_.submit_latency_ms.add(double(t_submit - q.t_au) / 1e6);

    int rc = avcodec_send_packet(ctx_, pkt);
    av_packet_free(&pkt);
    bool published = false;
    if (rc < 0 && rc != AVERROR(EAGAIN)) {
        ++tel_.decode_errors;
        inflight_.erase(pts);
        LOG_DEBUG("decoder", "tile %d send_packet error: %s (nal_len=%zu)", tile, av_error_string(rc), nal.size());
        { std::lock_guard<std::mutex> g(gate_mu_); gate_.mark_decode_error(tile, now); }
        if (cfg_.codec == VideoCodec::Avc && is_key) mark_reference_chain_broken("fresh intra frame failed after DPB reset");
    } else if (rc == AVERROR(EAGAIN)) {
        ++eagain_streak_;   // backpressure, not a broken chain (no FIR here)
    }
    for (;;) {
        AVFrame* f = av_frame_alloc();
        rc = avcodec_receive_frame(ctx_, f);
        if (rc < 0) { av_frame_free(&f); break; }
        auto it = inflight_.find(f->pts);
        if (it == inflight_.end()) { LOG_DEBUG("decoder", "frame pts=%lld not in flight map", (long long)f->pts); av_frame_free(&f); continue; }
        InFlight meta = it->second;
        inflight_.erase(it);
        publish(f, meta, t_submit);
        published = true;
    }
    if (published) { eagain_streak_ = 0; silent_nalus_ = 0; recovery_in_progress_ = false; }
    else {
        ++silent_nalus_;
        if (silent_nalus_ > HWACCEL_SILENT_NALU_LIMIT && !recovery_in_progress_.load()) {
            LOG_WARN("decoder", "%s silent for %d NALUs without output; dropping P-frames + waiting for fresh IDRs (no flush)", hw_name_.empty() ? "software" : hw_name_.c_str(), silent_nalus_);
            recovery_in_progress_ = true;
            { std::lock_guard<std::mutex> g(gate_mu_); gate_.mark_decode_error(tile, now); }
            try_recovery();
            silent_nalus_ = 0;
        }
    }
}

void VideoDecoder::publish(AVFrame* f, const InFlight& meta, int64_t t_submit) {
    const int64_t t_out = now_ns();
    const int tile = meta.tile;
    if (!hw_verified_) {
        hw_verified_ = true;
        const bool hwfmt = f->format == AV_PIX_FMT_D3D11;
        if (!hw_name_.empty() && !hwfmt) { LOG_WARN("decoder", "hwaccel %s did not bind for this stream (output=%s); decoding in SOFTWARE", hw_name_.c_str(), av_get_pix_fmt_name(AVPixelFormat(f->format))); hw_name_.clear(); hw_bound_ = false; }
        if (hwfmt) hw_bound_ = true;
        if (pix_fmt_name_.empty() || !hwfmt) pix_fmt_name_ = av_get_pix_fmt_name(AVPixelFormat(f->format));
        LOG_INFO("decoder", "first decoded frame: %s %dx%d range=%s colorspace=%s", av_get_pix_fmt_name(AVPixelFormat(f->format)), f->width, f->height,
                 f->color_range == AVCOL_RANGE_JPEG ? "full" : f->color_range == AVCOL_RANGE_MPEG ? "limited" : "unspecified",
                 f->colorspace == AVCOL_SPC_BT709 ? "bt709" : (f->colorspace == AVCOL_SPC_BT470BG || f->colorspace == AVCOL_SPC_SMPTE170M) ? "bt601" : "unspecified");
    }
    const bool had_error = f->decode_error_flags != 0 || (f->flags & AV_FRAME_FLAG_CORRUPT);
    tel_.decode_latency_ms.add(double(t_out - t_submit) / 1e6);
    ++tel_.frames_out;
    if (cfg_.codec == VideoCodec::Avc && reference_reset_pending_.load()) { av_frame_free(&f); return; }   // never publish the concealed frame of a break in progress
    auto df = std::make_unique<DecodedFrame>();
    df->frame = f; df->tile = tile; df->index = ++next_index_;
    df->t_au_complete_ns = meta.t_au; df->t_submit_ns = t_submit; df->t_output_ns = t_out;
    df->had_error = had_error; df->hw = f->format == AV_PIX_FMT_D3D11;
    df->donl = meta.donl; df->has_donl = meta.has_donl;
    {
        std::lock_guard<std::mutex> lk(tiles_mu_);
        TileSlot& s = tiles_[size_t(tile)];
        if (s.frame) ++tel_.frames_replaced;   // newest wins; the render thread never queues stale frames
        s.frame = std::move(df);
        ++s.good;
        if (!had_error) ++s.clean;
    }
    if (cfg_.codec == VideoCodec::Avc && !dpb_has_idr_.load()) { dpb_has_idr_ = true; std::lock_guard<std::mutex> g(gate_mu_); for (int t = 0; t < cfg_.num_tiles; ++t) gate_.mark_idr_observed(t, t_out); }
    { std::lock_guard<std::mutex> lk(frame_cv_mu_); frame_pending_ = true; }
    frame_cv_.notify_all();
    if (on_frame_published) on_frame_published(tile);
}

// Native-aligned wedge recovery: no flush_buffers (it wipes the SHARED DPB and orphans healthy tiles).
// Only the gate-flagged broken tiles wait for the next tile-0 IDR; the rest keep decoding. Also drains
// the worker backlog so the recovery IDR is reached within ~1 RTT instead of grinding through stale P-frames.
void VideoDecoder::try_recovery() {
    std::set<int> broken;
    { std::lock_guard<std::mutex> g(gate_mu_); for (int t = 0; t < cfg_.num_tiles; ++t) if (gate_.bad_streak(t) > 0) broken.insert(t); }
    if (broken.empty()) for (int t = 0; t < cfg_.num_tiles; ++t) broken.insert(t);
    if (cfg_.pertile_recovery) { std::lock_guard<std::mutex> a(await_mu_); tiles_await_idr_.insert(broken.begin(), broken.end()); }
    else dpb_has_idr_ = false;
    { std::lock_guard<std::mutex> t(tiles_mu_); for (int b : broken) tiles_[size_t(b)].saw_idr = false; }
    eagain_streak_ = 0;
    drain_queue();
}

void VideoDecoder::mark_wedge_recovery() { std::lock_guard<std::recursive_mutex> lk(codec_mu_); try_recovery(); }

// ── render-side API ─────────────────────────────────────────────────────────
std::unique_ptr<DecodedFrame> VideoDecoder::take_latest(int tile) {
    if (tile < 0 || tile >= cfg_.num_tiles) return nullptr;
    if (!dpb_has_idr_.load()) return nullptr;
    if (cfg_.codec == VideoCodec::Hevc && cfg_.pertile_recovery) { std::lock_guard<std::mutex> a(await_mu_); if (tiles_await_idr_.count(tile)) return nullptr; }
    std::unique_ptr<DecodedFrame> out;
    { std::lock_guard<std::mutex> lk(tiles_mu_); out = std::move(tiles_[size_t(tile)].frame); }
    if (!out) return nullptr;
    std::lock_guard<std::mutex> g(gate_mu_);
    if (out->had_error) gate_.mark_decode_error(tile, now_ns()); else gate_.mark_clean(tile, now_ns());
    return out;
}

bool VideoDecoder::wait_for_frame(int timeout_ms) {
    std::unique_lock<std::mutex> lk(frame_cv_mu_);
    if (!frame_cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&] { return frame_pending_; })) return false;
    frame_pending_ = false;
    return true;
}

std::optional<uint16_t> VideoDecoder::last_clean_donl(int tile) const { return tile >= 0 && tile < cfg_.num_tiles ? last_clean_donl_[size_t(tile)] : std::nullopt; }
std::vector<uint64_t> VideoDecoder::good_counts() const { std::lock_guard<std::mutex> lk(tiles_mu_); std::vector<uint64_t> v; for (auto& t : tiles_) v.push_back(t.good); return v; }
std::vector<uint64_t> VideoDecoder::clean_counts() const { std::lock_guard<std::mutex> lk(tiles_mu_); std::vector<uint64_t> v; for (auto& t : tiles_) v.push_back(t.clean); return v; }

void VideoDecoder::mark_reference_chain_broken(const char* trigger) {
    if (!reference_reset_pending_.exchange(true)) { reference_break_ns_ = now_ns(); reference_break_trigger_ = trigger ? trigger : ""; }
    await_key_ = true;
}

void VideoDecoder::mark_hwaccel_failed(const char* trigger) {
    if (hw_failed_) return;
    LOG_WARN("decoder", "hwaccel %s failed during stream setup; continuing in software and disabling HW retries for this session (%s)", hw_name_.empty() ? "requested accelerator" : hw_name_.c_str(), trigger ? trigger : "");
    hw_failed_ = true; hw_name_.clear(); hw_bound_ = false;
}

void VideoDecoder::mark_hwaccel_reference_failure(const char* trigger) {
    if (hw_failed_ || hw_name_ != "d3d11va") return;
    hw_failed_ = true;
    LOG_WARN("decoder", "AVC d3d11va produced a confirmed broken reference chain; the fresh-intra recovery will switch this session to software (%s)", trigger ? trigger : "");
}

bool probe_hevc444_hw(const GpuDevice& gpu) {
    if (!gpu.device) return false;
    // 64x64 HEVC Main 4:4:4 8-bit IDR (VPS+SPS+PPS+slice, Annex-B) — the same sample hwcaps.py uses.
    static const Bytes sample = unhex("0000000140010c01ffff0408000003009e280000030000baba0240000000014201010408000003009e280000030000ba90041020b2dd25261734040000030004003d090020000000014401c070306011200000012801ade0d117ffd39173238b80");
    DecoderConfig cfg; cfg.codec = VideoCodec::Hevc; cfg.num_tiles = 1; cfg.prefer_hw = true; cfg.gpu = gpu;
    VideoDecoder d(cfg);
    // Split the sample into NALs.
    std::vector<Bytes> nals; size_t i = 0;
    while (i + 4 <= sample.size()) {
        if (sample[i] == 0 && sample[i + 1] == 0 && sample[i + 2] == 0 && sample[i + 3] == 1) {
            size_t j = i + 4; while (j + 4 <= sample.size() && !(sample[j] == 0 && sample[j + 1] == 0 && sample[j + 2] == 0 && sample[j + 3] == 1)) ++j;
            if (j + 4 > sample.size()) j = sample.size();
            nals.emplace_back(sample.begin() + ptrdiff_t(i + 4), sample.begin() + ptrdiff_t(j)); i = j;
        } else ++i;
    }
    if (nals.size() < 4) return false;
    std::map<int, Bytes> pps; pps[0] = nals[2];
    d.set_params(view(nals[0]), view(nals[1]), pps);
    try { d.start(); } catch (...) { return false; }
    std::map<int, std::vector<Bytes>> burst; burst[0] = {nals[3]};
    d.feed_burst(burst);
    const bool ok = d.hw_bound() && d.good_counts()[0] > 0;
    LOG_INFO("decoder", "hevc444 probe (d3d11va): %s", ok ? "HW-decoded" : "no hardware 4:4:4 path");
    d.close();
    return ok;
}

}  // namespace scshr
