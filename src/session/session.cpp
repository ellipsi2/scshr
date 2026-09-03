#include "session/session.h"
#include "app/audio.h"
#include "common/clock.h"
#include "common/log.h"
#include "media/bitstream.h"
#include "media/nalu.h"
#include "protocol/auth.h"
#include "protocol/offers.h"

extern "C" {
#include <libavutil/log.h>
}

#include <windows.h>

#include <algorithm>
#include <cstdio>
#include <random>

namespace scshr {

namespace {
// Tunables (reference values from session.py).
constexpr int64_t TX_INTERVAL_NS = 500'000'000;
constexpr int RTCP_SR_EVERY_N_TICKS = 10, TX_PROFILE_EVERY_N_TICKS = 4;
constexpr int BURST_RETRY_ATTEMPTS = 3; constexpr double BURST_RETRY_SLEEP_S = 0.8;
constexpr int DYNAMIC_SSRC_PACKET_THRESHOLD = 5;
constexpr int64_t SSRC_ADOPT_STALL_NS = 2'000'000'000;
constexpr int64_t FIR_MIN_INTERVAL_NS = 250'000'000;
constexpr int64_t DPB_ERR_WINDOW_NS = 1'000'000'000, DPB_FAST_COOLDOWN_NS = 1'000'000'000, DPB_RESTART_GRACE_NS = 0, DPB_STORM_RESET_NS = 3'000'000'000;
constexpr int DPB_ERR_THRESHOLD = 1, DPB_FORCEALL_AFTER_FIRS = 3;
constexpr int64_t DPB_FORCEALL_STALL_NS = 2'500'000'000;
constexpr int64_t SATURATION_LOSS_FREE_WINDOW_NS = 8'000'000'000, SATURATION_RESTART_GAP_NS = 8'000'000'000;
constexpr int64_t GRAYOUT_WINDOW_NS = 250'000'000;
constexpr uint64_t AVC_D3D11_REANCHOR_FRAMES = 7000;
constexpr uint32_t PACKET_POOL_SLOTS = 8192;      // 16 MiB; bounded — overflow drops are counted, never queued
constexpr uint32_t IOCP_DEPTH = 256;
const uint8_t HEARTBEAT_PAYLOAD[4] = {0x00, 0x68, 0x34, 0x00};
constexpr uint8_t AUDIO_PT = 101;

bool contains(const std::string& hay, const char* needle) { return hay.find(needle) != std::string::npos; }
std::string lower(std::string s) { for (auto& c : s) c = char(tolower(uint8_t(c))); return s; }
}  // namespace

Session* Session::active_ = nullptr;

struct Session::AudioDecoder { std::unique_ptr<AacEldDecoder> dec; };

Session::Session(const SessionConfig& cfg) : cfg_(cfg) {}
Session::~Session() { close(); }

std::pair<int, int> Session::canvas_dims() const {
    const int w = runtime_canvas_w_.load(), h = runtime_canvas_h_.load();
    if (w && h) return {w, h};
    return neg_ ? std::pair<int, int>{int(neg_->canvas_width), int(neg_->canvas_height)} : std::pair<int, int>{0, 0};
}
std::pair<int, int> Session::scaled_dims() const {
    const int w = runtime_scaled_w_.load(), h = runtime_scaled_h_.load();
    if (w && h) return {w, h};
    return neg_ ? std::pair<int, int>{int(neg_->canvas_width), int(neg_->canvas_height)} : std::pair<int, int>{0, 0};
}
int Session::num_tiles() const { if (observed_tile_count_) return observed_tile_count_; return neg_ && neg_->canvas_tiles ? int(neg_->canvas_tiles) : cfg_.tiles_per_frame; }
std::vector<rfb::DisplayRect> Session::display_rects() const { std::lock_guard<std::mutex> lk(dims_mu_); return display_rects_; }
std::optional<rfb::DisplayRect> Session::display_content_rect() const {
    auto [cw, ch] = canvas_dims();
    auto rects = display_rects();
    if (cw <= 0 || ch <= 0 || rects.empty()) return std::nullopt;
    int x0 = INT32_MAX, y0 = INT32_MAX, x1 = 0, y1 = 0;
    for (auto& r : rects) { x0 = std::min(x0, r.x); y0 = std::min(y0, r.y); x1 = std::max(x1, r.x + r.w); y1 = std::max(y1, r.y + r.h); }
    x0 = std::max(0, x0); y0 = std::max(0, y0); x1 = std::min(cw, x1); y1 = std::min(ch, y1);
    if (x1 <= x0 || y1 <= y0) return std::nullopt;
    if (x0 == 0 && y0 == 0 && x1 == cw && y1 == ch) return std::nullopt;
    return rfb::DisplayRect{0, x0, y0, x1 - x0, y1 - y0};
}
std::string Session::decoder_name() const { if (!decoder_) return "none"; return decoder_->hw_bound() ? "d3d11va" : "software"; }

// ── connect ─────────────────────────────────────────────────────────────────
void Session::connect() {
    if (connected_) return;
    try { connect_internal(); connected_ = true; }
    catch (...) { teardown(); throw; }
}

void Session::close() { stop_ = true; teardown(); connected_ = false; }

void Session::write_record(int kind, const uint8_t* data, size_t len, int64_t t) {
    if (!rec_) return;
    std::lock_guard<std::mutex> lk(rec_mu_);
    uint8_t h[12]; put_be64(h, uint64_t(t)); put_be16(h + 8, uint16_t(kind)); put_be16(h + 10, uint16_t(len));
    fwrite(h, 1, 12, rec_); fwrite(data, 1, len, rec_);
}

void Session::connect_internal() {
    LOG_INFO("session", "connecting to %s:%u (%s, codec=%s tiles=%d)", cfg_.host.c_str(), cfg_.port, cfg_.srp_first ? "srp" : "nonsrp", cfg_.codec == VideoCodec::Hevc ? "hevc" : "avc", cfg_.tiles_per_frame);
    dest_host_ = cfg_.replay_mode ? (cfg_.host.empty() ? std::string("127.0.0.1") : cfg_.host) : net::resolve_ipv4(cfg_.host);
    if (!cfg_.replay_mode && dest_host_ != cfg_.host) LOG_INFO("session", "resolved %s -> %s (IPv4 for HP UDP transport)", cfg_.host.c_str(), dest_host_.c_str());
    ctrl_port_ = cfg_.udp_ctrl_port ? cfg_.udp_ctrl_port : cfg_.port;
    video_port_ = cfg_.udp_video_port ? cfg_.udp_video_port : uint16_t(cfg_.port + 1);
    // Replay mode has no host: send feedback to the discard port so it cannot loop back into our own sockets.
    dest_ctrl_port_ = cfg_.replay_mode ? 9 : ctrl_port_; dest_video_port_ = cfg_.replay_mode ? 9 : video_port_;
    ltr_enabled_ = cfg_.codec == VideoCodec::Hevc && cfg_.ltrp;
    // 1) Bind UDP before the handshake: the burst lands ~100 ms after the 0x1c answer.
    sock_ctrl_.bind(cfg_.udp_bind_host, ctrl_port_);
    sock_video_.bind(cfg_.udp_bind_host, video_port_, 16 << 20);
    LOG_INFO("session", "UDP bound: ctrl=%u video=%u -> %s:%u/%u", ctrl_port_, video_port_, dest_host_.c_str(), ctrl_port_, video_port_);
    if (!cfg_.record_packets.empty()) {
        rec_ = fopen(cfg_.record_packets.c_str(), "wb");
        if (!rec_) LOG_WARN("session", "cannot open %s for packet recording", cfg_.record_packets.c_str());
        else { uint8_t hdr[106] = {}; std::memcpy(hdr, "SCSHRPKT", 8); put_be32(hdr + 8, 1); hdr[12] = cfg_.codec == VideoCodec::Hevc ? 1 : 0; hdr[13] = uint8_t(cfg_.tiles_per_frame); if (cfg_.replay_video_key.size() == 46) std::memcpy(hdr + 14, cfg_.replay_video_key.data(), 46); fwrite(hdr, 1, sizeof hdr, rec_); }
    }
    // 2) Apple's two-TCP warmup.
    if (cfg_.warmup_tcp && !cfg_.replay_mode) {
        try { negotiation::warmup_tcp(dest_host_, cfg_.port); }
        catch (const std::exception& e) { LOG_WARN("session", "warmup TCP failed (%s); continuing without it", e.what()); }
    }
    // 3-6) Handshake + burst under a firewall-punch loop (media must count as established return traffic).
    std::atomic<bool> punch_stop{false};
    std::thread punch([&] { punch_thread(punch_stop); });
    InitialBurst burst;
    try { burst = handshake_with_reconnect(); }
    catch (...) { punch_stop = true; punch.join(); throw; }
    punch_stop = true; punch.join();

    ssrc_to_tile_ = burst.ssrc_to_tile;
    observed_tile_count_ = int(ssrc_to_tile_.size());
    const int declared = neg_ ? int(neg_->canvas_tiles) : 0;
    if (observed_tile_count_ > 0 && declared && observed_tile_count_ != declared) LOG_WARN("session", "tile count MISMATCH: negotiation declared %d, burst observed %d — using observed", declared, observed_tile_count_);
    const int ntiles = (neg_ && neg_->canvas_tiles) ? int(neg_->canvas_tiles) : cfg_.tiles_per_frame;
    codec_name_ = burst.detected_codec;

    // 7) Decoder.
    DecoderConfig dc; dc.codec = cfg_.codec; dc.num_tiles = ntiles; dc.prefer_hw = cfg_.prefer_hw; dc.gpu = cfg_.gpu; dc.hw_override = cfg_.decoder_override;
    dc.pertile_recovery = cfg_.pertile_recovery; dc.avc_sps_patch = cfg_.avc_sps_patch;
    decoder_ = std::make_unique<VideoDecoder>(dc);
    decoder_->on_frame_published = [this](int tile) { last_publish_ns_ = now_ns(); send_ltr_ack(tile); };
    decoder_->set_params(view(burst.vps), view(burst.sps), burst.all_pps);
    avc_cfg_sps_ = burst.sps;
    active_ = this;
    av_log_set_level(AV_LOG_WARNING);
    av_log_set_callback(&Session::av_log_hook);
    decoder_->start();
    last_decoder_restart_ns_ = now_ns();
    decoder_->feed_burst(burst.tile_nalus);

    // Packet pipeline: pool + assembler seeded with the burst's leftover groups.
    pool_ = std::make_unique<PacketPool>(PACKET_POOL_SLOTS);
    assembler_ = std::make_unique<RtpAssembler>(*pool_, cfg_.codec);
    assembler_->on_flush = [this](FlushedGroup& g) { on_flushed_group(g, now_ns()); };
    assembler_->on_drop = [this](const DroppedGroup& d) { on_dropped_group(d, now_ns()); };
    for (auto& p : burst.pending) {
        const uint32_t slot = pool_->acquire();
        if (slot == UINT32_MAX) break;
        PacketSlot& s = (*pool_)[slot];
        const size_t n = std::min(p.payload.size(), PACKET_SLOT_BYTES);
        std::memcpy(s.data, p.payload.data(), n);
        s.len = uint32_t(n); s.payload_off = 0; s.payload_len = uint32_t(n); s.t_recv_ns = p.t_ns;
        assembler_->queue_packet(p.ssrc, p.ts, p.seq, p.marker, slot, now_ns());
    }

    // 8) Audio.
    if (cfg_.audio) {
        std::string why;
        aac_ = std::make_unique<AudioDecoder>();
        aac_->dec = AacEldDecoder::create(&why);
        if (!aac_->dec) { LOG_WARN("audio", "%s", why.c_str()); aac_.reset(); }
    }
    // 9b) Clipboard enable + prime.
    if (cfg_.clipboard && neg_) { send_ctrl(view(clip::build_auto_pasteboard_msg(1))); send_ctrl(view(clip::build_clipboard_request(false))); }
    // 10) Threads.
    stop_ = false;
    last_publish_ns_ = now_ns();
    snap_t_ns_ = now_ns();
    spawn_threads();
    // 11) FIR tiles that got no IDR in the burst (Apple often IDRs tile 0 only).
    for (int ti = 0; ti < ntiles; ++ti) if (!burst.last_idr.count(ti)) { LOG_DEBUG("session", "burst missed IDR for tile %d; FIR", ti); send_fir_for_tile(ti, now_ns()); }
}

void Session::punch_thread(std::atomic<bool>& stop) {
    const uint8_t z = 0;
    while (!stop) {
        sock_ctrl_.send_to(ByteView(&z, 1), dest_host_, dest_ctrl_port_);
        sock_video_.send_to(ByteView(&z, 1), dest_host_, dest_video_port_);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

InitialBurst Session::handshake_with_reconnect() {
    std::string last;
    for (int attempt = 0; attempt < BURST_RETRY_ATTEMPTS; ++attempt) {
        try { return negotiate_and_burst(); }
        catch (const BurstStarved& e) {
            last = e.what();
            if (attempt + 1 >= BURST_RETRY_ATTEMPTS) break;
            LOG_WARN("session", "burst starved (%s); full reconnect %d/%d", e.what(), attempt + 1, BURST_RETRY_ATTEMPTS);
            if (neg_) { neg_->sock.close_rst(); neg_.reset(); }
            std::this_thread::sleep_for(std::chrono::duration<double>(BURST_RETRY_SLEEP_S));
        }
    }
    throw std::runtime_error("HP stream never started across " + std::to_string(BURST_RETRY_ATTEMPTS) + " fresh handshakes (" + last + "). On the Mac, toggle Screen Sharing off/on in System Settings, then reconnect; --no-curtain can also help.");
}

InitialBurst Session::negotiate_and_burst() {
    if (cfg_.replay_mode) {
        if (cfg_.replay_video_key.size() != SRTP_KEY_BLOB_LEN) throw std::runtime_error("replay mode needs a 46-byte video key");
        replay_video_dec_ = SrtpDecryptor::from_blob(view(cfg_.replay_video_key));
        video_dec_ = replay_video_dec_.get();
        srtcp_enc_ = SrtcpEncryptor::from_blob(view(cfg_.replay_video_key));
        if (cfg_.replay_audio_key.size() == SRTP_KEY_BLOB_LEN) audio_dec_ = SrtpDecryptor::from_blob(view(cfg_.replay_audio_key));
        our_video_ssrc_ = 0x5c5c5c5c;
        LOG_INFO("session", "replay mode: waiting for media on UDP %u (no TCP negotiation)", video_port_);
        std::vector<std::pair<Bytes, int64_t>> raw;
        std::vector<uint8_t> buf(65536);
        const int64_t deadline = now_ns() + 30'000'000'000LL;
        int64_t settle = 0;
        while (now_ns() < deadline) {
            const int n = sock_video_.recv(buf.data(), buf.size(), 50);
            if (n > 0) { raw.emplace_back(Bytes(buf.begin(), buf.begin() + n), now_ns()); write_record(0, buf.data(), size_t(n), raw.back().second); if (!settle && raw.size() >= (cfg_.codec == VideoCodec::Avc ? 400u : 100u)) settle = now_ns() + 300'000'000; }
            if (settle && now_ns() >= settle) break;
        }
        return gather_initial_burst(raw, *video_dec_, cfg_.codec, cfg_.tiles_per_frame, cfg_.quality_tier);
    }
    offers::OfferOptions oo; oo.codec = cfg_.offer_codec; oo.tiles_per_frame = cfg_.tiles_per_frame; oo.ltrp = cfg_.ltrp; oo.audio_enabled = cfg_.audio;
    auto [vo, ao] = offers::create_offers(oo);
    video_offer_ = vo; audio_offer_ = ao;
    our_video_ssrc_ = offers::extract_offer_ssrc(view(vo), true);
    our_audio_ssrc_ = offers::extract_offer_ssrc(view(ao), false);
    LOG_INFO("session", "our SSRCs: video=0x%08x audio=0x%08x (audio=%s)", our_video_ssrc_.value_or(0), our_audio_ssrc_.value_or(0), cfg_.audio ? "on" : "off");
    negotiation::Params p;
    p.host = dest_host_; p.port = cfg_.port; p.username = cfg_.username; p.password = cfg_.password; p.srp_first = cfg_.srp_first;
    p.advertise = cfg_.advertise; p.hdr = cfg_.hdr; p.curtain = cfg_.curtain; p.share_console = cfg_.share_console; p.alt_session = cfg_.alt_session;
    p.on_session_choice = cfg_.on_session_choice; p.audio_offer = ao; p.video_offer = vo; p.legacy_cursor = cfg_.legacy_cursor;
    neg_ = std::make_unique<negotiation::Result>(negotiation::connect_and_negotiate(p));
    server_w_ = neg_->server_width; server_h_ = neg_->server_height;
    video_dec_ = neg_->video_decryptor.get();
    if (rec_) {
        // Patch the keys into the placeholder header now that they are known (records follow the 106-byte header).
        std::lock_guard<std::mutex> lk(rec_mu_);
        const long pos = ftell(rec_);
        fseek(rec_, 14, SEEK_SET);
        fwrite(neg_->keys.video_key_s.data(), 1, 46, rec_); fwrite(neg_->keys.audio_key_s.data(), 1, 46, rec_);
        fseek(rec_, pos, SEEK_SET);
    }
    audio_dec_ = SrtpDecryptor::from_blob(view(neg_->keys.audio_key_s));
    srtcp_dec_ = SrtcpDecryptor::from_blob(view(neg_->keys.video_key_s));
    srtcp_enc_ = SrtcpEncryptor::from_blob(view(neg_->keys.video_key_v));
    if (our_audio_ssrc_) audio_enc_ = SrtpEncryptor::from_blob(view(neg_->keys.audio_key_v), *our_audio_ssrc_);
    // Drain the start burst (blocking recv, ≤ 2 s HEVC / 4 s AVC, stop 50 ms after the last packet).
    const bool is_avc = cfg_.codec == VideoCodec::Avc;
    const double max_s = is_avc ? 4.0 : 2.0;
    const size_t min_packets = is_avc ? 400 : 100;
    std::vector<std::pair<Bytes, int64_t>> raw;
    const int64_t deadline = now_ns() + int64_t(max_s * 1e9);
    std::vector<uint8_t> buf(65536);
    int64_t settle_deadline = 0;
    while (now_ns() < deadline) {
        const int n = sock_video_.recv(buf.data(), buf.size(), 50);
        if (n > 0) { raw.emplace_back(Bytes(buf.begin(), buf.begin() + n), now_ns()); write_record(0, buf.data(), size_t(n), raw.back().second); }
        else if (n == 0 && !raw.empty()) {
            // burst.py: wait until min_packets (or deadline), then settle 300 ms
            if (raw.size() >= min_packets) { if (!settle_deadline) settle_deadline = now_ns() + 300'000'000; if (now_ns() >= settle_deadline) break; }
            else if (now_ns() > deadline) break;
        }
        if (raw.size() >= min_packets && settle_deadline && now_ns() >= settle_deadline) break;
        if (raw.size() >= min_packets && !settle_deadline) settle_deadline = now_ns() + 300'000'000;
    }
    return gather_initial_burst(raw, *video_dec_, cfg_.codec, cfg_.tiles_per_frame, cfg_.quality_tier);
}

void Session::spawn_threads() {
    threads_.emplace_back([this] { packet_thread(); });
    threads_.emplace_back([this] { ctrl_thread(); });
    threads_.emplace_back([this] { tcp_thread(); });
    threads_.emplace_back([this] { tx_thread(); });
    if (cfg_.clipboard && read_local_clipboard) threads_.emplace_back([this] { clipboard_thread(); });
}

void Session::teardown() {
    stop_ = true;
    { std::lock_guard<std::mutex> lk(tx_mu_); tx_wake_ = true; }
    tx_cv_.notify_all();
    if (rx_) rx_->stop();
    for (auto& t : threads_) if (t.joinable() && t.get_id() != std::this_thread::get_id()) t.join();
    threads_.clear();
    if (active_ == this) { av_log_set_callback(av_log_default_callback); active_ = nullptr; }
    if (decoder_) { decoder_->close(); decoder_.reset(); }
    rx_.reset();
    sock_ctrl_.close(); sock_video_.close();
    if (neg_) { neg_->sock.close_rst(); neg_.reset(); }
    video_dec_ = nullptr; replay_video_dec_.reset();
    assembler_.reset(); pool_.reset();
    ssrc_to_tile_.clear();
    runtime_canvas_w_ = runtime_canvas_h_ = runtime_scaled_w_ = runtime_scaled_h_ = 0;
    { std::lock_guard<std::mutex> lk(dims_mu_); display_rects_.clear(); }
    needs_post_layout_fir_ = needs_param_harvest_ = avc_needs_reconfig_ = false;
    harvest_vps_.clear(); harvest_sps_.clear(); harvest_pps_.clear();
    if (rec_) { fclose(rec_); rec_ = nullptr; }
    aac_.reset();
}

// ── control-channel send helpers ────────────────────────────────────────────
void Session::send_ctrl(ByteView plain) {
    if (!neg_ || !neg_->cipher) return;
    try {
        std::lock_guard<std::mutex> lk(neg_->cipher->send_mutex());
        Bytes enc = neg_->cipher->encrypt_message(plain);
        neg_->sock.send_all(view(enc));
        ++tx_pkts_;
    } catch (const std::exception& e) { LOG_DEBUG("session", "ctrl send dropped: %s", e.what()); }
}

void Session::pointer_event(uint8_t buttons, int x, int y) {
    if (!neg_) return;
    auto [cw, ch] = canvas_dims();
    const int cx = std::clamp(x, 0, std::max(0, cw - 1)), cy = std::clamp(y, 0, std::max(0, ch - 1));
    // Apple's stock client wraps every pointer event in msg 0x10 (cursor-tracker side effects); see input.py.
    send_ctrl(view(rfb::build_msg10_pointer(ByteView(neg_->cipher->cbc_key()), buttons, cx, cy)));
}
void Session::scroll_event(int x, int y, int dy) {
    if (dy == 0) return;
    const uint8_t bit = dy < 0 ? rfb::BTN_SCROLL_UP : rfb::BTN_SCROLL_DOWN;
    for (int i = 0; i < std::abs(dy); ++i) { pointer_event(bit, x, y); pointer_event(0, x, y); }
}
void Session::key_event(bool down, uint32_t keysym) { if (keysym) send_ctrl(view(rfb::build_key_event(down, keysym))); }
void Session::cut_text(const std::string& text) { if (!text.empty()) send_ctrl(view(clip::build_clipboard_send(text))); }

void Session::request_fir(std::optional<int> tile) {
    if (!decoder_ || !neg_) return;
    const int64_t now = now_ns();
    if (!tile) {
        { std::lock_guard<std::mutex> g(decoder_->gate_mutex()); decoder_->gate().force_keyframe_all(now); }
        for (int ti = 0; ti < std::min(num_tiles(), decoder_->num_tiles()); ++ti) send_fir_for_tile(ti, now);
    } else {
        { std::lock_guard<std::mutex> g(decoder_->gate_mutex()); decoder_->gate().mark_decode_error(*tile, now); }
        send_fir_for_tile(*tile, now);
    }
}

void Session::send_dynamic_resolution(int width, int height, double hidpi_scale) {
    if (!neg_) { LOG_INFO("session", "dynamic resolution ignored (replay mode)"); return; }
    LOG_INFO("session", "send_dynamic_resolution: requesting %dx%d @%gx", width, height, hidpi_scale);
    send_ctrl(view(rfb::build_virtual_display(width, height, hidpi_scale, false)));
    send_ctrl(view(rfb::build_fbu_request(false)));
    request_fir();
}

// ── packet thread: UDP video → SRTP → RTP → assembler ────────────────────────
void Session::packet_thread() {
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    rx_ = std::make_unique<net::IocpReceiver>(sock_video_, *pool_, IOCP_DEPTH);
    SrtpDecryptor& dec = *video_dec_;
    net::RecvBatch batch;
    int64_t last_evict = now_ns();
    std::mt19937 rng(12345);
    std::uniform_real_distribution<double> uni(0.0, 100.0);
    while (!stop_) {
        if (!rx_->wait(20, batch)) break;
        const int64_t now = now_ns();
        for (auto& it : batch.items) {
            PacketSlot& s = (*pool_)[it.slot];
            ++rx_pkts_video_; rx_bytes_video_ += s.len;
            if (rec_) write_record(0, s.data, s.len, s.t_recv_ns);
            if (cfg_.drop_pct > 0 && uni(rng) < cfg_.drop_pct) { pool_->release(it.slot); continue; }
            RtpHeaderInfo h;
            if (!dec.decrypt(s.data, s.len, h)) { ++srtp_auth_fail_; pool_->release(it.slot); continue; }
            s.payload_off = uint32_t(h.header_len); s.payload_len = uint32_t(h.payload_len);
            assembler_->track_seq(h.ssrc, h.seq, s.t_recv_ns);
            if (auto& np = assembler_->nack_pending()[h.ssrc]; !np.empty()) { std::lock_guard<std::mutex> lk(tx_mu_); tx_wake_ = true; tx_cv_.notify_one(); }
            note_unknown_ssrc(h.ssrc, now);
            assembler_->queue_packet(h.ssrc, h.timestamp, h.seq, h.marker, it.slot, s.t_recv_ns);
        }
        if (now - last_evict >= 20'000'000) { last_evict = now; assembler_->evict_stale(now); }
    }
}

void Session::on_flushed_group(FlushedGroup& g, int64_t now) {
    auto tit = ssrc_to_tile_.find(g.ssrc);
    if (tit == ssrc_to_tile_.end()) return;   // not in the subscribed tier
    const int ti = tit->second;
    tile_bytes_[ti] += g.bytes;
    std::optional<uint16_t> donl = ltr_enabled_ ? first_donl(g.payloads) : std::nullopt;
    if (cfg_.codec == VideoCodec::Avc && avc_needs_reconfig_.load()) {
        maybe_reharvest_avc_config(g.payloads);
        if (avc_needs_reconfig_.load()) return;   // do not feed new-canvas slices under the old SPS
    }
    static thread_local Bytes au; static thread_local std::vector<NalRange> ranges;
    au.clear(); ranges.clear();
    if (cfg_.codec == VideoCodec::Avc) reassemble_h264(g.payloads, au, ranges); else reassemble_hevc(g.payloads, au, ranges);
    if (needs_param_harvest_.load() && !ranges.empty() && cfg_.codec != VideoCodec::Avc) {
        harvest_param_sets(au, ranges);
        if (needs_param_harvest_.load()) return;   // old-canvas context: drop until the new param sets land
    }
    if (g.incomplete) { ++incomplete_; return; }   // never feed a partial access unit (native viewer behaviour)
    ++reconstructed_;
    if (ti == 0) { if (last_au_ns_) au_interval_ms_.add(double(g.t_last_ns - last_au_ns_) / 1e6); last_au_ns_ = g.t_last_ns; }
    for (auto& r : ranges) decoder_->feed_nalu(ByteView(au.data() + r.off, r.len), ti, donl, g.t_last_ns, now);
}

void Session::on_dropped_group(const DroppedGroup& d, int64_t now) {
    auto tit = ssrc_to_tile_.find(d.ssrc);
    if (cfg_.codec == VideoCodec::Avc && tit != ssrc_to_tile_.end() && decoder_) {
        char trig[160];
        snprintf(trig, sizeof trig, "RTP access unit incomplete after repair window (%s; packets=%zu age=%.1fms)", d.reason, d.packets, double(d.age_ns) / 1e6);
        LOG_WARN("session", "%s — dropping frame and requesting fresh intra", trig);
        decoder_->mark_reference_chain_broken(trig);
        { std::lock_guard<std::mutex> g(decoder_->gate_mutex()); decoder_->gate().mark_decode_error(tit->second, now); }
        { std::lock_guard<std::mutex> lk(tx_mu_); tx_wake_ = true; }
        tx_cv_.notify_one();
    }
}

void Session::note_unknown_ssrc(uint32_t ssrc, int64_t now) {
    if (ssrc_to_tile_.count(ssrc) || !video_dec_) return;
    const bool have_active = !ssrc_to_tile_.empty();
    const int64_t lp = last_publish_ns_.load();
    const bool recently_published = lp > 0 && now - lp < SSRC_ADOPT_STALL_NS;
    if (have_active && recently_published) return;
    const auto& counts = video_dec_->ssrc_counts();
    std::vector<uint32_t> cands;
    for (auto& kv : counts) if (!ssrc_to_tile_.count(kv.first) && !ssrc_blacklist_.count(kv.first) && kv.second >= DYNAMIC_SSRC_PACKET_THRESHOLD) cands.push_back(kv.first);
    std::sort(cands.begin(), cands.end());
    const int want = cfg_.tiles_per_frame;
    if (int(cands.size()) < want) return;
    std::vector<uint32_t> run{cands[0]}; std::vector<uint32_t> group;
    if (want == 1) group = run;
    else {
        for (size_t i = 1; i < cands.size(); ++i) {
            if (cands[i] - run.back() <= 1 && int(run.size()) < want) { run.push_back(cands[i]); if (int(run.size()) == want) { group = run; break; } }
            else run = {cands[i]};
        }
    }
    if (group.empty()) return;
    std::map<uint32_t, int> nm; for (size_t i = 0; i < group.size(); ++i) nm[group[i]] = int(i);
    if (nm == ssrc_to_tile_) return;
    std::string s; for (uint32_t x : group) { char b[16]; snprintf(b, sizeof b, "0x%08x ", x); s += b; }
    LOG_INFO("session", "adopting fresh SSRC group: %s", s.c_str());
    for (auto& kv : ssrc_to_tile_) ssrc_blacklist_.insert(kv.first);
    ssrc_to_tile_ = nm;
    observed_tile_count_ = int(nm.size());
    last_ssrc_adopt_ns_ = now;
    ++ssrc_changes_;
    last_publish_ns_ = now;   // grace window before another adoption can trigger
    if (!decoder_) return;
    std::lock_guard<std::recursive_mutex> lk(policy_mu_);
    if (needs_param_harvest_.load()) { LOG_INFO("session", "SSRC adoption deferred — waiting for param harvest"); dpb_error_window_.clear(); request_fir(); return; }
    dpb_error_window_.clear();
    const int64_t last_restart = last_decoder_restart_ns_;
    const bool must_restart = cfg_.codec == VideoCodec::Avc || now - last_restart >= 3'000'000'000;
    if (must_restart) {
        last_decoder_restart_ns_ = now;
        if (cfg_.codec == VideoCodec::Avc) LOG_INFO("session", "AVC SSRC generation change: resetting decoder DPB before fresh keyframe");
        decoder_->restart();
    }
    request_fir();
}

void Session::maybe_reharvest_avc_config(const std::vector<ByteView>& payloads) {
    for (ByteView p : payloads) {
        if (p.empty() || p[0] != APPLE_AVC_CONFIG_MARKER) continue;
        auto cfg = parse_avc_config(p);
        if (!cfg || cfg->sps.empty() || cfg->sps == avc_cfg_sps_) continue;
        LOG_INFO("session", "AVC: new avcC config after resize → set_params + restart (SPS %zuB, PPS %zuB)", cfg->sps.size(), cfg->pps.size());
        avc_cfg_sps_ = cfg->sps;
        std::map<int, Bytes> pps; pps[0] = cfg->pps;
        decoder_->set_params({}, view(cfg->sps), pps);
        decoder_->restart();
        avc_needs_reconfig_ = false;
        last_decoder_restart_ns_ = now_ns();
        request_fir();
        return;
    }
}

void Session::harvest_param_sets(const Bytes& au, const std::vector<NalRange>& ranges) {
    for (auto& r : ranges) {
        ByteView n(au.data() + r.off, r.len);
        if (n.size() < 2) continue;
        const int nt = hevc_nal_type(n[0]);
        if (nt == HEVC_NAL_VPS) harvest_vps_ = to_bytes(n);
        else if (nt == HEVC_NAL_SPS) harvest_sps_ = to_bytes(n);
        else if (nt == HEVC_NAL_PPS && n.size() > 2) harvest_pps_[hevc_pps_id(n)] = to_bytes(n);
    }
    if (!harvest_vps_.empty() && !harvest_sps_.empty() && !harvest_pps_.empty()) {
        LOG_INFO("session", "harvested param sets from new stream: VPS=%zuB SPS=%zuB PPS=%zu", harvest_vps_.size(), harvest_sps_.size(), harvest_pps_.size());
        decoder_->set_params(view(harvest_vps_), view(harvest_sps_), harvest_pps_);
        decoder_->restart();
        needs_param_harvest_ = false;
        request_fir();
    }
}

// ── ctrl thread: audio RTP + RTCP (rtcp-muxed on UDP 5900) ──────────────────
void Session::ctrl_thread() {
    std::vector<uint8_t> buf(65536);
    while (!stop_) {
        const int n = sock_ctrl_.recv(buf.data(), buf.size(), 200);
        if (n <= 0) { if (n < 0 && stop_) break; continue; }
        ++rx_pkts_ctrl_;
        if (rec_) write_record(1, buf.data(), size_t(n), now_ns());
        const bool rtcp = n >= 2 && (buf[0] & 0xC0) == 0x80 && (buf[1] & 0x7F) >= 64 && (buf[1] & 0x7F) <= 95;
        if (!rtcp) {
            ++rx_pkts_audio_;
            if (!audio_dec_ || !aac_ || !on_audio) continue;
            RtpHeaderInfo h;
            if (!audio_dec_->decrypt(buf.data(), size_t(n), h)) continue;
            std::vector<float> pcm = aac_->dec->decode(ByteView(buf.data() + h.header_len, h.payload_len));
            if (!pcm.empty()) on_audio(pcm.data(), pcm.size() / 2);
            continue;
        }
        ++rx_pkts_rtcp_;
        if (!srtcp_dec_) continue;
        auto plain = srtcp_dec_->unprotect(ByteView(buf.data(), size_t(n)));
        if (!plain) continue;
        for (auto& [ssrc, mid32] : rtcp::parse_sr(view(*plain))) { std::lock_guard<std::mutex> lk(sr_mu_); server_sr_[ssrc] = {mid32, double(wall_time_ns()) / 1e9}; }
    }
}

// ── TCP thread ──────────────────────────────────────────────────────────────
void Session::tcp_thread() {
    if (!neg_) { while (!stop_) std::this_thread::sleep_for(std::chrono::milliseconds(200)); return; }
    for (auto& m : neg_->leftover_msgs) handle_tcp_msg(view(m));
    neg_->leftover_msgs.clear();
    neg_->sock.set_timeout(1.0);
    while (!stop_) {
        bool to = false; Bytes chunk;
        try { chunk = neg_->sock.recv_some(65536, &to); }
        catch (const std::exception& e) { LOG_INFO("session", "TCP control read failed (%s); marking session dead", e.what()); connected_ = false; return; }
        if (to) continue;
        ++rx_pkts_tcp_;
        tcp_buf_.insert(tcp_buf_.end(), chunk.begin(), chunk.end());
        std::vector<Bytes> msgs;
        const size_t consumed = neg_->cipher->decrypt_stream(view(tcp_buf_), msgs);
        for (auto& m : msgs) handle_tcp_msg(view(m));
        if (consumed) tcp_buf_.erase(tcp_buf_.begin(), tcp_buf_.begin() + ptrdiff_t(consumed));
    }
}

void Session::handle_tcp_msg(ByteView msg) {
    if (msg.empty()) return;
    ++rx_msg_type_counts_[msg[0]];
    if (clip_reasm_.in_progress()) { if (auto full = clip_reasm_.feed(msg)) handle_clipboard_send(view(*full)); return; }
    const uint8_t t = msg[0];
    if (t == 0x14) {
        const int cmd = msg.size() >= 8 ? be16(msg.data() + 6) : -1;
        if (cmd != last_misc_cmd_) { LOG_DEBUG("session", "server sent 0x14 misc-status (cmd=%d)", cmd); last_misc_cmd_ = cmd; }
        if (cmd == 2 && cfg_.clipboard) { LOG_INFO("session", "remote clipboard changed; sending fetch (0x0b)"); send_ctrl(view(clip::build_clipboard_request(false))); }
        return;
    }
    if (t == 0x1f) { if (auto full = clip_reasm_.feed(msg)) handle_clipboard_send(view(*full)); return; }
    if (t == 0x00) handle_fbu(msg);
}

void Session::handle_fbu(ByteView msg) {
    if (msg.size() < 4) return;
    const size_t n_rects = be16(msg.data() + 2);
    size_t off = 4;
    bool saw_cursor = false;
    for (size_t i = 0; i < n_rects; ++i) {
        if (off + 12 > msg.size()) return;
        const int f0 = be16(msg.data() + off), f1 = be16(msg.data() + off + 2), f2 = be16(msg.data() + off + 4), f3 = be16(msg.data() + off + 6);
        const int32_t enc = int32_t(be32(msg.data() + off + 8));
        off += 12;
        if (enc == 1104) {
            saw_cursor = true;
            const int consumed = handle_cursor_rect(msg, off, f0, f1, f2, f3);
            if (consumed < 0) return;
            off += size_t(consumed);
        } else if (enc == 1010 || enc == 1011 || enc == 1107 || enc == 1109 || enc == 1110 || enc == 0x3f2 || enc == 0x3f3 || enc == 0x3ea || enc == 0x453 || enc == 0x455 || enc == 0x456) {
            if (off + 2 > msg.size()) return;
            const size_t sz = be16(msg.data() + off);
            if (off + 2 + sz > msg.size()) return;
            off += 2 + sz;
        } else if (enc == 0x451) {
            if (off + 2 > msg.size()) return;
            const size_t plen = be16(msg.data() + off);
            if (off + 2 + plen > msg.size()) return;
            auto layout = rfb::parse_apple_display_layout(msg.subspan(off + 2, plen));
            bool needs_arm = false;
            if (layout) {
                bool changed_rects = false;
                { std::lock_guard<std::mutex> lk(dims_mu_); if (layout->rects != display_rects_) { display_rects_ = layout->rects; changed_rects = true; } }
                if (changed_rects) {
                    std::string s; for (auto& r : layout->rects) { char b[64]; snprintf(b, sizeof b, "#%u@%d,%d %dx%d ", r.display_id, r.x, r.y, r.w, r.h); s += b; }
                    LOG_INFO("session", "AppleDisplayLayout: %zu display(s): %s", layout->rects.size(), s.c_str());
                }
            }
            if (plen >= 10) {
                const int sw = be16(msg.data() + off + 2), sh = be16(msg.data() + off + 4), bw = be16(msg.data() + off + 6), bh = be16(msg.data() + off + 8);
                const int new_bw = (bw && bh) ? bw : runtime_canvas_w_.load(), new_bh = (bw && bh) ? bh : runtime_canvas_h_.load();
                if (sw && sh) {
                    const bool had = runtime_canvas_w_ > 0 && runtime_canvas_h_ > 0;
                    const bool changed = had && (new_bw != runtime_canvas_w_ || new_bh != runtime_canvas_h_);
                    if (new_bw && new_bh) { runtime_canvas_w_ = new_bw; runtime_canvas_h_ = new_bh; }
                    runtime_scaled_w_ = sw; runtime_scaled_h_ = sh;
                    LOG_INFO("session", "AppleDisplayLayout: scaled=%dx%d backing=%dx%d changed=%d", sw, sh, bw, bh, int(changed));
                    if (changed) {
                        needs_arm = true;
                        if (cfg_.codec != VideoCodec::Avc) { needs_param_harvest_ = true; harvest_vps_.clear(); harvest_sps_.clear(); harvest_pps_.clear(); LOG_INFO("session", "AppleDisplayLayout: flagged param harvest for new canvas"); }
                        else { avc_needs_reconfig_ = true; LOG_INFO("session", "AppleDisplayLayout: armed AVC avcC re-harvest for new canvas"); }
                    }
                    if (on_layout_changed) on_layout_changed();
                }
            }
            send_cursor_rearm();
            if (needs_arm) schedule_post_layout_arm();
            off += 2 + plen;
        } else {
            ++fbu_video_rects_;
            LOG_DEBUG("session", "FBU rect with video/unknown encoding=%d; aborting walk (video_rects=%llu)", enc, (unsigned long long)fbu_video_rects_);
            return;
        }
    }
    if (saw_cursor) send_ctrl(view(rfb::build_fbu_request(true, 0, 0, 1, 1)));   // 1x1 keepalive re-arms the cursor sender without pulling video
}

int Session::handle_cursor_rect(ByteView msg, size_t off, int hx, int hy, int w, int h) {
    if (off + 8 > msg.size()) return -1;
    const uint32_t cache_id = be32(msg.data() + off), comp = be32(msg.data() + off + 4);
    const size_t poff = off + 8;
    if (poff + comp > msg.size()) return -1;
    if (comp == 0) {
        auto it = cursor_cache_.find(cache_id);
        if (it == cursor_cache_.end()) { LOG_DEBUG("session", "cursor cache miss for cache_id=%u", cache_id); notify_cursor(nullptr); return 8; }
        notify_cursor(it->second);
        return 8;
    }
    auto raw = clip::inflate_sync_flush(msg.subspan(poff, comp));
    if (!raw) { LOG_WARN("session", "cursor zlib decompress failed"); return int(8 + comp); }
    const size_t pix = size_t(w) * size_t(h) * 4, mask = size_t(w) * size_t(h);
    if (raw->size() != pix + mask) { LOG_DEBUG("session", "cursor size mismatch (got %zu, expected %zu)", raw->size(), pix + mask); return int(8 + comp); }
    auto img = std::make_shared<CursorShape>();
    img->w = w; img->h = h; img->hx = hx; img->hy = hy; img->rgba.resize(pix);
    for (size_t p = 0; p < mask; ++p) { const size_t o = p * 4; img->rgba[o] = (*raw)[o + 2]; img->rgba[o + 1] = (*raw)[o + 1]; img->rgba[o + 2] = (*raw)[o]; img->rgba[o + 3] = (*raw)[pix + p]; }
    cursor_cache_[cache_id] = img; cursor_cache_order_.push_back(cache_id);
    if (cursor_cache_.size() > 64) { cursor_cache_.erase(cursor_cache_order_.front()); cursor_cache_order_.erase(cursor_cache_order_.begin()); }
    LOG_DEBUG("session", "cursor: cache_id=%u %dx%d hotspot=(%d,%d) compressed=%uB", cache_id, w, h, hx, hy, comp);
    notify_cursor(img);
    return int(8 + comp);
}

void Session::notify_cursor(std::shared_ptr<const CursorShape> img) {
    ++cursor_msgs_; cursor_last_ns_ = now_ns();
    if (img) last_cursor_ = img;
    if (on_cursor) on_cursor(img);
}

void Session::handle_clipboard_send(ByteView full) {
    auto h = clip::parse_send_header(full);
    if (!h) return;
    auto dec = clip::inflate_sync_flush(full.subspan(16, h->compressed));
    if (!dec) { LOG_WARN("session", "clipboard decompress failed"); return; }
    auto items = clip::parse_items(view(*dec));
    auto text = clip::text_from_items(items);
    if (!text) { LOG_INFO("session", "clipboard recv: no text flavour (%zu items)", items.size()); return; }
    LOG_INFO("session", "clipboard recv: %zu items, text=%zu chars", items.size(), text->size());
    { std::lock_guard<std::mutex> lk(clip_mu_); last_received_clipboard_ = *text; }
    if (write_local_clipboard) write_local_clipboard(*text);
    if (on_clipboard_text) on_clipboard_text(*text);
}

void Session::clipboard_thread() {
    auto norm = [](std::string s) { std::string o; for (size_t i = 0; i < s.size(); ++i) { if (s[i] == '\r' && i + 1 < s.size() && s[i + 1] == '\n') continue; o.push_back(s[i]); } while (!o.empty() && isspace(uint8_t(o.back()))) o.pop_back(); return o; };
    std::string last_seen = norm(read_local_clipboard().value_or(""));
    while (!stop_) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (stop_) return;
        auto cur = read_local_clipboard();
        if (!cur) continue;
        const std::string c = norm(*cur);
        if (c.empty() || c == last_seen) continue;
        last_seen = c;
        { std::lock_guard<std::mutex> lk(clip_mu_); if (c == norm(last_received_clipboard_)) continue; }
        cut_text(c);
        LOG_INFO("session", "clipboard send: %zu chars", c.size());
    }
}

void Session::send_cursor_rearm() { send_ctrl(view(rfb::build_fbu_request(false))); }

void Session::schedule_post_layout_arm() {
    if (!neg_) return;
    Bytes m = negotiation::build_0x1c(view(audio_offer_), view(video_offer_), neg_->keys, cfg_.alt_session, cfg_.legacy_cursor);
    send_ctrl(view(m));
    LOG_INFO("session", "post-layout: sent 0x1c re-offer (%zuB)", m.size());
    needs_post_layout_fir_ = true;
}

// ── TX thread ───────────────────────────────────────────────────────────────
void Session::tx_thread() {
    while (!stop_) {
        { std::lock_guard<std::mutex> lk(tx_mu_); tx_wake_ = false; }
        ++tx_tick_;
        const int64_t now = now_ns();
        try {
            send_heartbeat();
            send_rr_and_maybe_sr();
            if (needs_post_layout_fir_.exchange(false)) request_fir();
            drain_pending_nack();
            drain_pending_fir(now);
            maybe_reanchor_d3d11va_avc(now);
            check_stall(now);
            send_ctrl(view(rfb::build_fbu_request(true, 0, 0, 1, 1)));   // cursor-sender keepalive
            if (tx_tick_ % TX_PROFILE_EVERY_N_TICKS == 0) log_profile_snapshot();
        } catch (const std::exception& e) { LOG_DEBUG("session", "tx tick error: %s", e.what()); }
        std::unique_lock<std::mutex> lk(tx_mu_);
        tx_cv_.wait_for(lk, std::chrono::nanoseconds(TX_INTERVAL_NS), [&] { return tx_wake_ || stop_.load(); });
    }
}

void Session::send_heartbeat() {
    if (!audio_enc_) return;
    Bytes p = audio_enc_->encrypt(ByteView(HEARTBEAT_PAYLOAD, 4), AUDIO_PT);
    sock_ctrl_.send_to(view(p), dest_host_, dest_ctrl_port_);
    ++tx_pkts_;
}

void Session::send_rr_and_maybe_sr() {
    if (!srtcp_enc_ || !our_video_ssrc_) return;
    std::vector<uint32_t> sources; std::map<uint32_t, rtcp::SsrcStat> stats;
    for (auto& kv : ssrc_to_tile_) { sources.push_back(kv.first); auto it = assembler_->seq_state().find(kv.first); if (it != assembler_->seq_state().end()) stats[kv.first] = {it->second.max_seq, it->second.roc}; }
    std::map<uint32_t, rtcp::SrArrival> sr; { std::lock_guard<std::mutex> lk(sr_mu_); sr = server_sr_; }
    Bytes rr = rtcp::build_rr(*our_video_ssrc_, sources, stats, sr);
    if (tx_tick_ % RTCP_SR_EVERY_N_TICKS == 0) { Bytes s = rtcp::build_empty_sr(*our_video_ssrc_); s.insert(s.end(), rr.begin(), rr.end()); rr = s; }
    sock_ctrl_.send_to(view(srtcp_enc_->protect(view(rr))), dest_host_, dest_ctrl_port_);
    ++tx_pkts_;
}

void Session::drain_pending_nack() {
    if (!srtcp_enc_ || !our_video_ssrc_ || !assembler_) return;
    auto& np = assembler_->nack_pending();
    for (auto& kv : np) {
        if (kv.second.empty()) continue;
        std::set<uint16_t> seqs; seqs.swap(kv.second);
        Bytes n = rtcp::build_nack(*our_video_ssrc_, kv.first, seqs);
        if (n.empty()) continue;
        sock_ctrl_.send_to(view(srtcp_enc_->protect(view(rtcp::compound_with_rr(*our_video_ssrc_, view(n))))), dest_host_, dest_ctrl_port_);
        ++tx_pkts_; ++nack_sent_;
    }
}

bool Session::send_fir_for_tile(int tile, int64_t now, bool record_grayout) {
    uint32_t target = 0; bool found = false;
    for (auto& kv : ssrc_to_tile_) if (kv.second == tile) { target = kv.first; found = true; break; }
    if (!found || !our_video_ssrc_ || !srtcp_enc_) return false;
    {
        std::lock_guard<std::recursive_mutex> lk(policy_mu_);
        auto it = last_fir_per_tile_.find(tile);
        if (it != last_fir_per_tile_.end() && now - it->second < FIR_MIN_INTERVAL_NS) return false;   // coalesce multi-source FIR storms
        last_fir_per_tile_[tile] = now;
    }
    // AVPF FIR + PLI + the legacy PT=192 FIR the native viewer uses (screensharingd answers the legacy one reliably).
    Bytes body = rtcp::build_fir(*our_video_ssrc_, target, uint8_t(tx_tick_ & 0xFF));
    Bytes pli = rtcp::build_pli(*our_video_ssrc_, target); body.insert(body.end(), pli.begin(), pli.end());
    Bytes leg = rtcp::build_fir_legacy(target); body.insert(body.end(), leg.begin(), leg.end());
    sock_ctrl_.send_to(view(srtcp_enc_->protect(view(rtcp::compound_with_rr(*our_video_ssrc_, view(body))))), dest_host_, dest_ctrl_port_);
    ++tx_pkts_; ++fir_sent_;
    LOG_DEBUG("session", "FIR/PLI sent for tile %d (ssrc=0x%08x)", tile, target);
    if (record_grayout) {
        std::lock_guard<std::recursive_mutex> lk(policy_mu_);
        if (grayout_tiles_.empty() || now - grayout_window_ns_ >= GRAYOUT_WINDOW_NS) { if (!grayout_tiles_.empty()) flush_grayout(now); grayout_window_ns_ = now; }
        grayout_tiles_.insert(tile);
    }
    return true;
}

void Session::flush_grayout(int64_t) {
    if (grayout_tiles_.empty()) return;
    std::string t; for (int x : grayout_tiles_) t += std::to_string(x) + " ";
    LOG_INFO("session", "gray-out: tiles [%s] recovering via FIR (libav: %s)", t.c_str(), last_concealment_msg_.empty() ? "no libav concealment captured" : last_concealment_msg_.c_str());
    grayout_tiles_.clear(); last_concealment_msg_.clear();
    ++recovery_count_;
}

void Session::drain_pending_fir(int64_t now) {
    if (!decoder_) return;
    std::lock_guard<std::recursive_mutex> lk(policy_mu_);
    // Armed force-all escalation runs BEFORE the idle guard (a manual force-IDR makes Apple emit an IDR even while idle).
    if (dpb_forceall_pending_ && num_tiles() == 1) {
        bool required; { std::lock_guard<std::mutex> g(decoder_->gate_mutex()); required = !decoder_->gate().keyframe_required().empty(); }
        if (!required) dpb_forceall_pending_ = false;
        else if (now - last_dpb_error_ns_ >= DPB_FORCEALL_STALL_NS) { dpb_forceall_pending_ = false; LOG_WARN("session", "DPB break unrecovered %.1fs after per-tile FIR — escalating to force-IDR ALL tiles", double(now - last_dpb_error_ns_) / 1e9); request_fir(); }
    }
    // Apple-idle suppression: no packets for 1.5 s means the encoder rate-controlled to silence; a FIR can't help.
    const int64_t lp = assembler_ ? assembler_->last_video_pkt_ns : 0;
    if (lp > 0 && now - lp >= 1'500'000'000) return;
    std::set<int> tiles; { std::lock_guard<std::mutex> g(decoder_->gate_mutex()); tiles = decoder_->gate().consume_fir_request(now); }
    for (int ti : tiles) send_fir_for_tile(ti, now);
    if (!grayout_tiles_.empty() && now - grayout_window_ns_ >= GRAYOUT_WINDOW_NS) flush_grayout(now);
}

void Session::maybe_reanchor_d3d11va_avc(int64_t now) {
    if (!connected_ || cfg_.codec != VideoCodec::Avc || !decoder_ || !decoder_->hw_bound()) return;
    if (decoder_->reference_reset_pending()) return;
    if (decoder_->frames_since_keyframe() < AVC_D3D11_REANCHOR_FRAMES) return;
    if (now - last_avc_reanchor_ns_ < 3'000'000'000) return;
    last_avc_reanchor_ns_ = now;
    int sent = 0; for (int ti = 0; ti < num_tiles(); ++ti) if (send_fir_for_tile(ti, now, false)) ++sent;
    LOG_INFO("session", "AVC d3d11va re-anchor: %llu frames since intra (threshold=%llu) — requested fresh intra without decoder reset (%d/%d tiles)", (unsigned long long)decoder_->frames_since_keyframe(), (unsigned long long)AVC_D3D11_REANCHOR_FRAMES, sent, num_tiles());
}

void Session::check_stall(int64_t now) {
    if (!connected_ || last_publish_ns_ == 0 || !decoder_) return;
    std::lock_guard<std::recursive_mutex> lk(policy_mu_);
    const int64_t gap = now - last_publish_ns_;
    const uint64_t cur_loss = assembler_ ? assembler_->lost_pkts : 0;
    if (cur_loss > loss_at_prev_stall_check_) last_loss_growth_ns_ = now;
    loss_at_prev_stall_check_ = cur_loss;
    const bool recent_loss = now - last_loss_growth_ns_ < SATURATION_LOSS_FREE_WINDOW_NS;
    const int64_t lp = assembler_ ? assembler_->last_video_pkt_ns : 0;
    const bool pkts_flowing = lp > 0 && now - lp < 500'000'000;
    const bool apple_idle = lp > 0 && now - lp >= 1'500'000'000;
    // A: session-wide stall.
    if (gap > SATURATION_RESTART_GAP_NS && !recent_loss && pkts_flowing && now - last_decoder_restart_ns_ >= 3'000'000'000) {
        last_decoder_restart_ns_ = now;
        LOG_WARN("session", "decoder stuck %.1fs, packets flowing, no loss for %.0fs — restart decoder + FIR", double(gap) / 1e9, double(SATURATION_LOSS_FREE_WINDOW_NS) / 1e9);
        decoder_->restart(); request_fir(); return;
    }
    if (gap > 15'000'000'000 && now - last_decoder_restart_ns_ >= 8'000'000'000) {
        if (apple_idle) return;
        last_decoder_restart_ns_ = now;
        LOG_WARN("session", "decoder stuck %.1fs (long); restart decoder + FIR storm", double(gap) / 1e9);
        decoder_->restart(); request_fir(); return;
    }
    if (gap > 3'000'000'000 && now - last_stall_fir_ns_ >= 1'500'000'000) {
        if (apple_idle) return;
        last_stall_fir_ns_ = now;
        size_t required; { std::lock_guard<std::mutex> g(decoder_->gate_mutex()); required = decoder_->gate().keyframe_required().size(); }
        if (int(required) >= num_tiles()) LOG_WARN("session", "decoder stuck %.1fs (gate already recovering all tiles, deferring)", double(gap) / 1e9);
        else { LOG_WARN("session", "decoder stuck %.1fs; FIR storm", double(gap) / 1e9); request_fir(); }
    }
    // B: persistent per-tile concealment.
    constexpr int STUCK_TILE_ERRORS = 30;
    int worst = 0; std::vector<int> stuck;
    { std::lock_guard<std::mutex> g(decoder_->gate_mutex()); for (int i = 0; i < std::min(num_tiles(), decoder_->num_tiles()); ++i) { const int b = decoder_->gate().bad_streak(i); worst = std::max(worst, b); if (b >= STUCK_TILE_ERRORS) stuck.push_back(i); } }
    if (worst >= STUCK_TILE_ERRORS) {
        if (recent_loss) {
            if (now - last_stuck_tile_fir_ns_ >= 2'000'000'000) { last_stuck_tile_fir_ns_ = now; LOG_WARN("session", "tile stuck (worst bad_streak=%d, loss active); FIR storm, no flush", worst); request_fir(); }
        } else if (now - last_decoder_restart_ns_ >= 4'000'000'000) {
            last_decoder_restart_ns_ = now;
            LOG_WARN("session", "tile stuck (worst bad_streak=%d, no loss) — saturation wedge; restart decoder + FIR", worst);
            decoder_->restart(); request_fir();
        }
    }
}

void Session::send_ltr_ack(int tile) {
    if (!ltr_enabled_ || tile != 0 || !decoder_ || !srtcp_enc_ || !our_video_ssrc_) return;
    auto donl = decoder_->last_clean_donl(0);
    if (!donl || (ltr_last_acked_ && *ltr_last_acked_ == *donl)) return;
    ltr_last_acked_ = *donl;
    sock_video_.send_to(view(srtcp_enc_->protect(view(rtcp::build_rtcp_app_ltrp(*our_video_ssrc_, *donl)))), dest_host_, dest_video_port_);
    ++ltr_acks_sent_;
}

// ── libav log → concealment detection ───────────────────────────────────────
void Session::av_log_hook(void* avcl, int level, const char* fmt, va_list vl) {
    if (level > AV_LOG_WARNING) return;
    char buf[512];
    vsnprintf(buf, sizeof buf, fmt, vl);
    size_t n = std::strlen(buf); while (n && (buf[n - 1] == '\n' || buf[n - 1] == ' ')) buf[--n] = 0;
    if (Session* s = active_) s->on_libav_message(buf, level);
    (void)avcl;
}

void Session::on_libav_message(const char* raw, int level) {
    const std::string msg = raw, ml = lower(msg);
    const bool hw_failure = contains(ml, "failed to get the decoder guids") || contains(ml, "failed setup for format d3d11") || contains(ml, "hwaccel initialisation returned error");
    if (hw_failure && decoder_) { decoder_->mark_hwaccel_failed(raw); return; }
    if (!(contains(ml, "could not find ref") || contains(ml, "non-existing pps") || contains(ml, "concealing") || contains(ml, "no frame!") || contains(ml, "missing reference") ||
          contains(ml, "reference picture missing") || contains(ml, "number of reference frames") || contains(ml, "decode_slice_header error") || contains(ml, "skipping bitstream"))) {
        if (level <= AV_LOG_ERROR) LOG_INFO("libav", "%s", raw);
        return;
    }
    on_libav_concealment(msg, now_ns());
}

void Session::on_libav_concealment(const std::string& msg, int64_t now) {
    if (!decoder_) return;
    const std::string ml = lower(msg);
    std::lock_guard<std::recursive_mutex> lk(policy_mu_);
    if (contains(ml, "could not find ref") || contains(ml, "reference picture missing") || contains(ml, "missing reference picture") || (contains(ml, "number of reference frames") && contains(ml, "exceeds max"))) {
        last_concealment_msg_ = msg;
        if (cfg_.codec == VideoCodec::Avc) { decoder_->mark_reference_chain_broken(msg.c_str()); decoder_->mark_hwaccel_reference_failure(msg.c_str()); }
        if (now - last_dpb_error_ns_ > DPB_STORM_RESET_NS) dpb_fir_count_ = 0;
        last_dpb_error_ns_ = now;
        dpb_error_window_.push_back(now);
        while (!dpb_error_window_.empty() && dpb_error_window_.front() < now - DPB_ERR_WINDOW_NS) dpb_error_window_.pop_front();
        const bool in_grace = now - last_decoder_restart_ns_ < DPB_RESTART_GRACE_NS;
        if (!in_grace && int(dpb_error_window_.size()) >= DPB_ERR_THRESHOLD && now - last_dpb_fast_recovery_ns_ >= DPB_FAST_COOLDOWN_NS) {
            last_dpb_fast_recovery_ns_ = now;
            dpb_error_window_.clear();
            ++dpb_fir_count_;
            if (num_tiles() == 1) dpb_forceall_pending_ = true;
            if (dpb_fir_count_ >= DPB_FORCEALL_AFTER_FIRS) {
                LOG_WARN("session", "DPB break persisted through %d FIRs — escalating to force-IDR ALL tiles", dpb_fir_count_);
                dpb_fir_count_ = 0; dpb_forceall_pending_ = false;
                request_fir();
            } else {
                LOG_WARN("session", "DPB break: reference-missing event — FIR for fresh IDR (attempt %d/%d before force-all) [%s]", dpb_fir_count_, DPB_FORCEALL_AFTER_FIRS, msg.substr(0, 100).c_str());
            }
            std::vector<int> bad;
            { std::lock_guard<std::mutex> g(decoder_->gate_mutex()); for (int i = 0; i < std::min(num_tiles(), decoder_->num_tiles()); ++i) if (decoder_->gate().bad_streak(i) > 0) bad.push_back(i); }
            if (bad.empty() && num_tiles() == 1) bad.push_back(0);
            std::lock_guard<std::mutex> g(decoder_->gate_mutex());
            for (int ti : bad) decoder_->gate().mark_decode_error(ti, now, false);
        }
        return;
    }
    // Soft concealment: rate-limited, suppressed while frames flow.
    const int64_t lp = last_publish_ns_.load();
    if (lp > 0 && now - lp < 500'000'000) return;
    if (now - last_libav_fir_ns_ < 2'000'000'000) return;
    last_libav_fir_ns_ = now;
    LOG_WARN("session", "libav decoder error: %s", msg.substr(0, 120).c_str());
    std::lock_guard<std::mutex> g(decoder_->gate_mutex());
    decoder_->gate().mark_decode_error(0, now, false);
}

// ── telemetry ───────────────────────────────────────────────────────────────
SessionStats Session::stats_snapshot() {
    SessionStats s;
    const int64_t now = now_ns();
    const double el = snap_t_ns_ ? double(now - snap_t_ns_) / 1e9 : 0.0;
    const uint64_t rv = rx_pkts_video_, bv = rx_bytes_video_, ra = rx_pkts_audio_, rr = rx_pkts_rtcp_, rt = rx_pkts_tcp_, tx = tx_pkts_;
    if (el > 0) {
        s.video_pps = double(rv - snap_rx_video_) / el; s.video_mbps = double(bv - snap_bytes_video_) * 8 / el / 1e6;
        s.audio_pps = double(ra - snap_rx_audio_) / el; s.rtcp_pps = double(rr - snap_rx_rtcp_) / el; s.tcp_pps = double(rt - snap_rx_tcp_) / el; s.tx_pps = double(tx - snap_tx_) / el;
    }
    snap_rx_video_ = rv; snap_bytes_video_ = bv; snap_rx_audio_ = ra; snap_rx_rtcp_ = rr; snap_rx_tcp_ = rt; snap_tx_ = tx; snap_t_ns_ = now;
    s.rx_pkts_video = rv; s.rx_bytes_video = bv; s.srtp_auth_fail = srtp_auth_fail_;
    if (assembler_) { s.received = assembler_->received_pkts; s.lost = assembler_->lost_pkts; s.reorder_depth = assembler_->reorder_depth(); s.pending_groups = assembler_->pending_groups(); s.dropped_groups = assembler_->dropped_groups; }
    if (pool_) { s.packet_pool_in_use = pool_->in_use(); s.packet_pool_cap = pool_->capacity(); }
    if (rx_) s.pool_exhausted = uint32_t(rx_->pool_exhausted);
    s.reconstructed_frames = reconstructed_; s.incomplete_frames = incomplete_;
    s.ssrc_groups = video_dec_ ? int(video_dec_->ssrc_counts().size()) / std::max(1, num_tiles()) : 0;
    s.recovery_count = recovery_count_; s.ssrc_changes = ssrc_changes_; s.fir_sent = fir_sent_; s.nack_sent = nack_sent_;
    if (decoder_) { s.good = decoder_->good_counts(); s.clean = decoder_->clean_counts(); std::lock_guard<std::mutex> g(decoder_->gate_mutex()); s.bad_tiles = decoder_->gate().bad_tiles(); }
    return s;
}

std::string Session::telemetry_line() {
    SessionStats s = stats_snapshot();
    char buf[1024];
    std::string good, clean, bad;
    for (auto g : s.good) good += std::to_string(g) + ",";
    for (auto c : s.clean) clean += std::to_string(c) + ",";
    for (int b : s.bad_tiles) bad += std::to_string(b) + ",";
    auto& tel = decoder_->telemetry();
    auto sl = tel.submit_latency_ms.summary(), dl = tel.decode_latency_ms.summary(), ai = au_interval_ms_.summary();
    const int64_t lp = last_publish_ns_.load();
    snprintf(buf, sizeof buf,
             "video %.0f pps %.1f Mbps | pool %u/%u exh=%u | reorder=%zu pending=%zu | frames rec=%llu inc=%llu drop=%llu | loss %llu/%llu authfail=%llu | "
             "dec %s q=%d fed=%llu qdrop=%llu out=%llu stale=%llu err=%llu keys=%llu restarts=%llu submit p50/p95=%.2f/%.2f decode p50/p95/p99=%.2f/%.2f/%.2f ms | "
             "tiles good=[%s] clean=[%s] gray=[%s] | fir=%d nack=%d rec=%d ssrc_chg=%d groups=%d ltr=%llu | AU interval p50/p95/p99=%.1f/%.1f/%.1f ms | last_pub=%.1fs | tcp %.1f pps audio %.0f pps",
             s.video_pps, s.video_mbps, s.packet_pool_in_use, s.packet_pool_cap, s.pool_exhausted, s.reorder_depth, s.pending_groups,
             (unsigned long long)s.reconstructed_frames, (unsigned long long)s.incomplete_frames, (unsigned long long)s.dropped_groups,
             (unsigned long long)s.lost, (unsigned long long)s.received, (unsigned long long)s.srtp_auth_fail,
             decoder_name().c_str(), tel.queue_depth.load(), (unsigned long long)tel.nalus_fed.load(), (unsigned long long)tel.nalus_dropped_queue.load(), (unsigned long long)tel.frames_out.load(),
             (unsigned long long)tel.frames_replaced.load(), (unsigned long long)tel.decode_errors.load(), (unsigned long long)tel.keyframes.load(), (unsigned long long)tel.restarts.load(),
             sl.median, sl.p95, dl.median, dl.p95, dl.p99, good.c_str(), clean.c_str(), bad.c_str(), s.fir_sent, s.nack_sent, s.recovery_count, s.ssrc_changes, s.ssrc_groups,
             (unsigned long long)ltr_acks_sent_.load(), ai.median, ai.p95, ai.p99, lp ? double(now_ns() - lp) / 1e9 : -1.0, s.tcp_pps, s.audio_pps);
    return buf;
}

void Session::log_profile_snapshot() { if (decoder_) LOG_INFO("stats", "%s", telemetry_line().c_str()); }

}  // namespace scshr
