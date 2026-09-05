#pragma once
// Session: the whole receiver pipeline for one Apple HP screen-share connection (port of proxy/session.py).
//
//   TCP control (record layer) ──────── tcp thread: cursor / layout / clipboard / misc-status
//   UDP 5901 video (IOCP) ───────────── packet thread: SRTP → RTP seq → group assembly → NAL → decoder
//   UDP 5900 audio+RTCP ─────────────── ctrl thread: SRTP audio → AAC-ELD → sink; SRTCP SR
//   tx thread (500 ms + wakeups) ────── heartbeat, RR/SR, NACK, FIR, LTR-ack pacing, stall watchdog, telemetry
//
// All queues are bounded; the decoder keeps one newest frame per tile; the render loop pulls.
#include "common/bytes.h"
#include "common/stats.h"
#include "crypto/srtp.h"
#include "media/burst.h"
#include "media/decoder.h"
#include "media/packet_pool.h"
#include "media/rtp_assembler.h"
#include "net/tcp.h"
#include "net/udp.h"
#include "protocol/clipboard.h"
#include "protocol/negotiation.h"
#include "protocol/record_layer.h"
#include "protocol/rfb.h"
#include "protocol/rtcp.h"

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace scshr {

struct SessionConfig {
    std::string host, username, password;
    uint16_t port = 5900;
    bool srp_first = true;
    negotiation::AdvertiseDims advertise;
    bool hdr = false, audio = true, curtain = true, share_console = false, alt_session = false, warmup_tcp = true;
    std::string hidpi = "auto";
    int quality_tier = 0;
    std::string udp_bind_host;
    uint16_t udp_ctrl_port = 0, udp_video_port = 0;   // 0 = port / port+1
    bool dynamic_resolution = false;
    VideoCodec codec = VideoCodec::Avc;
    offers::Codec offer_codec = offers::Codec::Avc;
    int tiles_per_frame = 1;
    bool ltrp = true;
    bool prefer_hw = true;
    std::string decoder_override;          // "" | "sw"
    bool clipboard = true;
    bool legacy_cursor = false;
    bool pertile_recovery = true;
    bool avc_sps_patch = true;
    std::string record_packets;            // write received media datagrams to this .scshr file (replay/diff tooling)
    std::function<std::string(const std::string&)> on_session_choice;
    double drop_pct = 0;                   // synthetic inbound loss (testing)
    GpuDevice gpu;                         // decoder device (nullptr → software)
    // Replay mode: no TCP handshake; media arrives on the bound UDP ports (from scshr_sender) under these keys.
    bool replay_mode = false;
    Bytes replay_video_key, replay_audio_key;
};

struct CursorShape { int w, h, hx, hy; Bytes rgba; };

struct SessionStats {
    // rates over the last snapshot interval
    double video_pps = 0, video_mbps = 0, audio_pps = 0, rtcp_pps = 0, tcp_pps = 0, tx_pps = 0;
    uint64_t rx_pkts_video = 0, rx_bytes_video = 0, srtp_auth_fail = 0, received = 0, lost = 0;
    uint32_t packet_pool_in_use = 0, packet_pool_cap = 0, pool_exhausted = 0;
    size_t reorder_depth = 0, pending_groups = 0;
    uint64_t reconstructed_frames = 0, incomplete_frames = 0, dropped_groups = 0;
    int ssrc_groups = 0, recovery_count = 0, ssrc_changes = 0, fir_sent = 0, nack_sent = 0;
    std::vector<uint64_t> good, clean;
    std::set<int> bad_tiles;
};

class Session {
public:
    explicit Session(const SessionConfig& cfg);
    ~Session();
    void connect();                       // full handshake + burst + threads (throws on failure)
    void close();
    // Aborts a connect() running on another thread (the viewer window was closed mid-handshake).
    // Without it the caller has to wait out the handshake's timeouts — up to minutes.
    void cancel_connect();
    bool is_connected() const { return connected_.load(); }

    VideoDecoder* decoder() { return decoder_.get(); }
    std::pair<int, int> canvas_dims() const;
    std::pair<int, int> scaled_dims() const;
    std::pair<int, int> server_dims() const { return {server_w_, server_h_}; }
    int num_tiles() const;
    std::vector<rfb::DisplayRect> display_rects() const;
    std::optional<rfb::DisplayRect> display_content_rect() const;
    const std::string& codec_name() const { return codec_name_; }
    std::string decoder_name() const;

    // Input (any thread; serialised on the record layer).
    void pointer_event(uint8_t buttons, int x, int y);
    void scroll_event(int x, int y, int dy);
    void key_event(bool down, uint32_t keysym);
    void cut_text(const std::string& utf8);
    void request_fir(std::optional<int> tile = std::nullopt);
    void send_dynamic_resolution(int width, int height, double hidpi_scale);

    // Callbacks (from session threads).
    std::function<void(std::shared_ptr<const CursorShape>)> on_cursor;    // nullptr = cache miss / OS default
    std::function<void(const std::string&)> on_clipboard_text;
    std::function<void(const float* interleaved_stereo, size_t frames)> on_audio;
    std::function<std::optional<std::string>()> read_local_clipboard;   // app-provided
    std::function<void(const std::string&)> write_local_clipboard;
    std::function<void()> on_layout_changed;

    SessionStats stats_snapshot();
    std::string telemetry_line();          // compact periodic statistics line
    uint64_t last_publish_ns() const { return uint64_t(last_publish_ns_.load()); }
    int64_t last_video_pkt_ns() const { return assembler_ ? assembler_->last_video_pkt_ns : 0; }

private:
    // connect
    void connect_internal();
    InitialBurst handshake_with_reconnect();
    InitialBurst negotiate_and_burst();
    void teardown();
    void spawn_threads();
    // threads
    void packet_thread();
    void ctrl_thread();
    void tcp_thread();
    void tx_thread();
    void clipboard_thread();
    void punch_thread(std::atomic<bool>& stop);
    // packet path
    void on_flushed_group(FlushedGroup& g, int64_t now);
    void on_dropped_group(const DroppedGroup& d, int64_t now);
    void note_unknown_ssrc(uint32_t ssrc, int64_t now);
    void maybe_reharvest_avc_config(const std::vector<ByteView>& payloads);
    void harvest_param_sets(const Bytes& au, const std::vector<NalRange>& ranges);
    // tcp path
    void handle_tcp_msg(ByteView msg);
    void handle_fbu(ByteView msg);
    int handle_cursor_rect(ByteView msg, size_t off, int hx, int hy, int w, int h);
    void notify_cursor(std::shared_ptr<const CursorShape> img);
    void handle_clipboard_send(ByteView full);
    void send_ctrl(ByteView plain);        // record-layer encrypt + send (locked)
    void send_cursor_rearm();
    void schedule_post_layout_arm();
    // tx
    void send_heartbeat();
    void send_rr_and_maybe_sr();
    void send_rr(const std::vector<uint32_t>& sources, const std::map<uint32_t, rtcp::SsrcStat>& stats);
    void drain_pending_fir(int64_t now);
    bool send_fir_for_tile(int tile, int64_t now, bool record_grayout = true);
    void drain_pending_nack();
    void maybe_reanchor_d3d11va_avc(int64_t now);
    void check_stall(int64_t now);
    void log_profile_snapshot();
    void send_ltr_ack(int tile);
    void flush_grayout(int64_t now);
    // libav log hook
    void on_libav_message(const char* msg, int level);
    void on_libav_concealment(const std::string& msg, int64_t now);
    static void av_log_hook(void* avcl, int level, const char* fmt, va_list vl);
    void write_record(int kind, const uint8_t* data, size_t len, int64_t t_ns);

    SessionConfig cfg_;
    std::string dest_host_;
    uint16_t ctrl_port_ = 0, video_port_ = 0;             // local bind ports
    uint16_t dest_ctrl_port_ = 0, dest_video_port_ = 0;   // where our RTCP / heartbeats go (== bind ports on Apple's symmetric layout)
    std::atomic<bool> connected_{false}, stop_{false}, cancel_{false};
    std::vector<std::thread> threads_;
    // transport
    std::unique_ptr<negotiation::Result> neg_;
    net::UdpSocket sock_ctrl_, sock_video_;
    std::unique_ptr<PacketPool> pool_;
    std::unique_ptr<net::IocpReceiver> rx_;
    std::unique_ptr<SrtpDecryptor> audio_dec_, replay_video_dec_;
    SrtpDecryptor* video_dec_ = nullptr;
    std::unique_ptr<SrtpEncryptor> audio_enc_;
    std::unique_ptr<SrtcpDecryptor> srtcp_dec_;
    std::unique_ptr<SrtcpEncryptor> srtcp_enc_;
    std::optional<uint32_t> our_video_ssrc_, our_audio_ssrc_;
    Bytes video_offer_, audio_offer_;
    // media
    std::unique_ptr<RtpAssembler> assembler_;
    std::unique_ptr<VideoDecoder> decoder_;
    std::map<uint32_t, int> ssrc_to_tile_;
    std::set<uint32_t> ssrc_blacklist_;
    int observed_tile_count_ = 0;
    std::string codec_name_;
    uint16_t server_w_ = 0, server_h_ = 0;
    std::atomic<int> runtime_canvas_w_{0}, runtime_canvas_h_{0}, runtime_scaled_w_{0}, runtime_scaled_h_{0};
    std::vector<rfb::DisplayRect> display_rects_;
    mutable std::mutex dims_mu_;
    std::atomic<bool> needs_post_layout_fir_{false}, needs_param_harvest_{false}, avc_needs_reconfig_{false};
    Bytes harvest_vps_, harvest_sps_; std::map<int, Bytes> harvest_pps_;
    Bytes avc_cfg_sps_;
    bool ltr_enabled_ = false;
    std::optional<uint16_t> ltr_last_acked_;
    std::atomic<uint64_t> ltr_acks_sent_{0};
    // recovery state (tx / packet threads; protected by policy_mu_)
    std::recursive_mutex policy_mu_;
    std::atomic<int64_t> last_publish_ns_{0};
    int64_t last_decoder_restart_ns_ = 0, last_dpb_fast_recovery_ns_ = 0, last_dpb_error_ns_ = 0, last_stall_fir_ns_ = 0, last_stuck_tile_fir_ns_ = 0, last_avc_reanchor_ns_ = 0, last_libav_fir_ns_ = 0, last_loss_growth_ns_ = 0, last_ssrc_adopt_ns_ = 0;
    uint64_t loss_at_prev_stall_check_ = 0;
    std::deque<int64_t> dpb_error_window_;
    int dpb_fir_count_ = 0;
    bool dpb_forceall_pending_ = false;
    std::map<int, int64_t> last_fir_per_tile_;
    std::set<int> grayout_tiles_; int64_t grayout_window_ns_ = 0; std::string last_concealment_msg_;
    std::atomic<int> recovery_count_{0}, ssrc_changes_{0}, fir_sent_{0}, nack_sent_{0};
    // tx sync
    std::mutex tx_mu_; std::condition_variable tx_cv_; bool tx_wake_ = false; int tx_tick_ = 0;
    std::map<uint32_t, rtcp::SrArrival> server_sr_;
    std::mutex sr_mu_;
    // stats
    std::atomic<uint64_t> rx_pkts_video_{0}, rx_bytes_video_{0}, rx_pkts_ctrl_{0}, rx_pkts_audio_{0}, rx_pkts_rtcp_{0}, rx_pkts_tcp_{0}, tx_pkts_{0}, srtp_auth_fail_{0}, reconstructed_{0}, incomplete_{0};
    uint64_t snap_rx_video_ = 0, snap_bytes_video_ = 0, snap_rx_audio_ = 0, snap_rx_rtcp_ = 0, snap_rx_tcp_ = 0, snap_tx_ = 0; int64_t snap_t_ns_ = 0;
    std::map<int, uint64_t> tile_bytes_;
    RollingStats au_interval_ms_{600}; int64_t last_au_ns_ = 0;
    std::map<int, uint64_t> rx_msg_type_counts_;
    // cursor / clipboard
    std::map<uint32_t, std::shared_ptr<const CursorShape>> cursor_cache_;
    std::vector<uint32_t> cursor_cache_order_;
    std::shared_ptr<const CursorShape> last_cursor_;
    std::atomic<uint64_t> cursor_msgs_{0}; std::atomic<int64_t> cursor_last_ns_{0};
    clip::Reassembler clip_reasm_;
    std::string last_received_clipboard_;
    std::mutex clip_mu_;
    int last_misc_cmd_ = -1;
    uint64_t fbu_video_rects_ = 0;
    std::vector<uint8_t> tcp_buf_;
    // audio
    struct AudioDecoder; std::unique_ptr<AudioDecoder> aac_;
    // recording
    FILE* rec_ = nullptr; std::mutex rec_mu_;
    static Session* active_;
};

}  // namespace scshr
