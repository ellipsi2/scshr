// Packet-path invariants: RTP group assembly (wrap / reorder / dup / loss / repair window / marker timeout),
// quality-gate sticky semantics (ports of the reference's pytest cases), NAL reassembly edge cases.
#include "tests/test.h"

#include "media/nalu.h"
#include "media/packet_pool.h"
#include "media/quality_gate.h"
#include "media/rtp_assembler.h"
#include "media/session_audio.h"

#include <cmath>
#include <cstring>

using namespace scshr;

namespace {
struct Harness {
    PacketPool pool{256};
    RtpAssembler a;
    std::vector<std::pair<uint32_t, uint32_t>> flushed;   // (ts, first seq)
    std::vector<std::vector<uint16_t>> flushed_seqs;
    std::vector<bool> flushed_incomplete;
    std::vector<std::string> drops;
    explicit Harness(VideoCodec c = VideoCodec::Avc) : a(pool, c) {
        a.on_flush = [&](FlushedGroup& g) { flushed.emplace_back(g.ts, g.packets.front().seq); std::vector<uint16_t> s; for (auto& p : g.packets) s.push_back(p.seq); flushed_seqs.push_back(s); flushed_incomplete.push_back(g.incomplete); };
        a.on_drop = [&](const DroppedGroup& d) { drops.push_back(std::string(d.reason) + (d.had_marker ? "+m" : "")); };
    }
    void pkt(uint32_t ssrc, uint32_t ts, uint16_t seq, bool marker, int64_t now, const char* payload = "x") {
        const uint32_t slot = pool.acquire();
        PacketSlot& s = pool[slot];
        const size_t n = std::strlen(payload);
        std::memcpy(s.data, payload, n); s.len = uint32_t(n); s.payload_off = 0; s.payload_len = uint32_t(n); s.t_recv_ns = now;
        a.track_seq(ssrc, seq, now);
        a.queue_packet(ssrc, ts, seq, marker, slot, now);
    }
};
constexpr int64_t MS = 1'000'000;
}  // namespace

TEST(assembler_wrap_65535_to_0) {
    Harness h(VideoCodec::Hevc);
    h.pkt(1, 100, 65534, false, 0); h.pkt(1, 100, 65535, false, 0); h.pkt(1, 100, 0, false, 0); h.pkt(1, 100, 1, true, 0);
    CHECK_EQ(h.flushed.size(), size_t(1));
    CHECK((h.flushed_seqs[0] == std::vector<uint16_t>{65534, 65535, 0, 1}));
    CHECK(!h.flushed_incomplete[0]);
    CHECK_EQ(h.pool.in_use(), 0u);   // every slot released after flush
}

TEST(assembler_hevc_flushes_immediately_at_marker) {
    Harness h(VideoCodec::Hevc);
    h.pkt(1, 100, 10, false, 0); h.pkt(1, 100, 12, true, 0);   // gap: still flushes (HEVC has no repair wait) but marked incomplete
    CHECK_EQ(h.flushed.size(), size_t(1));
    CHECK(h.flushed_incomplete[0]);
}

TEST(assembler_avc_missing_first_packet_waits_for_repair) {
    Harness h;
    h.pkt(0x1000, 100, 10, false, 0); h.pkt(0x1000, 100, 12, true, 0);   // 11 missing
    CHECK_EQ(h.flushed.size(), size_t(0));
    h.pkt(0x1000, 200, 13, true, 5 * MS);                                 // later AU waits behind
    CHECK_EQ(h.flushed.size(), size_t(0));
    h.pkt(0x1000, 100, 11, false, 10 * MS);                               // retransmit completes it: flush in order
    CHECK_EQ(h.flushed.size(), size_t(2));
    CHECK_EQ(h.flushed[0].first, 100u); CHECK_EQ(h.flushed[1].first, 200u);
    CHECK_EQ(h.a.nack_pending()[0x1000].size(), size_t(0));   // late retransmit cancels its NACK
}

TEST(assembler_avc_repair_timeout_drops_and_unblocks) {
    Harness h;
    h.pkt(0x1000, 100, 10, false, 0); h.pkt(0x1000, 100, 12, true, 0);
    h.pkt(0x1000, 200, 13, true, 1 * MS);
    h.a.evict_stale(50 * MS);
    CHECK_EQ(h.flushed.size(), size_t(0));
    h.a.evict_stale(80 * MS);   // > 75 ms repair window
    CHECK_EQ(h.drops.size(), size_t(1));
    CHECK(h.drops[0].find("NACK/reorder timeout") == 0);
    CHECK_EQ(h.flushed.size(), size_t(1));   // AU 200 now flushes (anchored at the dropped AU's marker)
    CHECK_EQ(h.flushed[0].first, 200u);
    CHECK_EQ(h.pool.in_use(), 0u);
}

TEST(assembler_avc_missing_marker_blocks_until_ttl) {
    Harness h;
    h.pkt(0x1000, 100, 10, false, 0);          // never gets its marker
    h.pkt(0x1000, 200, 12, true, 1 * MS);      // exposes the gap; older group gets a repair deadline
    CHECK_EQ(h.flushed.size(), size_t(0));
    h.a.evict_stale(100 * MS);
    CHECK_EQ(h.drops.size(), size_t(1));
    // The dropped group had no marker → the transport anchor is forgotten, so the internally complete AU 200
    // flushes immediately (reference: `_last_group_marker_seq.pop` + `_flush_ready_groups`).
    CHECK_EQ(h.flushed.size(), size_t(1));
    CHECK_EQ(h.flushed[0].first, 200u);
    h.pkt(0x1000, 300, 13, true, 101 * MS);
    CHECK_EQ(h.flushed.size(), size_t(2));
}

TEST(assembler_duplicate_and_dedup_after_flush) {
    Harness h;
    h.pkt(0x1000, 100, 10, false, 0); h.pkt(0x1000, 100, 10, false, 0); h.pkt(0x1000, 100, 11, true, 0);
    CHECK_EQ(h.flushed.size(), size_t(1));
    CHECK_EQ(h.flushed_seqs[0].size(), size_t(2));
    h.pkt(0x1000, 100, 11, true, 1 * MS);      // late duplicate of an already-flushed group is dropped (dedup TTL)
    CHECK_EQ(h.flushed.size(), size_t(1));
    CHECK_EQ(h.pool.in_use(), 0u);
}

TEST(seq_tracking_loss_late_dup) {
    PacketPool pool(16); RtpAssembler a(pool, VideoCodec::Avc);
    a.track_seq(5, 10, 0);
    auto e = a.track_seq(5, 13, 0);
    CHECK_EQ(e.lost, 2); CHECK_EQ(a.nack_pending()[5].size(), size_t(2));
    e = a.track_seq(5, 12, 0); CHECK(e.late); CHECK_EQ(a.nack_pending()[5].size(), size_t(1));
    e = a.track_seq(5, 13, 0); CHECK(e.dup);
    e = a.track_seq(5, 100, 0); CHECK_EQ(e.lost, 31);   // capped at 32 candidates
    a.track_seq(6, 65534, 0); a.track_seq(6, 65535, 0);
    e = a.track_seq(6, 0, 0); CHECK_EQ(a.seq_state().at(6).roc, 1u); CHECK_EQ(e.lost, 0);
}

TEST(gate_sustained_loss_keeps_asking) {
    FrameQualityGate g(1);
    int64_t t = 1000 * MS; int fired = 0;
    for (int i = 0; i < 3000; ++i) { g.mark_decode_error(0, t); if (!g.consume_fir_request(t).empty()) ++fired; t += 20 * MS; }
    CHECK(g.keyframe_required().count(0));
    CHECK(fired > 5);
    CHECK(g.fir_attempts_tile0() >= g.re_arm_cap);
}

TEST(gate_recovers_and_resets_cadence) {
    FrameQualityGate g(1);
    int64_t t = 1000 * MS;
    for (int i = 0; i < g.re_arm_cap + 3; ++i) { g.mark_decode_error(0, t); g.consume_fir_request(t); t += g.re_arm_interval_ns + 10 * MS; }
    CHECK(g.fir_attempts_tile0() >= g.re_arm_cap);
    t += g.post_idr_grace_ns + 50 * MS;
    g.mark_idr_observed(0, t); t += 10 * MS; g.mark_clean(0, t);
    CHECK(!g.keyframe_required().count(0));
    CHECK_EQ(g.fir_attempts_tile0(), 0);
}

TEST(gate_post_idr_grace_and_suspicious_idr) {
    FrameQualityGate g(1);
    int64_t t = 1000 * MS;
    g.mark_decode_error(0, t);
    g.mark_idr_observed(0, t, true);            // suspicious: must not count as observed
    t += g.post_idr_grace_ns + 1 * MS;
    g.mark_clean(0, t + g.recovery_quiet_ns);
    CHECK(g.keyframe_required().count(0));      // still pending: no real IDR
    g.mark_idr_observed(0, t);
    g.mark_decode_error(0, t + 100 * MS);       // inside the post-IDR grace → suppressed (streak was reset by mark_clean)
    CHECK_EQ(g.bad_streak(0), 0);
    g.mark_clean(0, t + g.recovery_quiet_ns + 1 * MS);
    CHECK(!g.keyframe_required().count(0));
}

TEST(nalu_hevc_orphan_fu_dropped) {
    std::vector<Bytes> st; st.push_back(Bytes{0x62, 0x01, 0x80 | 19, 0, 8, 0x11, 0x22}); st.push_back(Bytes{0x62, 0x01, 19, 0, 8, 0x33});
    std::vector<ByteView> pays; for (auto& s : st) pays.push_back(view(s));
    Bytes out; std::vector<NalRange> r;
    reassemble_hevc(pays, out, r);
    CHECK_EQ(r.size(), size_t(0)); CHECK_EQ(out.size(), size_t(0));
}

TEST(nalu_h264_single_is_donless) {
    std::vector<Bytes> st; st.push_back(Bytes{0x41, 0x9a, 0x11});
    std::vector<ByteView> pays{view(st[0])};
    Bytes out; std::vector<NalRange> r;
    reassemble_h264(pays, out, r);
    CHECK_EQ(r.size(), size_t(1)); CHECK_EQ(r[0].len, size_t(3)); CHECK_EQ(out[r[0].off], 0x41);
}

TEST(packet_pool_bounded) {
    PacketPool p(4);
    uint32_t a = p.acquire(), b = p.acquire(), c = p.acquire(), d = p.acquire();
    CHECK_EQ(p.acquire(), UINT32_MAX);
    p.release(b); CHECK_EQ(p.acquire(), b);
    (void)a; (void)c; (void)d;
}

// ── session audio (PCM from the Mac's audio agent) ──────────────────────────
TEST(session_audio_packet_parse) {
    Bytes p{'S', 'C', 'A', 'U', 1, 2, 0x34, 0x12, 0x44, 0xAC, 0, 0, 2, 0, 0, 0,
            0x00, 0x40, 0x00, 0xC0, 0xFF, 0x7F, 0x00, 0x80};   // seq 0x1234, 44100 Hz, 2 frames
    auto r = parse_session_audio_packet(view(p));
    CHECK(r.has_value());
    if (r) {
        CHECK_EQ(r->seq, uint16_t(0x1234)); CHECK_EQ(r->sample_rate, 44100u); CHECK_EQ(r->pcm.size(), size_t(4));
        CHECK(std::fabs(r->pcm[0] - 0.5f) < 1e-6f); CHECK(std::fabs(r->pcm[1] + 0.5f) < 1e-6f);
        CHECK(r->pcm[2] > 0.999f); CHECK(std::fabs(r->pcm[3] + 1.0f) < 1e-6f);
    }
    Bytes trunc(p.begin(), p.end() - 1);
    CHECK(!parse_session_audio_packet(view(trunc)));
    Bytes v2 = p; v2[4] = 2;
    CHECK(!parse_session_audio_packet(view(v2)));
    CHECK(!parse_session_audio_packet(view(std::string_view("SCAU1 status no-agent alice"))));
}

TEST(stereo_resampler_continuous_across_packets) {
    StereoResampler rs;
    std::vector<float> a, b;
    for (int i = 0; i < 10; ++i) { a.push_back(float(i)); a.push_back(float(-i)); }
    for (int i = 10; i < 20; ++i) { b.push_back(float(i)); b.push_back(float(-i)); }
    auto o1 = rs.to_48k(a.data(), 10, 24000), o2 = rs.to_48k(b.data(), 10, 24000);
    std::vector<float> all(o1); all.insert(all.end(), o2.begin(), o2.end());
    CHECK_EQ(all.size() / 2, size_t(38));   // 20 in → 40 out minus the not-yet-known tail
    bool ok = true;
    for (size_t i = 0; i < all.size() / 2; ++i) if (std::fabs(all[i * 2] - 0.5f * float(i)) > 1e-4f || std::fabs(all[i * 2 + 1] + 0.5f * float(i)) > 1e-4f) ok = false;
    CHECK(ok);   // a 24 kHz ramp becomes an unbroken 48 kHz ramp across the packet boundary
    auto o3 = rs.to_48k(a.data(), 10, 48000);
    CHECK_EQ(o3.size(), a.size());   // 48 kHz passes through untouched
}
