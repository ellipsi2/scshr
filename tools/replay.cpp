// scshr_replay: deterministic offline replay of a .scshr recording through the native packet core
// (SRTP → seq tracking → group assembly → NAL reassembly), printing one JSON line per protocol decision so
// tests/diff_replay.py can compare against the Python reference driven with the same recording.
//
//   scshr_replay --in file.scshr [--jsonl out.jsonl] [--decode sw|hw] [--bench]
//
// With --decode the reconstructed access units are also fed through the FFmpeg decoder (software, or D3D11VA
// on a headless device) and per-frame decode latency is reported.
#include "common/clock.h"
#include "common/log.h"
#include "crypto/srtp.h"
#include "media/burst.h"
#include "media/decoder.h"
#include "media/nalu.h"
#include "media/packet_pool.h"
#include "media/rtp_assembler.h"
#include "tools/pktfile.h"

#include <d3d11.h>
#include <wrl/client.h>

#include <cstdio>
#include <string>
#include <vector>

using namespace scshr;

namespace {
uint32_t crc32(ByteView d) {
    static uint32_t table[256]; static bool init = false;
    if (!init) { for (uint32_t i = 0; i < 256; ++i) { uint32_t c = i; for (int k = 0; k < 8; ++k) c = c & 1 ? 0xEDB88320u ^ (c >> 1) : c >> 1; table[i] = c; } init = true; }
    uint32_t c = 0xFFFFFFFFu; for (uint8_t b : d) c = table[(c ^ b) & 0xFF] ^ (c >> 8); return c ^ 0xFFFFFFFFu;
}
}  // namespace

int main(int argc, char** argv) {
    std::string in, jsonl, decode; bool bench = false;
    for (int i = 1; i < argc; ++i) {
        std::string k = argv[i]; auto v = [&] { return std::string(argv[++i]); };
        if (k == "--in") in = v(); else if (k == "--jsonl") jsonl = v(); else if (k == "--decode") decode = v(); else if (k == "--bench") bench = true; else if (k == "-v") log_set_level(LogLevel::Debug);
        else { std::fprintf(stderr, "unknown arg %s\n", argv[i]); return 2; }
    }
    pkt::Header h; std::vector<pkt::Record> recs;
    if (in.empty() || !pkt::read_file(in, h, recs)) { std::fprintf(stderr, "usage: scshr_replay --in file.scshr [--jsonl out] [--decode sw|hw]\n"); return 2; }
    if (!bench) log_set_level(LogLevel::Warn);
    const VideoCodec codec = h.codec == 1 ? VideoCodec::Hevc : VideoCodec::Avc;
    auto dec = SrtpDecryptor::from_blob(view(h.video_key));
    FILE* jf = jsonl.empty() ? nullptr : fopen(jsonl.c_str(), "wb");
    auto J = [&](const char* fmt, ...) { if (!jf) return; va_list ap; va_start(ap, fmt); vfprintf(jf, fmt, ap); va_end(ap); fputc('\n', jf); };

    // Burst phase exactly like the session: first 100 packets (+300 ms settle) form the burst.
    std::vector<std::pair<Bytes, int64_t>> raw;
    size_t idx = 0;
    const int64_t t_first = recs.empty() ? 0 : recs.front().t_ns;
    for (; idx < recs.size(); ++idx) {
        if (recs[idx].kind != 0) continue;
        raw.emplace_back(recs[idx].data, recs[idx].t_ns);
        if (raw.size() >= (codec == VideoCodec::Avc ? 400u : 100u) && recs[idx].t_ns - t_first > 0) { ++idx; break; }
    }
    // settle: include packets within 300 ms after the min_packets point
    const int64_t settle_end = raw.empty() ? 0 : raw.back().second + 300'000'000;
    for (; idx < recs.size() && recs[idx].t_ns <= settle_end; ++idx) if (recs[idx].kind == 0) raw.emplace_back(recs[idx].data, recs[idx].t_ns);
    InitialBurst burst;
    try { burst = gather_initial_burst(raw, *dec, codec, h.tiles, 0); }
    catch (const std::exception& e) { std::fprintf(stderr, "burst: %s\n", e.what()); J("{\"ev\":\"burst_starved\",\"reason\":\"%s\"}", e.what()); if (jf) fclose(jf); return 3; }
    {
        std::string tiles; for (auto& kv : burst.ssrc_to_tile) { char b[32]; snprintf(b, sizeof b, "\"%u\":%d,", kv.first, kv.second); tiles += b; }
        if (!tiles.empty()) tiles.pop_back();
        std::string tn; for (auto& kv : burst.tile_nalus) { char b[64]; snprintf(b, sizeof b, "\"%d\":%zu,", kv.first, kv.second.size()); tn += b; }
        if (!tn.empty()) tn.pop_back();
        J("{\"ev\":\"burst\",\"packets\":%zu,\"ssrc_to_tile\":{%s},\"vps\":%zu,\"sps\":%zu,\"pps\":%zu,\"idr_tiles\":%zu,\"tile_nalus\":{%s},\"pending\":%zu,\"codec\":\"%s\"}",
          raw.size(), tiles.c_str(), burst.vps.size(), burst.sps.size(), burst.all_pps.size(), burst.last_idr.size(), tn.c_str(), burst.pending.size(), burst.detected_codec.c_str());
    }

    // Optional decoder.
    std::unique_ptr<VideoDecoder> vd;
    Microsoft::WRL::ComPtr<ID3D11Device> dev; Microsoft::WRL::ComPtr<ID3D11DeviceContext> ctx; std::recursive_mutex gpu_lock;
    if (!decode.empty()) {
        DecoderConfig dc; dc.codec = codec; dc.num_tiles = int(burst.ssrc_to_tile.size()); dc.prefer_hw = decode == "hw";
        if (decode == "hw") {
            D3D_FEATURE_LEVEL fl;
            if (SUCCEEDED(D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, D3D11_CREATE_DEVICE_VIDEO_SUPPORT, nullptr, 0, D3D11_SDK_VERSION, &dev, &fl, &ctx))) {
                Microsoft::WRL::ComPtr<ID3D10Multithread> mt; if (SUCCEEDED(ctx.As(&mt))) mt->SetMultithreadProtected(TRUE);
                dc.gpu = GpuDevice{dev.Get(), ctx.Get(), &gpu_lock};
            } else std::fprintf(stderr, "D3D11CreateDevice failed; software decode\n");
        }
        vd = std::make_unique<VideoDecoder>(dc);
        vd->set_params(view(burst.vps), view(burst.sps), burst.all_pps);
        vd->start();
        vd->feed_burst(burst.tile_nalus);
    }

    PacketPool pool(8192);
    RtpAssembler asm_(pool, codec);
    uint64_t flushes = 0, drops = 0, nals_total = 0, incomplete = 0;
    Bytes au; std::vector<NalRange> ranges;
    asm_.on_flush = [&](FlushedGroup& g) {
        ++flushes;
        au.clear(); ranges.clear();
        if (codec == VideoCodec::Avc) reassemble_h264(g.payloads, au, ranges); else reassemble_hevc(g.payloads, au, ranges);
        std::string seqs; for (auto& p : g.packets) seqs += "\"" + std::to_string(p.seq) + (p.marker ? "m\"," : "\",");
        if (!seqs.empty()) seqs.pop_back();
        std::string nl;
        for (auto& r : ranges) { ByteView n(au.data() + r.off, r.len); char b[64]; snprintf(b, sizeof b, "[%d,%zu,%u],", codec == VideoCodec::Avc ? avc_nal_type(n[0]) : hevc_nal_type(n[0]), n.size(), crc32(n)); nl += b; }
        if (!nl.empty()) nl.pop_back();
        auto d = first_donl(g.payloads);
        J("{\"ev\":\"flush\",\"ssrc\":%u,\"ts\":%u,\"seqs\":[%s],\"incomplete\":%s,\"nals\":[%s],\"donl\":%d}", g.ssrc, g.ts, seqs.c_str(), g.incomplete ? "true" : "false", nl.c_str(), d ? int(*d) : -1);
        nals_total += ranges.size();
        if (g.incomplete) { ++incomplete; return; }
        auto tit = burst.ssrc_to_tile.find(g.ssrc);
        if (vd && tit != burst.ssrc_to_tile.end()) for (auto& r : ranges) vd->feed_nalu(ByteView(au.data() + r.off, r.len), tit->second, d, g.t_last_ns, g.t_last_ns);
    };
    asm_.on_drop = [&](const DroppedGroup& d) { ++drops; J("{\"ev\":\"drop\",\"ssrc\":%u,\"ts\":%u,\"had_marker\":%s,\"reason\":\"%s\",\"packets\":%zu}", d.ssrc, d.ts, d.had_marker ? "true" : "false", d.reason, d.packets); };
    // Leftover burst groups are re-queued at connect time (arrival = end of the burst), exactly like the session.
    const int64_t t_connect = raw.empty() ? 0 : raw.back().second;
    for (auto& p : burst.pending) {
        const uint32_t slot = pool.acquire(); PacketSlot& s = pool[slot];
        std::memcpy(s.data, p.payload.data(), p.payload.size()); s.len = uint32_t(p.payload.size()); s.payload_off = 0; s.payload_len = s.len; s.t_recv_ns = p.t_ns;
        asm_.queue_packet(p.ssrc, p.ts, p.seq, p.marker, slot, t_connect);
    }
    const int64_t t_bench0 = now_ns();
    uint64_t pkts = 0, auth_fail = 0; int64_t last_evict = 0;
    for (; idx < recs.size(); ++idx) {
        auto& r = recs[idx];
        if (r.kind != 0) continue;
        const int64_t now = r.t_ns;
        const uint32_t slot = pool.acquire();
        if (slot == UINT32_MAX) { J("{\"ev\":\"pool_exhausted\"}"); asm_.evict_stale(now); continue; }
        PacketSlot& s = pool[slot];
        std::memcpy(s.data, r.data.data(), r.data.size()); s.len = uint32_t(r.data.size()); s.t_recv_ns = now;
        RtpHeaderInfo hh;
        ++pkts;
        if (!dec->decrypt(s.data, s.len, hh)) { ++auth_fail; pool.release(slot); J("{\"ev\":\"auth_fail\",\"i\":%llu}", (unsigned long long)pkts); continue; }
        s.payload_off = uint32_t(hh.header_len); s.payload_len = uint32_t(hh.payload_len);
        SeqEvent se = asm_.track_seq(hh.ssrc, hh.seq, now);
        if (se.lost || se.late || se.dup) J("{\"ev\":\"seq\",\"ssrc\":%u,\"seq\":%u,\"lost\":%d,\"late\":%s,\"dup\":%s}", hh.ssrc, hh.seq, se.lost, se.late ? "true" : "false", se.dup ? "true" : "false");
        asm_.queue_packet(hh.ssrc, hh.timestamp, hh.seq, hh.marker, slot, now);
        if (now - last_evict >= 20'000'000) { last_evict = now; asm_.evict_stale(now); }
    }
    asm_.evict_stale(recs.empty() ? 0 : recs.back().t_ns + 5'000'000'000LL);
    const double bench_s = double(now_ns() - t_bench0) / 1e9;
    std::string nack;
    for (auto& kv : asm_.nack_pending()) { for (uint16_t s : kv.second) nack += std::to_string(s) + ","; }
    J("{\"ev\":\"summary\",\"packets\":%llu,\"auth_fail\":%llu,\"received\":%llu,\"lost\":%llu,\"flushes\":%llu,\"incomplete\":%llu,\"drops\":%llu,\"nals\":%llu}",
      (unsigned long long)pkts, (unsigned long long)auth_fail, (unsigned long long)asm_.received_pkts, (unsigned long long)asm_.lost_pkts, (unsigned long long)flushes, (unsigned long long)incomplete, (unsigned long long)drops, (unsigned long long)nals_total);
    if (jf) fclose(jf);
    std::fprintf(stderr, "replay: %llu packets (%llu auth fail), lost=%llu, flushes=%llu incomplete=%llu drops=%llu nals=%llu  [%.1f ms packet-core time = %.0f pkt/s offline]\n",
                 (unsigned long long)pkts, (unsigned long long)auth_fail, (unsigned long long)asm_.lost_pkts, (unsigned long long)flushes, (unsigned long long)incomplete, (unsigned long long)drops, (unsigned long long)nals_total, bench_s * 1e3, double(pkts) / bench_s);
    if (vd) {
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        auto& t = vd->telemetry();
        auto dl = t.decode_latency_ms.summary();
        auto good = vd->good_counts();
        uint64_t g = 0; for (auto x : good) g += x;
        std::fprintf(stderr, "decode: %s pixfmt=%s fed=%llu out=%llu (good=%llu) errors=%llu keyframes=%llu queue_drops=%llu decode p50/p95/p99=%.2f/%.2f/%.2f ms\n",
                     vd->hw_bound() ? "d3d11va" : "software", vd->pix_fmt_name().c_str(), (unsigned long long)t.nalus_fed.load(), (unsigned long long)t.frames_out.load(), (unsigned long long)g,
                     (unsigned long long)t.decode_errors.load(), (unsigned long long)t.keyframes.load(), (unsigned long long)t.nalus_dropped_queue.load(), dl.median, dl.p95, dl.p99);
        vd->close();
    }
    return 0;
}
