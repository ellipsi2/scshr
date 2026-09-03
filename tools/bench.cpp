// scshr_bench: packet-path throughput microbenchmarks (single thread, like the production packet thread).
//   srtp     : SRTP auth+decrypt of 1200-byte packets (the per-packet crypto cost)
//   pipeline : SRTP + seq tracking + group assembly + NAL reassembly of a synthetic 60 fps AVC-like stream
#include "common/clock.h"
#include "crypto/crypto.h"
#include "crypto/srtp.h"
#include "media/nalu.h"
#include "media/packet_pool.h"
#include "media/rtp_assembler.h"

#include <cstdio>
#include <string>
#include <vector>

using namespace scshr;

int main(int argc, char** argv) {
    int seconds = argc > 1 ? atoi(argv[1]) : 3;
    Bytes blob = crypto::random_bytes(46);
    auto enc = SrtpEncryptor::from_blob(view(blob), 0x1000);
    // Pre-build a ring of 1024 encrypted 1200-byte packets (FU-A-shaped payloads, marker every 20th) — seq continuous.
    std::vector<Bytes> pkts;
    Bytes payload(1200, 0x41);
    payload[0] = 0x7c; payload[1] = 0x01;   // FU-A middle fragment
    // 65536 packets = one full sequence cycle, so replaying the ring is a legitimate continuous stream (ROC advances).
    for (int i = 0; i < 65536; ++i) pkts.push_back(enc->encrypt(view(payload), 100, (i % 20) == 19));
    {
        auto dec = SrtpDecryptor::from_blob(view(blob));
        // Decryptor state must follow seq; decrypt in order repeatedly by re-encrypting? Simpler: measure decrypt on a
        // fresh decryptor per pass over the ring (ROC candidates handle the wrap; the auth check dominates anyway).
        const int64_t t0 = now_ns(); uint64_t n = 0, ok = 0; Bytes buf;
        while (now_ns() - t0 < int64_t(seconds) * 1000000000LL) {
            for (auto& p : pkts) { buf = p; RtpHeaderInfo h; if (dec->decrypt(buf.data(), buf.size(), h)) ++ok; ++n; }
        }
        const double s = double(now_ns() - t0) / 1e9;
        std::printf("srtp: %.0f pkt/s (%.1f MB/s payload) auth_ok=%.1f%%\n", double(n) / s, double(n) * 1200 / s / 1e6, 100.0 * double(ok) / double(n));
    }
    {
        PacketPool pool(4096);
        RtpAssembler asm_(pool, VideoCodec::Avc);
        uint64_t flushed = 0, nals = 0; size_t bytes = 0;
        Bytes au; std::vector<NalRange> r;
        asm_.on_flush = [&](FlushedGroup& g) { ++flushed; au.clear(); r.clear(); reassemble_h264(g.payloads, au, r); nals += r.size(); bytes += g.bytes; };
        const int64_t t0 = now_ns(); uint64_t n = 0; Bytes buf;
        uint32_t ts = 0; int in_frame = 0;
        auto d = SrtpDecryptor::from_blob(view(blob));
        while (now_ns() - t0 < int64_t(seconds) * 1000000000LL) {
            for (auto& p : pkts) {
                const uint32_t slot = pool.acquire();
                if (slot == UINT32_MAX) break;
                PacketSlot& s = pool[slot];
                std::memcpy(s.data, p.data(), p.size()); s.len = uint32_t(p.size()); s.t_recv_ns = now_ns();
                RtpHeaderInfo h;
                if (!d->decrypt(s.data, s.len, h)) { pool.release(slot); continue; }
                s.payload_off = uint32_t(h.header_len); s.payload_len = uint32_t(h.payload_len);
                // Synthesise FU-A start/end so groups reassemble: first of 20 = start, last = end+marker.
                uint8_t* pl = s.data + s.payload_off;
                pl[1] = uint8_t((in_frame == 0 ? 0x80 : 0) | (h.marker ? 0x40 : 0) | 1);
                asm_.track_seq(h.ssrc, h.seq, s.t_recv_ns);
                asm_.queue_packet(h.ssrc, ts, h.seq, h.marker, slot, s.t_recv_ns);
                if (h.marker) { ts += 1500; in_frame = 0; } else ++in_frame;
                ++n;
            }
            asm_.evict_stale(now_ns());
        }
        const double s = double(now_ns() - t0) / 1e9;
        std::printf("pipeline (srtp+seq+assemble+reassemble): %.0f pkt/s, %.0f AU/s, %.1f MB/s, pool_in_use=%u\n", double(n) / s, double(flushed) / s, double(bytes) / s / 1e6, pool.in_use());
    }
    return 0;
}
