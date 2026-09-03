// scshr_synth: turn an Annex-B H.264 / HEVC elementary stream into an Apple-format SRTP packet recording
// (.scshr) with optional impairments, for differential replay (Python vs native) and the real-time sender.
//
//   scshr_synth --in stream.h264 --codec avc --out clean.scshr [--fps 60] [--mtu 1200] [--ssrc 0x1000]
//               [--seq-start 65400] [--loss P] [--reorder P] [--dup P] [--ssrc-switch-at N] [--corrupt P]
//               [--restart-at N] [--seed S]
//
// AVC packetisation = what the reference documents (avc_nalu.py): DON-less FU-A / single NAL, SPS/PPS carried
// out-of-band in Apple's 0x92 avcC config packet. HEVC = RFC 7798 with DONL on every structure (nalu.py).
#include "common/bytes.h"
#include "crypto/crypto.h"
#include "crypto/srtp.h"
#include "media/bitstream.h"
#include "media/nalu.h"
#include "tools/pktfile.h"

#include <cstdio>
#include <random>
#include <string>
#include <vector>

using namespace scshr;

namespace {
std::vector<Bytes> split_annexb(const Bytes& d) {
    std::vector<Bytes> out; size_t i = 0, n = d.size();
    auto is_sc = [&](size_t p, size_t& len) { if (p + 3 <= n && d[p] == 0 && d[p + 1] == 0 && d[p + 2] == 1) { len = 3; return true; } if (p + 4 <= n && d[p] == 0 && d[p + 1] == 0 && d[p + 2] == 0 && d[p + 3] == 1) { len = 4; return true; } return false; };
    size_t sl;
    while (i < n && !is_sc(i, sl)) ++i;
    while (i < n) {
        i += sl; size_t j = i; size_t l2;
        while (j < n && !is_sc(j, l2)) ++j;
        size_t end = j; while (end > i && d[end - 1] == 0) --end;   // trailing zero bytes belong to the next start code
        if (end > i) out.emplace_back(d.begin() + ptrdiff_t(i), d.begin() + ptrdiff_t(end));
        if (j >= n) break; sl = l2; i = j;
    }
    return out;
}
}  // namespace

int main(int argc, char** argv) {
    std::string in, out, codec = "avc";
    double fps = 60, loss = 0, reorder = 0, dup = 0, corrupt = 0;
    int mtu = 1200; uint32_t ssrc = 0x1000; uint32_t seq_start = 0; int switch_at = -1, restart_at = -1; unsigned seed = 1;
    for (int i = 1; i < argc; ++i) {
        std::string k = argv[i]; auto v = [&] { return std::string(argv[++i]); };
        if (k == "--in") in = v(); else if (k == "--out") out = v(); else if (k == "--codec") codec = v(); else if (k == "--fps") fps = atof(v().c_str());
        else if (k == "--mtu") mtu = atoi(v().c_str()); else if (k == "--ssrc") ssrc = uint32_t(strtoul(v().c_str(), nullptr, 0)); else if (k == "--seq-start") seq_start = uint32_t(atoi(v().c_str()));
        else if (k == "--loss") loss = atof(v().c_str()); else if (k == "--reorder") reorder = atof(v().c_str()); else if (k == "--dup") dup = atof(v().c_str());
        else if (k == "--corrupt") corrupt = atof(v().c_str()); else if (k == "--ssrc-switch-at") switch_at = atoi(v().c_str()); else if (k == "--restart-at") restart_at = atoi(v().c_str());
        else if (k == "--seed") seed = unsigned(atoi(v().c_str()));
        else { std::fprintf(stderr, "unknown arg %s\n", argv[i]); return 2; }
    }
    if (in.empty() || out.empty()) { std::fprintf(stderr, "usage: scshr_synth --in stream.h264 --codec avc|hevc --out file.scshr [impairments]\n"); return 2; }
    FILE* f = fopen(in.c_str(), "rb"); if (!f) { std::perror("open"); return 1; }
    Bytes data; { uint8_t buf[65536]; size_t n; while ((n = fread(buf, 1, sizeof buf, f)) > 0) data.insert(data.end(), buf, buf + n); fclose(f); }
    const bool hevc = codec == "hevc";
    std::vector<Bytes> nals = split_annexb(data);
    if (nals.empty()) { std::fprintf(stderr, "no NAL units\n"); return 1; }

    // Group NALs into access units: parameter sets attach to the next VCL NAL; AVC one slice per AU (Apple sends one
    // slice per tile picture); a VCL NAL with first_mb/first_slice flag starts a new AU.
    struct Au { std::vector<Bytes> nals; bool has_vcl = false; };
    std::vector<Au> aus; Au cur;
    Bytes avc_sps, avc_pps;
    for (auto& n : nals) {
        const int t = hevc ? hevc_nal_type(n[0]) : avc_nal_type(n[0]);
        const bool vcl = hevc ? t < 32 : (t >= 1 && t <= 5);
        if (!hevc && t == AVC_NAL_SPS) { avc_sps = n; continue; }
        if (!hevc && t == AVC_NAL_PPS) { avc_pps = n; continue; }
        if (!hevc && (t == 6 || t == 9)) continue;   // SEI / AUD not sent by Apple
        if (hevc && (t == 35 || t == 39 || t == 40)) continue;
        bool first = false;
        if (vcl) {
            if (hevc) first = n.size() > 2 && (n[2] & 0x80);
            else { Bytes rb = remove_emulation_prevention(ByteView(n.data() + 1, std::min<size_t>(n.size() - 1, 16))); first = BitReader(view(rb)).read_ue() == 0; }   // first_mb_in_slice == 0
        }
        if (first && cur.has_vcl) { aus.push_back(std::move(cur)); cur = Au(); }
        cur.nals.push_back(n); if (vcl) cur.has_vcl = true;
    }
    if (cur.has_vcl) aus.push_back(std::move(cur));
    std::fprintf(stderr, "%zu NALs → %zu access units (%s)\n", nals.size(), aus.size(), hevc ? "hevc" : "avc");

    std::mt19937 rng(seed);
    std::uniform_real_distribution<double> uni(0, 100);
    pkt::Header hdr; hdr.codec = hevc ? 1 : 0; hdr.tiles = 1;
    hdr.video_key = crypto::random_bytes(46); hdr.audio_key = crypto::random_bytes(46);
    FILE* of = fopen(out.c_str(), "wb"); if (!of) { std::perror("open out"); return 1; }
    pkt::write_header(of, hdr);
    std::unique_ptr<SrtpEncryptor> enc = SrtpEncryptor::from_blob(view(hdr.video_key), ssrc);

    // We drive the RTP header ourselves (seq/ts/marker) and use the encryptor only for crypto → build packets manually.
    Bytes cipher_key = srtp_kdf(view(Bytes(hdr.video_key.begin(), hdr.video_key.begin() + 32)), view(Bytes(hdr.video_key.begin() + 32, hdr.video_key.end())), 0, 32);
    Bytes auth_key = srtp_kdf(view(Bytes(hdr.video_key.begin(), hdr.video_key.begin() + 32)), view(Bytes(hdr.video_key.begin() + 32, hdr.video_key.end())), 1, 20);
    Bytes salt = srtp_kdf(view(Bytes(hdr.video_key.begin(), hdr.video_key.begin() + 32)), view(Bytes(hdr.video_key.begin() + 32, hdr.video_key.end())), 2, 14);
    crypto::AesCtr aes(view(cipher_key)); crypto::HmacSha1 hmac(view(auth_key));
    uint32_t seq = seq_start & 0xFFFF, roc = 0; uint32_t ts = 0; uint32_t cur_ssrc = ssrc;
    int64_t t_ns = 0; const int64_t frame_ns = int64_t(1e9 / fps);
    uint32_t au_pkts = 0;
    std::vector<std::pair<int64_t, Bytes>> pending_reorder;
    size_t packets = 0;
    auto emit = [&](ByteView payload, bool marker) {
        Bytes p(12 + payload.size() + 10);
        p[0] = 0x80; p[1] = uint8_t(100 | (marker ? 0x80 : 0)); put_be16(&p[2], uint16_t(seq)); put_be32(&p[4], ts); put_be32(&p[8], cur_ssrc);
        uint8_t iv[16]; std::memcpy(iv, salt.data(), 14); iv[14] = iv[15] = 0;
        iv[4] ^= uint8_t(cur_ssrc >> 24); iv[5] ^= uint8_t(cur_ssrc >> 16); iv[6] ^= uint8_t(cur_ssrc >> 8); iv[7] ^= uint8_t(cur_ssrc);
        const uint64_t index = (uint64_t(roc) << 16) | seq;
        iv[8] ^= uint8_t(index >> 40); iv[9] ^= uint8_t(index >> 32); iv[10] ^= uint8_t(index >> 24); iv[11] ^= uint8_t(index >> 16); iv[12] ^= uint8_t(index >> 8); iv[13] ^= uint8_t(index);
        if (!payload.empty()) aes.crypt(iv, payload.data(), p.data() + 12, payload.size());
        uint8_t roc_be[4]; put_be32(roc_be, roc); uint8_t tag[20];
        hmac.tag({ByteView(p.data(), 12 + payload.size()), ByteView(roc_be, 4)}, tag);
        std::memcpy(p.data() + 12 + payload.size(), tag, 10);
        seq = (seq + 1) & 0xFFFF; if (seq == 0) ++roc;
        ++packets;
        if (uni(rng) < loss) return;                                  // lost on the wire
        if (uni(rng) < corrupt) p[12 + (p.size() > 20 ? 5 : 0)] ^= 0x55;   // damaged payload → auth failure
        const int64_t t = t_ns + std::min<int64_t>(int64_t(au_pkts++) * 20000, frame_ns / 2);   // monotone sub-ms spread inside a frame
        if (uni(rng) < reorder) { pending_reorder.emplace_back(t + 3'000'000, p); return; }   // delivered 3 ms late
        pkt::write_record(of, t, 0, view(p));
        if (uni(rng) < dup) pkt::write_record(of, t + 500'000, 0, view(p));
        for (auto it = pending_reorder.begin(); it != pending_reorder.end();) { if (it->first <= t) { pkt::write_record(of, it->first, 0, view(it->second)); it = pending_reorder.erase(it); } else ++it; }
    };
    auto send_avc_config = [&] {
        // Apple 0x92 config packet: junk header + avc1 sample entry + avcC (SPS/PPS).
        Writer w; w.u8(0x92).zeros(7).str("avc1").zeros(78).u32(0).str("avcC").u8(1).u8(avc_sps.size() > 1 ? avc_sps[1] : 0).u8(avc_sps.size() > 2 ? avc_sps[2] : 0).u8(avc_sps.size() > 3 ? avc_sps[3] : 0).u8(0xff).u8(0xe1)
            .u16(uint16_t(avc_sps.size())).raw(view(avc_sps)).u8(1).u16(uint16_t(avc_pps.size())).raw(view(avc_pps));
        emit(view(w.out), false);
    };
    if (!hevc) { if (avc_sps.empty() || avc_pps.empty()) { std::fprintf(stderr, "AVC stream lacks SPS/PPS\n"); return 1; } send_avc_config(); }
    uint16_t donl = 0;
    for (size_t ai = 0; ai < aus.size(); ++ai) {
        if (int(ai) == switch_at) { cur_ssrc += 4; seq = 0; roc = 0; std::fprintf(stderr, "SSRC switch at AU %zu → 0x%08x\n", ai, cur_ssrc); if (!hevc) send_avc_config(); }
        if (int(ai) == restart_at) { t_ns += 1'500'000'000; std::fprintf(stderr, "stream restart gap at AU %zu\n", ai); if (!hevc) send_avc_config(); }
        auto& au = aus[ai];
        for (size_t ni = 0; ni < au.nals.size(); ++ni) {
            const Bytes& n = au.nals[ni];
            const bool last = ni + 1 == au.nals.size();
            if (hevc) {
                const int t = hevc_nal_type(n[0]);
                if (t == HEVC_NAL_VPS || t == HEVC_NAL_SPS || t == HEVC_NAL_PPS) {
                    // Aggregation packet with a single DONL (Apple deviation): pack consecutive param sets together.
                    Writer ap; ap.u8(uint8_t((48 << 1) | (n[0] & 0x81))).u8(n[1]).u16(donl);
                    ap.u16(uint16_t(n.size())).raw(view(n));
                    emit(view(ap.out), false);
                    continue;
                }
                if (int(n.size()) + 4 <= mtu) { Writer s; s.u8(n[0]).u8(n[1]).u16(donl).raw(ByteView(n.data() + 2, n.size() - 2)); emit(view(s.out), last); }
                else {
                    size_t off = 2; const size_t chunk = size_t(mtu) - 5;
                    while (off < n.size()) {
                        const size_t len = std::min(chunk, n.size() - off);
                        const bool s = off == 2, e = off + len >= n.size();
                        Writer fu; fu.u8(uint8_t((49 << 1) | (n[0] & 0x81))).u8(n[1]).u8(uint8_t((s ? 0x80 : 0) | (e ? 0x40 : 0) | t)).u16(donl).raw(ByteView(n.data() + off, len));
                        emit(view(fu.out), last && e); off += len;
                    }
                }
            } else {
                const int t = avc_nal_type(n[0]);
                if (int(n.size()) <= mtu) emit(view(n), last);
                else {
                    size_t off = 1; const size_t chunk = size_t(mtu) - 2;
                    while (off < n.size()) {
                        const size_t len = std::min(chunk, n.size() - off);
                        const bool s = off == 1, e = off + len >= n.size();
                        Writer fu; fu.u8(uint8_t((n[0] & 0xE0) | 28)).u8(uint8_t((s ? 0x80 : 0) | (e ? 0x40 : 0) | t)).raw(ByteView(n.data() + off, len));
                        emit(view(fu.out), last && e); off += len;
                    }
                }
            }
        }
        ++donl; ts += uint32_t(90000.0 / fps); t_ns += frame_ns; au_pkts = 0;
    }
    for (auto& pr : pending_reorder) pkt::write_record(of, pr.first, 0, view(pr.second));
    fclose(of);
    std::fprintf(stderr, "wrote %s: %zu packets, %zu AUs, key=%s\n", out.c_str(), packets, aus.size(), hex(view(hdr.video_key)).c_str());
    return 0;
}
