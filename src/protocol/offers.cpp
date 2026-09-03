#include "protocol/offers.h"
#include "common/clock.h"
#include "common/log.h"
#include "crypto/crypto.h"
#include "protocol/bplist.h"

#include <miniz.h>

#include <cstdio>
#include <stdexcept>

namespace scshr::offers {

namespace {
constexpr const char* SCSHR_VERSION = "0.1.0";

void varint(Writer& w, uint64_t v) { while (v > 0x7F) { w.u8(uint8_t((v & 0x7F) | 0x80)); v >>= 7; } w.u8(uint8_t(v & 0x7F)); }
void field_varint(Writer& w, int fn, uint64_t v) { varint(w, uint64_t(fn << 3) | 0); varint(w, v); }
void field_bytes(Writer& w, int fn, ByteView v) { varint(w, uint64_t(fn << 3) | 2); varint(w, v.size()); w.raw(v); }
bool read_varint(ByteView d, size_t& pos, uint64_t& val) {
    val = 0; int shift = 0;
    while (pos < d.size()) {
        const uint8_t b = d[pos++];
        if (shift < 64) val |= uint64_t(b & 0x7F) << shift;
        shift += 7;
        if (!(b & 0x80)) return true;
        if (shift > 70) return false;
    }
    return false;
}

struct Tier { int f1; int f2; int f3; };  // f3 < 0 = absent
const Tier AUDIO_F9_TIERS[] = {
    {0, 40000000, 12288}, {0, 6000000, 131072}, {4074, 0, 16384}, {16, 4100, -1}, {0, 75000000, 524288},
    {0, 20000000, 98304}, {4, 6500, -1}, {0, 60000000, 262144}, {1, 299, -1}, {0, 100000000, 1048576},
};

Bytes apple_audio_f9() {
    Writer w;
    for (const Tier& t : AUDIO_F9_TIERS) {
        Writer body;
        body.u8(0x08); varint(body, uint64_t(t.f1)); body.u8(0x10); varint(body, uint64_t(t.f2));
        if (t.f3 >= 0) { body.u8(0x18); varint(body, uint64_t(t.f3)); }
        w.u8(0x4a); varint(w, body.size()); w.raw(view(body.out));
    }
    return w.out;
}

const std::string_view HEVC_PARAMS_LTR = "FLS;MS:-1;LF:-1;LTR;CABAC;POS:0;EOD:1;HTS:2;RR:3;AR:16/9,5/8;XR:16/9,5/8;";
const std::string_view HEVC_PARAMS_NO_LTR = "FLS;MS:-1;LF:-1;CABAC;POS:0;EOD:1;HTS:2;RR:3;AR:16/9,5/8;XR:16/9,5/8;";
const std::string_view AVC_PARAMS = "FLS;LF:-1;POS:5;EOD:1;HTS:2;RR:3;POSE:4;AR:16/9,5/8;XR:16/9,5/8;";

std::string uuid4_upper() {
    Bytes r = crypto::random_bytes(16);
    r[6] = uint8_t((r[6] & 0x0F) | 0x40); r[8] = uint8_t((r[8] & 0x3F) | 0x80);
    char buf[40];
    snprintf(buf, sizeof buf, "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]);
    return buf;
}

Bytes zlib_compress(ByteView in) {
    mz_ulong cap = mz_compressBound(mz_ulong(in.size()));
    Bytes out(cap);
    mz_compress2(out.data(), &cap, in.data(), mz_ulong(in.size()), MZ_DEFAULT_LEVEL);
    out.resize(cap);
    return out;
}

std::optional<Bytes> zlib_decompress(ByteView in) {
    if (in.empty()) return std::nullopt;
    mz_stream s{};
    if (mz_inflateInit(&s) != MZ_OK) return std::nullopt;
    Bytes out(std::max<size_t>(in.size() * 8, 8192));
    s.next_in = in.data(); s.avail_in = uint32_t(in.size());
    for (;;) {
        s.next_out = out.data() + s.total_out; s.avail_out = uint32_t(out.size() - s.total_out);
        const int rc = mz_inflate(&s, MZ_NO_FLUSH);
        if (rc == MZ_STREAM_END) break;
        if (rc == MZ_OK) { if (s.avail_out == 0) { out.resize(out.size() * 2); continue; } if (s.avail_in == 0) break; continue; }
        mz_inflateEnd(&s); return std::nullopt;
    }
    out.resize(s.total_out);
    mz_inflateEnd(&s);
    return out;
}
}  // namespace

int default_tiles_per_frame(Codec c) { return c == Codec::Avc ? 1 : 4; }
bool ltrp_enabled_for(Codec c, bool want) { return c != Codec::Avc && want; }

Bytes remote_endpoint_info() {
    Writer w;
    auto str = [&](uint8_t tag, std::string_view s) { w.u8(tag).u8(uint8_t(std::min<size_t>(s.size(), 127))).str(s.substr(0, 127)); };
    w.u8(0x08).u8(0x00).u8(0x10).u8(0x01);
    str(0x1A, "Windows-AMD64");
    str(0x22, "1.0.0");
    str(0x2A, "10");
    return w.out;
}

Bytes build_mediablob(int mode, uint32_t session_id, uint64_t timestamp, const OfferOptions& o) {
    Writer desc_field;
    if (mode == 7) {
        const bool ltrp_on = ltrp_enabled_for(o.codec, o.ltrp);
        const std::string_view hevc_params = ltrp_on ? HEVC_PARAMS_LTR : HEVC_PARAMS_NO_LTR;
        Writer res, res_alt;
        field_varint(res, 1, 1); field_varint(res, 2, 1); field_varint(res, 3, 50115); field_varint(res, 4, 0);
        field_varint(res_alt, 1, 1); field_varint(res_alt, 2, 2); field_varint(res_alt, 3, 50115); field_varint(res_alt, 4, 0);
        Writer hevc_bank, avc_bank;
        field_varint(hevc_bank, 1, 123);
        field_bytes(hevc_bank, 2, view(res.out)); field_bytes(hevc_bank, 2, view(res_alt.out));
        field_bytes(hevc_bank, 2, view(res.out)); field_bytes(hevc_bank, 2, view(res_alt.out));
        field_bytes(hevc_bank, 3, view(hevc_params)); field_varint(hevc_bank, 4, 1);
        field_varint(avc_bank, 1, 100);
        field_bytes(avc_bank, 2, view(res.out)); field_bytes(avc_bank, 2, view(res_alt.out));
        field_bytes(avc_bank, 3, view(AVC_PARAMS)); field_varint(avc_bank, 4, 14);
        // Server response is INVERTED relative to bank naming (live-verified):
        //   field1=123 bank → server sends H.264 4:2:0; field1=100 bank → HEVC 4:4:4.
        Writer banks;
        if (o.codec == Codec::Avc) field_bytes(banks, 3, view(hevc_bank.out));
        else if (o.codec == Codec::Hevc) field_bytes(banks, 3, view(avc_bank.out));
        else { field_bytes(banks, 3, view(hevc_bank.out)); field_bytes(banks, 3, view(avc_bank.out)); }
        Writer desc;
        field_varint(desc, 1, session_id); field_varint(desc, 2, ltrp_on ? 1 : 0);
        desc.raw(view(banks.out));
        field_varint(desc, 6, uint64_t(o.tiles_per_frame)); field_varint(desc, 7, ltrp_on ? 1 : 0);
        field_varint(desc, 8, 63); field_varint(desc, 9, 1); field_varint(desc, 12, 1);
        field_bytes(desc_field, 5, view(desc.out));
    } else if (mode == 8) {
        const uint64_t af4 = o.audio_enabled ? 24191 : 1000;
        Writer desc;
        field_varint(desc, 1, session_id); field_varint(desc, 2, 0); field_varint(desc, 3, 0);
        field_varint(desc, 4, af4); field_varint(desc, 5, 0); field_varint(desc, 6, 0);
        field_bytes(desc_field, 3, view(desc.out));
    } else {
        throw std::runtime_error("unsupported negotiation mode");
    }
    Writer w;
    field_varint(w, 1, 1); field_varint(w, 2, 1);
    w.raw(view(desc_field.out));
    const std::string ua = std::string("iShareScreen ") + SCSHR_VERSION;
    field_bytes(w, 6, view(std::string_view(ua)));
    field_varint(w, 8, 0);
    w.raw(view(apple_audio_f9()));
    field_varint(w, 13, timestamp);
    field_varint(w, 14, 2); field_varint(w, 16, 0); field_varint(w, 18, 1);
    return w.out;
}

std::pair<Bytes, Bytes> create_offers(const OfferOptions& o) {
    auto plist = [&](int mode) {
        uint32_t sid = mode == 7 ? o.session_id_video : o.session_id_audio;
        if (sid == 0) { Bytes r = crypto::random_bytes(4); sid = be32(r.data()); }
        const uint64_t ts = o.timestamp_ns ? o.timestamp_ns : uint64_t(wall_time_ns());
        std::string callid = mode == 7 ? o.callid_video : o.callid_audio;
        if (callid.empty()) callid = uuid4_upper();
        bplist::Dict d;
        d["avcMediaStreamOptionRemoteEndpointInfo"] = bplist::Value(remote_endpoint_info());
        d["avcMediaStreamNegotiatorMode"] = bplist::Value(int64_t(mode));
        d["avcMediaStreamNegotiatorMediaBlob"] = bplist::Value(zlib_compress(view(build_mediablob(mode, sid, ts, o))));
        d["avcMediaStreamOptionCallID"] = bplist::Value(callid);
        return bplist::dump(d);
    };
    return {plist(7), plist(8)};
}

std::optional<uint32_t> extract_offer_ssrc(ByteView offer_plist, bool is_video) {
    auto v = bplist::load(offer_plist);
    if (!v || !v->dict()) return std::nullopt;
    auto it = v->dict()->find("avcMediaStreamNegotiatorMediaBlob");
    if (it == v->dict()->end() || !it->second.data()) return std::nullopt;
    auto blob = zlib_decompress(view(*it->second.data()));
    if (!blob) return std::nullopt;
    const int target = is_video ? 5 : 3;
    ByteView d = view(*blob);
    size_t pos = 0;
    while (pos < d.size()) {
        uint64_t tag; if (!read_varint(d, pos, tag)) break;
        const int fn = int(tag >> 3), wt = int(tag & 7);
        if (wt == 0) { uint64_t x; if (!read_varint(d, pos, x)) break; }
        else if (wt == 2) {
            uint64_t len; if (!read_varint(d, pos, len) || pos + len > d.size()) break;
            if (fn == target) {
                ByteView inner = d.subspan(pos, size_t(len));
                size_t ip = 0; uint64_t itag;
                if (read_varint(inner, ip, itag) && (itag & 7) == 0 && (itag >> 3) == 1) { uint64_t ssrc; if (read_varint(inner, ip, ssrc)) return uint32_t(ssrc & 0xFFFFFFFF); }
            }
            pos += size_t(len);
        } else if (wt == 1) pos += 8; else if (wt == 5) pos += 4; else break;
    }
    return std::nullopt;
}

CanvasDims extract_canvas_dims(ByteView msg) {
    CanvasDims out;
    if (msg.empty() || msg[0] != 0x00) return out;
    size_t idx = 0;
    for (;;) {
        // find "bplist"
        size_t found = std::string::npos;
        for (size_t i = idx; i + 6 <= msg.size(); ++i) if (std::memcmp(msg.data() + i, "bplist", 6) == 0) { found = i; break; }
        if (found == std::string::npos) return out;
        idx = found;
        std::optional<bplist::Value> pl;
        // The plist is embedded without a length; the trailer sits at the true end. Try even end offsets like
        // the reference implementation (Python steps by 2 from idx+1).
        for (size_t end = idx + 1; end <= msg.size(); end += 2) {
            pl = bplist::load(msg.subspan(idx, end - idx));
            if (pl) break;
        }
        if (!pl || !pl->dict()) { idx += 6; continue; }
        auto it = pl->dict()->find("avcMediaStreamNegotiatorMediaBlob");
        if (it == pl->dict()->end() || !it->second.data() || it->second.data()->empty()) { idx += 6; continue; }
        auto dec = zlib_decompress(view(*it->second.data()));
        if (!dec) { idx += 6; continue; }
        ByteView d = view(*dec);
        uint32_t cw = 0, ch = 0, ct = 0;
        size_t pos = 0;
        while (pos < d.size()) {
            uint64_t tag; if (!read_varint(d, pos, tag)) break;
            const int fn = int(tag >> 3), wt = int(tag & 7);
            if (wt == 0) { uint64_t x; if (!read_varint(d, pos, x)) break; }
            else if (wt == 2) {
                uint64_t ln; if (!read_varint(d, pos, ln) || pos + ln > d.size()) break;
                if (fn == 5) {
                    ByteView sub = d.subspan(pos, size_t(ln));
                    size_t sp = 0;
                    while (sp < sub.size()) {
                        uint64_t st; if (!read_varint(sub, sp, st)) break;
                        const int sf = int(st >> 3), sw = int(st & 7);
                        if (sw == 0) { uint64_t v; if (!read_varint(sub, sp, v)) break; if (sf == 4) cw = uint32_t(v); else if (sf == 5) ch = uint32_t(v); else if (sf == 6) ct = uint32_t(v); else if (sf == 7) out.ltrp = int(v); }
                        else if (sw == 2) { uint64_t sl; if (!read_varint(sub, sp, sl) || sp + sl > sub.size()) break; sp += size_t(sl); }
                        else if (sw == 1) sp += 8; else if (sw == 5) sp += 4; else break;
                    }
                }
                pos += size_t(ln);
            } else if (wt == 1) pos += 8; else if (wt == 5) pos += 4; else break;
        }
        if (cw && ch) { out.w = cw; out.h = ch; out.tiles = ct; return out; }
        idx += 6;
    }
}

}  // namespace scshr::offers
