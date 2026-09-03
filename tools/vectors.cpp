// Differential-vector CLI: prints hex results of native protocol/crypto builders so tests/diff_vectors.py can
// compare them byte-for-byte against the Python reference implementation. Every subcommand reads hex args.
#include "common/bytes.h"
#include "crypto/crypto.h"
#include "crypto/srtp.h"
#include "media/avc_util.h"
#include "media/bitstream.h"
#include "media/hevc_rps.h"
#include "media/nalu.h"
#include "protocol/auth.h"
#include "protocol/bplist.h"
#include "protocol/clipboard.h"
#include "protocol/negotiation.h"
#include "protocol/offers.h"
#include "protocol/record_layer.h"
#include "protocol/rfb.h"
#include "protocol/rtcp.h"

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

using namespace scshr;

static void out(ByteView b) { std::cout << hex(b) << "\n"; }
static std::string arg(int argc, char** argv, int i) { return i < argc ? argv[i] : ""; }

int main(int argc, char** argv) {
    const std::string cmd = arg(argc, argv, 1);
    try {
        if (cmd == "srtp_kdf") { out(view(srtp_kdf(view(unhex(arg(argc, argv, 2))), view(unhex(arg(argc, argv, 3))), uint8_t(atoi(arg(argc, argv, 4).c_str())), size_t(atoi(arg(argc, argv, 5).c_str()))))); }
        else if (cmd == "srtp_decrypt") {
            // blob46 pkt_hex [pkt_hex...]: prints "ok <hdrlen> <payload_hex>" or "fail" per packet, stateful ROC
            auto dec = SrtpDecryptor::from_blob(view(unhex(arg(argc, argv, 2))));
            for (int i = 3; i < argc; ++i) {
                Bytes p = unhex(argv[i]); RtpHeaderInfo h;
                if (dec->decrypt(p.data(), p.size(), h)) std::cout << "ok " << h.header_len << " " << hex(ByteView(p.data() + h.header_len, h.payload_len)) << "\n"; else std::cout << "fail\n";
            }
        }
        else if (cmd == "srtp_encrypt") { auto enc = SrtpEncryptor::from_blob(view(unhex(arg(argc, argv, 2))), uint32_t(strtoul(arg(argc, argv, 3).c_str(), nullptr, 0))); for (int i = 4; i < argc; ++i) out(view(enc->encrypt(view(unhex(argv[i]))))); }
        else if (cmd == "srtcp_protect") { auto enc = SrtcpEncryptor::from_blob(view(unhex(arg(argc, argv, 2)))); for (int i = 3; i < argc; ++i) out(view(enc->protect(view(unhex(argv[i]))))); }
        else if (cmd == "srtcp_unprotect") { auto dec = SrtcpDecryptor::from_blob(view(unhex(arg(argc, argv, 2)))); for (int i = 3; i < argc; ++i) { auto r = dec->unprotect(view(unhex(argv[i]))); if (r) out(view(*r)); else std::cout << "fail\n"; } }
        else if (cmd == "record_encrypt") { RecordLayer rl(view(unhex(arg(argc, argv, 2))), view(unhex(arg(argc, argv, 3)))); for (int i = 4; i < argc; ++i) out(view(rl.encrypt_message(view(unhex(argv[i]))))); }
        else if (cmd == "record_decrypt") { RecordLayer rl(view(unhex(arg(argc, argv, 2))), view(unhex(arg(argc, argv, 3)))); for (int i = 4; i < argc; ++i) { std::vector<Bytes> msgs; size_t n = rl.decrypt_stream(view(unhex(argv[i])), msgs); std::cout << n; for (auto& m : msgs) std::cout << " " << hex(view(m)); std::cout << "\n"; } }
        else if (cmd == "record_cbc_key") { RecordLayer rl(view(unhex(arg(argc, argv, 2))), view(unhex(arg(argc, argv, 3)))); out(ByteView(rl.cbc_key())); }
        else if (cmd == "rfb_set_encodings") out(view(rfb::build_set_encodings()));
        else if (cmd == "rfb_viewer_info") out(view(rfb::build_viewer_info()));
        else if (cmd == "rfb_post_toggle") out(view(rfb::build_post_encryption_toggle()));
        else if (cmd == "rfb_key") out(view(rfb::build_key_event(atoi(arg(argc, argv, 2).c_str()) != 0, uint32_t(strtoul(arg(argc, argv, 3).c_str(), nullptr, 0)))));
        else if (cmd == "rfb_pointer") out(view(rfb::build_pointer_event(uint8_t(atoi(arg(argc, argv, 2).c_str())), atoi(arg(argc, argv, 3).c_str()), atoi(arg(argc, argv, 4).c_str()))));
        else if (cmd == "rfb_fbu") out(view(rfb::build_fbu_request(atoi(arg(argc, argv, 2).c_str()) != 0, uint16_t(atoi(arg(argc, argv, 3).c_str())), uint16_t(atoi(arg(argc, argv, 4).c_str())), uint16_t(atoi(arg(argc, argv, 5).c_str())), uint16_t(atoi(arg(argc, argv, 6).c_str())))));
        else if (cmd == "rfb_vdisplay") out(view(rfb::build_virtual_display(atoi(arg(argc, argv, 2).c_str()), atoi(arg(argc, argv, 3).c_str()), atof(arg(argc, argv, 4).c_str()), atoi(arg(argc, argv, 5).c_str()) != 0)));
        else if (cmd == "rfb_autofbu") out(view(rfb::build_auto_framebuffer_update(uint16_t(atoi(arg(argc, argv, 2).c_str())), uint16_t(atoi(arg(argc, argv, 3).c_str())))));
        else if (cmd == "rfb_msg10") out(view(rfb::build_msg10_pointer(view(unhex(arg(argc, argv, 2))), uint8_t(atoi(arg(argc, argv, 3).c_str())), atoi(arg(argc, argv, 4).c_str()), atoi(arg(argc, argv, 5).c_str()))));
        else if (cmd == "rfb_layout") { auto li = rfb::parse_apple_display_layout(view(unhex(arg(argc, argv, 2)))); if (!li) std::cout << "none\n"; else { std::cout << li->scaled_w << " " << li->scaled_h << " " << li->backing_w << " " << li->backing_h; for (auto& r : li->rects) std::cout << " " << r.display_id << "," << r.x << "," << r.y << "," << r.w << "," << r.h; std::cout << "\n"; } }
        else if (cmd == "rtcp_fir") out(view(rtcp::build_fir(uint32_t(strtoul(arg(argc, argv, 2).c_str(), nullptr, 0)), uint32_t(strtoul(arg(argc, argv, 3).c_str(), nullptr, 0)), uint8_t(atoi(arg(argc, argv, 4).c_str())))));
        else if (cmd == "rtcp_fir_legacy") out(view(rtcp::build_fir_legacy(uint32_t(strtoul(arg(argc, argv, 2).c_str(), nullptr, 0)))));
        else if (cmd == "rtcp_pli") out(view(rtcp::build_pli(uint32_t(strtoul(arg(argc, argv, 2).c_str(), nullptr, 0)), uint32_t(strtoul(arg(argc, argv, 3).c_str(), nullptr, 0)))));
        else if (cmd == "rtcp_nack") { std::set<uint16_t> s; for (int i = 4; i < argc; ++i) s.insert(uint16_t(atoi(argv[i]))); out(view(rtcp::build_nack(uint32_t(strtoul(arg(argc, argv, 2).c_str(), nullptr, 0)), uint32_t(strtoul(arg(argc, argv, 3).c_str(), nullptr, 0)), s))); }
        else if (cmd == "rtcp_ltrp") out(view(rtcp::build_rtcp_app_ltrp(uint32_t(strtoul(arg(argc, argv, 2).c_str(), nullptr, 0)), uint32_t(strtoul(arg(argc, argv, 3).c_str(), nullptr, 0)))));
        else if (cmd == "rtcp_rr_empty") out(view(rtcp::build_rr(uint32_t(strtoul(arg(argc, argv, 2).c_str(), nullptr, 0)))));
        else if (cmd == "rtcp_rr") { std::vector<uint32_t> src; std::map<uint32_t, rtcp::SsrcStat> st; for (int i = 3; i + 2 < argc; i += 3) { uint32_t s = uint32_t(strtoul(argv[i], nullptr, 0)); src.push_back(s); st[s] = {uint16_t(atoi(argv[i + 1])), uint32_t(atoi(argv[i + 2]))}; } out(view(rtcp::build_rr(uint32_t(strtoul(arg(argc, argv, 2).c_str(), nullptr, 0)), src, st))); }
        else if (cmd == "clip_send_inner") { Bytes m = clip::build_clipboard_send(arg(argc, argv, 2)); auto h = clip::parse_send_header(view(m)); auto inner = clip::inflate_sync_flush(ByteView(m.data() + 16, h->compressed)); std::cout << int(h->promise) << " " << h->uncompressed << " " << (inner ? hex(view(*inner)) : "fail") << "\n"; }
        else if (cmd == "clip_parse") { auto inner = clip::inflate_sync_flush(view(unhex(arg(argc, argv, 2)))); if (!inner) { std::cout << "fail\n"; return 0; } auto items = clip::parse_items(view(*inner)); auto t = clip::text_from_items(items); std::cout << items.size() << " " << (t ? hex(view(std::string_view(*t))) : "none") << "\n"; }
        else if (cmd == "clip_auto") out(view(clip::build_auto_pasteboard_msg(uint16_t(atoi(arg(argc, argv, 2).c_str())))));
        else if (cmd == "clip_req") out(view(clip::build_clipboard_request(atoi(arg(argc, argv, 2).c_str()) != 0)));
        else if (cmd == "mediablob") {
            // mode session_id timestamp codec(hevc|avc|both) tiles ltrp(0/1) audio(0/1)
            offers::OfferOptions o; const std::string c = arg(argc, argv, 5);
            o.codec = c == "avc" ? offers::Codec::Avc : c == "hevc" ? offers::Codec::Hevc : offers::Codec::Both;
            o.tiles_per_frame = atoi(arg(argc, argv, 6).c_str()); o.ltrp = atoi(arg(argc, argv, 7).c_str()) != 0; o.audio_enabled = atoi(arg(argc, argv, 8).c_str()) != 0;
            out(view(offers::build_mediablob(atoi(arg(argc, argv, 2).c_str()), uint32_t(strtoul(arg(argc, argv, 3).c_str(), nullptr, 10)), strtoull(arg(argc, argv, 4).c_str(), nullptr, 10), o)));
        }
        else if (cmd == "endpoint_info") out(view(offers::remote_endpoint_info()));
        else if (cmd == "offer_ssrc") { auto s = offers::extract_offer_ssrc(view(unhex(arg(argc, argv, 2))), arg(argc, argv, 3) == "video"); if (s) std::cout << *s << "\n"; else std::cout << "none\n"; }
        else if (cmd == "canvas_dims") { auto cd = offers::extract_canvas_dims(view(unhex(arg(argc, argv, 2)))); std::cout << cd.w << " " << cd.h << " " << cd.tiles << "\n"; }
        else if (cmd == "bplist_dump") {
            // key=type:value ... (type s|b|i); sorted by map
            bplist::Dict d;
            for (int i = 2; i < argc; ++i) { std::string a = argv[i]; auto eq = a.find('='); std::string k = a.substr(0, eq), tv = a.substr(eq + 1); char t = tv[0]; std::string v = tv.substr(2); if (t == 's') d[k] = bplist::Value(v); else if (t == 'b') d[k] = bplist::Value(unhex(v)); else d[k] = bplist::Value(int64_t(strtoll(v.c_str(), nullptr, 10))); }
            out(view(bplist::dump(d)));
        }
        else if (cmd == "bplist_load") { auto v = bplist::load(view(unhex(arg(argc, argv, 2)))); if (!v || !v->dict()) { std::cout << "fail\n"; return 0; } for (auto& kv : *v->dict()) { std::cout << kv.first << "="; if (auto s = kv.second.str()) std::cout << "s:" << *s; else if (auto b = kv.second.data()) std::cout << "b:" << hex(view(*b)); else if (auto i = kv.second.integer()) std::cout << "i:" << *i; std::cout << "\n"; } }
        else if (cmd == "msg1c") { negotiation::Keys k{unhex(arg(argc, argv, 4)), unhex(arg(argc, argv, 5)), unhex(arg(argc, argv, 6)), unhex(arg(argc, argv, 7))}; Bytes m = negotiation::build_0x1c(view(unhex(arg(argc, argv, 2))), view(unhex(arg(argc, argv, 3))), k, atoi(arg(argc, argv, 8).c_str()) != 0, atoi(arg(argc, argv, 9).c_str()) != 0); std::memset(m.data() + 0x14, 0, 16); out(view(m)); }
        else if (cmd == "srp") {
            // s2c1_hex password a_hex → A M1 K key16
            auto ch = auth::parse_srp_challenge(view(unhex(arg(argc, argv, 2))));
            Bytes a = unhex(arg(argc, argv, 4));
            auto p = auth::solve_srp(ch, arg(argc, argv, 3), view(a));
            auto key = crypto::sha256(view(p.K));
            std::cout << hex(view(p.A)) << " " << hex(view(p.M1)) << " " << hex(view(p.K)) << " " << hex(ByteView(key.data(), 16)) << "\n";
        }
        else if (cmd == "srp_x") out(view(auth::derive_x(view(unhex(arg(argc, argv, 2))), strtoull(arg(argc, argv, 3).c_str(), nullptr, 10), arg(argc, argv, 4))));
        else if (cmd == "avc_sps_patch") out(view(avc_patch_sps_dpb(view(unhex(arg(argc, argv, 2))))));
        else if (cmd == "avc_keyframe") std::cout << (avc_nal_is_keyframe(view(unhex(arg(argc, argv, 2)))) ? 1 : 0) << "\n";
        else if (cmd == "avc_config") { auto c = parse_avc_config(view(unhex(arg(argc, argv, 2)))); if (!c) std::cout << "none\n"; else std::cout << hex(view(c->sps)) << " " << hex(view(c->pps)) << "\n"; }
        else if (cmd == "reassemble_hevc" || cmd == "reassemble_h264") {
            std::vector<Bytes> store; std::vector<ByteView> pays;
            for (int i = 2; i < argc; ++i) store.push_back(unhex(argv[i]));
            for (auto& s : store) pays.push_back(view(s));
            Bytes o; std::vector<NalRange> r;
            if (cmd == "reassemble_hevc") reassemble_hevc(pays, o, r); else reassemble_h264(pays, o, r);
            for (auto& x : r) std::cout << hex(ByteView(o.data() + x.off, x.len)) << "\n";
            auto d = first_donl(pays); std::cout << "donl " << (d ? int(*d) : -1) << "\n";
        }
        else if (cmd == "hevc_sps") { auto st = hevc_parse_sps(view(remove_emulation_prevention(view(unhex(arg(argc, argv, 2)))))); std::cout << st.log2_max_pic_order_cnt_lsb << " " << st.pic_width_in_luma_samples << " " << st.pic_height_in_luma_samples << " " << st.num_short_term_ref_pic_sets << " " << int(st.long_term_ref_pics_present_flag) << " " << st.num_long_term_ref_pics_sps << " " << st.log2_min_luma_coding_block_size_minus3 << " " << st.log2_diff_max_min_luma_coding_block_size; for (auto& s : st.short_term_rps_sets) { std::cout << " ["; for (auto& d : s.deltas) std::cout << d.first << (d.second ? "u" : "n") << ","; std::cout << "]"; } std::cout << "\n"; }
        else if (cmd == "hevc_rps") {
            // sps_nal_hex slice_nal_hex... → per slice: poc_lsb/deltas/num_lt (parsed via tracker check output: missing set + checks)
            HevcRpsTracker tr; Bytes sps = unhex(arg(argc, argv, 2)); tr.feed_sps(ByteView(sps.data() + 2, sps.size() - 2));
            for (int i = 3; i < argc; ++i) { Bytes n = unhex(argv[i]); auto m = tr.check_slice(view(n)); tr.commit_decoded(); std::cout << m.size(); for (int x : m) std::cout << " " << x; std::cout << "\n"; }
            std::cout << "far " << tr.far_ref_events << " maxdist " << tr.max_ref_distance << " ltr " << tr.ltr_ref_events << "\n";
        }
        else { std::cerr << "unknown command\n"; return 2; }
    } catch (const std::exception& e) { std::cout << "exception: " << e.what() << "\n"; return 1; }
    return 0;
}
