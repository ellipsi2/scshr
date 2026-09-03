#include "protocol/negotiation.h"
#include "common/clock.h"
#include "common/log.h"
#include "crypto/crypto.h"
#include "protocol/auth.h"
#include "protocol/rfb.h"

#include <thread>

namespace scshr::negotiation {

namespace {
constexpr double POST_VIEWERINFO_SETTLE_S = 0.1, POST_TOGGLE_SETTLE_S = 0.2;
constexpr double DEGENERATE_RETRY_INTERVAL_S = 0.2;
constexpr int DEGENERATE_RETRY_LIMIT = 16;
constexpr double SS_POPUP_TIMEOUT_S = 60.0;
const uint8_t SS_MAGIC[4] = {0x00, 0x4a, 0x00, 0x01};

void sleep_s(double s) { std::this_thread::sleep_for(std::chrono::duration<double>(s)); }

void protocol_handshake(net::TcpSocket& sock) {
    sock.recv_exact(12);
    sock.send_all(view(rfb::PROTOCOL_VERSION));
    const uint8_t nt = sock.recv_exact(1)[0];
    sock.recv_exact(nt);
}

net::TcpSocket open_and_handshake(const Params& p) {
    net::TcpSocket s = net::TcpSocket::connect(p.host, p.port, 15.0);
    protocol_handshake(s);
    return s;
}

std::pair<net::TcpSocket, std::array<uint8_t, 16>> phase_auth(const Params& p) {
    auto primary = p.srp_first ? auth::do_srp_auth : auth::do_nonsrp_auth;
    auto fallback = p.srp_first ? auth::do_nonsrp_auth : auth::do_srp_auth;
    net::TcpSocket s = open_and_handshake(p);
    try {
        auto k = primary(s, p.username, p.password);
        return {std::move(s), k};
    } catch (const auth::AuthError& e) {
        LOG_WARN("negotiation", "%s auth failed (%s); falling back to %s", p.srp_first ? "SRP" : "non-SRP", e.what(), p.srp_first ? "non-SRP" : "SRP");
        s.close();
    }
    net::TcpSocket s2 = open_and_handshake(p);
    auto k = fallback(s2, p.username, p.password);
    return {std::move(s2), k};
}

std::pair<uint16_t, uint16_t> phase_client_init(net::TcpSocket& sock) {
    sock.send_all(view(std::string_view("\xc1")));
    Bytes head = sock.recv_exact(24);
    const uint32_t name_len = be32(head.data() + 20);
    if (name_len > 65536) throw std::runtime_error("ServerInit: bad name length");
    if (name_len) sock.recv_exact(name_len);
    const uint16_t w = be16(head.data()), h = be16(head.data() + 2);
    LOG_INFO("negotiation", "ServerInit: %ux%u", w, h);
    return {w, h};
}

Bytes build_ss_cmd0_body(const std::string& console_user) {
    Writer w; w.u16(2).u16(0).u16(0).u8(0).u8(0).str(console_user).u8(0).u8(0);
    Bytes b = w.out; b.resize(72, 0); return b;
}

Bytes build_ss_cmd2_body(const std::string& username, const std::string& password, const std::array<uint8_t, 16>& key) {
    crypto::Aes128Ecb aes{ByteView(key)};
    Bytes ub(username.begin(), username.end()); ub.resize(64, 0);
    Bytes pb(password.begin(), password.end()); pb.resize(64, 0);
    Bytes eu(64), ep(64);
    aes.encrypt(view(ub), eu.data()); aes.encrypt(view(pb), ep.data());
    Writer w; w.u16(2).u16(0).u16(0).u8(2).u8(0).zeros(64).raw(view(eu)).raw(view(ep));
    return w.out;
}

bool peek_ss_prompt(net::TcpSocket& sock) {
    Bytes p = sock.peek(4, 2.0);
    return p.size() == 4 && std::memcmp(p.data(), SS_MAGIC, 4) == 0;
}

std::string peek_ss_console_user(net::TcpSocket& sock) {
    Bytes p = sock.peek(76, 2.0);
    if (p.size() < 0xd || std::memcmp(p.data(), SS_MAGIC, 4) != 0) return "";
    std::string s; for (size_t i = 0xc; i < p.size() && p[i]; ++i) s.push_back(char(p[i]));
    return s;
}

void phase_session_select(net::TcpSocket& sock, bool alt_session, const Params& p, const std::array<uint8_t, 16>& key) {
    sock.set_timeout(0.5);
    Bytes peek;
    try { peek = sock.recv_exact(4); } catch (...) { sock.set_timeout(15); LOG_WARN("negotiation", "session-select: no prompt"); return; }
    sock.set_timeout(15);
    if (std::memcmp(peek.data(), SS_MAGIC, 4) != 0) { LOG_WARN("negotiation", "session-select: magic missing (got %s)", hex(view(peek)).c_str()); return; }
    Bytes rest = sock.recv_exact(72);
    Bytes ssi = peek; ssi.insert(ssi.end(), rest.begin(), rest.end());
    const uint32_t flags = be32(ssi.data() + 4);
    std::string console_user; for (size_t i = 0xc; i < ssi.size() && ssi[i]; ++i) console_user.push_back(char(ssi[i]));
    LOG_INFO("negotiation", "session-select: prompt flags=0x%x console_user=%s mode=%s", flags, console_user.c_str(), alt_session ? "alt_session" : "share_console");
    const int cmd = alt_session ? 2 : 0;
    Bytes body = alt_session ? build_ss_cmd2_body(p.username, p.password, key) : build_ss_cmd0_body(console_user);
    if (!((flags >> cmd) & 1)) LOG_WARN("negotiation", "session-select: cmd=%d not in flags mask 0x%x", cmd, flags);
    Writer w; w.u16(uint16_t(body.size())).raw(view(body));
    sock.send_all(view(w.out));
    LOG_INFO("negotiation", "session-select: sent cmd=%d — waiting up to %.0fs for ack", cmd, SS_POPUP_TIMEOUT_S);
    sock.set_timeout(SS_POPUP_TIMEOUT_S);
    bool to = false;
    Bytes ack = sock.recv_some(65536, &to);
    sock.set_timeout(15);
    if (to) throw std::runtime_error("session-select: timed out waiting for server ack (popup not clicked / creds rejected)");
    LOG_INFO("negotiation", "session-select: ack received (%zuB)", ack.size());
}

void phase_handshake_plaintext(net::TcpSocket& sock, const Params& p) {
    sock.send_all(view(rfb::build_viewer_info()));
    sleep_s(POST_VIEWERINFO_SETTLE_S);
    if (p.curtain) sock.send_all(view(rfb::build_virtual_display(p.advertise.width, p.advertise.height, p.advertise.hidpi_scale, p.hdr)));
    else LOG_INFO("negotiation", "curtain=off — skipping SetDisplayConfiguration; host's physical screen will mirror the stream");
    sock.send_all(view(rfb::build_set_encodings()));
}

std::unique_ptr<RecordLayer> read_until_enc1103(net::TcpSocket& sock, const std::array<uint8_t, 16>& key, double first_byte_timeout = 10.0) {
    sock.set_timeout(1.0);
    Bytes init;
    const double deadline = now_s() + first_byte_timeout;
    while (now_s() < deadline) {
        bool to = false;
        Bytes chunk;
        try { chunk = sock.recv_some(65536, &to); } catch (...) { break; }
        if (to) { if (!init.empty()) break; continue; }
        init.insert(init.end(), chunk.begin(), chunk.end());
    }
    sock.set_timeout(15);
    size_t pos = 0;
    std::unique_ptr<RecordLayer> cipher;
    while (pos < init.size()) {
        const uint8_t b = init[pos];
        if (b == 0x14 && pos + 8 <= init.size()) { pos += 8; continue; }
        if (b == 0x00 && pos + 4 <= init.size()) {
            const size_t n_rects = be16(&init[pos + 2]);
            size_t q = pos + 4;
            for (size_t i = 0; i < n_rects; ++i) {
                if (q + 12 > init.size()) break;
                const int32_t enc = int32_t(be32(&init[q + 8]));
                q += 12;
                if (enc == 1103 && q + 36 <= init.size()) { cipher = std::make_unique<RecordLayer>(ByteView(&init[q], 36), ByteView(key)); q += 36; }
                else if ((enc == 1010 || enc == 1011) && q + 2 <= init.size()) { const size_t sz = be16(&init[q]); q += 2 + sz; }
                else break;
            }
            pos = q;
            break;
        }
        break;
    }
    if (!cipher) { sock.close(); throw std::runtime_error("server did not advertise enc1103. Most often this is rate-limiting on the server — wait 10-15 seconds and retry."); }
    LOG_INFO("negotiation", "enc1103 OK");
    if (pos < init.size()) { std::vector<Bytes> tail; cipher->decrypt_stream(ByteView(init.data() + pos, init.size() - pos), tail); }
    return cipher;
}

void drain_through_cipher(net::TcpSocket& sock, RecordLayer& cipher, double timeout) {
    sock.set_timeout(timeout);
    Bytes pre;
    for (;;) {
        bool to = false; Bytes c;
        try { c = sock.recv_some(65536, &to); } catch (...) { break; }
        if (to) break;
        pre.insert(pre.end(), c.begin(), c.end());
    }
    sock.set_timeout(15);
    if (!pre.empty()) { std::vector<Bytes> tail; cipher.decrypt_stream(view(pre), tail); }
}

offers::CanvasDims read_video_answer(net::TcpSocket& sock, RecordLayer& cipher, std::vector<Bytes>& leftover) {
    sock.set_timeout(5.0);
    Bytes answer;
    for (;;) {
        bool to = false; Bytes c;
        try { c = sock.recv_some(65536, &to); } catch (...) { break; }
        if (to) break;
        answer.insert(answer.end(), c.begin(), c.end());
        if (answer.size() > 100) break;
    }
    sock.set_timeout(15);
    offers::CanvasDims seen;
    if (answer.empty()) return seen;
    std::vector<Bytes> msgs;
    cipher.decrypt_stream(view(answer), msgs);
    for (auto& m : msgs) {
        LOG_DEBUG("negotiation", "0x1c answer msg cmd=0x%02x len=%zu", m.empty() ? 0 : m[0], m.size());
        auto cd = offers::extract_canvas_dims(view(m));
        if (cd.w && cd.h && seen.w == 0) {
            LOG_INFO("negotiation", "encoder canvas: %ux%u (%u tiles) ltrp=%d", cd.w, cd.h, cd.tiles, cd.ltrp);
            seen = cd;
        } else leftover.push_back(m);
    }
    return seen;
}
}  // namespace

Keys random_keys() {
    return Keys{crypto::random_bytes(SRTP_KEY_BLOB_LEN), crypto::random_bytes(SRTP_KEY_BLOB_LEN), crypto::random_bytes(SRTP_KEY_BLOB_LEN), crypto::random_bytes(SRTP_KEY_BLOB_LEN)};
}

Bytes build_0x1c(ByteView audio_offer, ByteView video_offer, const Keys& keys, bool alt_session, bool legacy_cursor) {
    const size_t AS = audio_offer.size(), VS = video_offer.size(), MS = AS + VS + 0xD8;
    Bytes buf(MS + 4, 0);
    buf[0] = 0x1C;
    put_be16(&buf[2], uint16_t(MS));
    put_be16(&buf[4], 3);
    uint32_t config_flags = 3;
    if (alt_session) config_flags = (config_flags & ~2u) | 4u;
    else if (!legacy_cursor) config_flags |= 4;
    // BIG-endian on purpose (see negotiation.py: the agent tests the flag after an NDR byte-swap).
    put_be32(&buf[6], config_flags);
    put_be16(&buf[10], uint16_t(AS));
    put_be16(&buf[12], uint16_t(VS));
    Bytes uuid = crypto::random_bytes(16);
    uuid[6] = uint8_t((uuid[6] & 0x0F) | 0x40); uuid[8] = uint8_t((uuid[8] & 0x3F) | 0x80);
    std::memcpy(&buf[0x14], uuid.data(), 16);
    std::memcpy(&buf[0x24], keys.audio_key_v.data(), 46);
    std::memcpy(&buf[0x52], keys.audio_key_s.data(), 46);
    std::memcpy(&buf[0x80], audio_offer.data(), AS);
    const size_t vo = 0x80 + AS;
    std::memcpy(&buf[vo], keys.video_key_v.data(), 46);
    std::memcpy(&buf[vo + 0x2E], keys.video_key_s.data(), 46);
    std::memcpy(&buf[vo + 0x5C], video_offer.data(), VS);
    return buf;
}

void warmup_tcp(const std::string& host, uint16_t port, double dwell_s) {
    net::TcpSocket s = net::TcpSocket::connect(host, port, 10.0);
    s.set_timeout(5.0);
    protocol_handshake(s);
    s.close();
    if (dwell_s > 0) sleep_s(dwell_s);
}

Result connect_and_negotiate(const Params& pin) {
    Params p = pin;
    if (p.share_console && p.alt_session) throw std::runtime_error("share_console and alt_session are mutually exclusive");
    if (p.audio_offer.empty() || p.video_offer.empty()) { auto [v, a] = offers::create_offers({}); if (p.audio_offer.empty()) p.audio_offer = a; if (p.video_offer.empty()) p.video_offer = v; }

    auto [sock, key] = phase_auth(p);
    auto [sw, sh] = phase_client_init(sock);
    bool alt = p.alt_session;

    if (peek_ss_prompt(sock)) {
        if (!alt && !p.share_console && p.on_session_choice) {
            const std::string cu = peek_ss_console_user(sock);
            std::string choice = "share_console";
            try { choice = p.on_session_choice(cu); } catch (...) {}
            alt = (choice == "alt_session");
            LOG_INFO("negotiation", "session-select: %s chose %s", cu.c_str(), choice.c_str());
        }
        if (alt) {
            LOG_INFO("negotiation", "alt-session: closing conn1, opening conn2 for cmd=2");
            sock.close();
            auto r2 = phase_auth(p);
            sock = std::move(r2.first); key = r2.second;
            auto wh = phase_client_init(sock); sw = wh.first; sh = wh.second;
        }
        phase_session_select(sock, alt, p, key);
    }

    if (alt) {
        sock.send_all(view(rfb::build_viewer_info()));
        sleep_s(POST_VIEWERINFO_SETTLE_S);
        sock.send_all(view(rfb::build_virtual_display(p.advertise.width, p.advertise.height, p.advertise.hidpi_scale, p.hdr)));
        sock.send_all(view(rfb::build_set_encodings()));
    } else {
        phase_handshake_plaintext(sock, p);
    }

    auto cipher = read_until_enc1103(sock, key);
    sock.send_all(view(rfb::build_post_encryption_toggle()));
    sleep_s(POST_TOGGLE_SETTLE_S);
    drain_through_cipher(sock, *cipher, 0.5);

    // Encrypted preface + media offer.
    sock.send_all(view(cipher->encrypt_message(view(rfb::build_set_encodings()))));
    Keys keys = random_keys();
    Bytes msg_1c = build_0x1c(view(p.audio_offer), view(p.video_offer), keys, alt, p.legacy_cursor);
    sock.send_all(view(cipher->encrypt_message(view(msg_1c))));
    LOG_INFO("negotiation", "0x1c sent (encrypted)");
    if (!p.legacy_cursor) {
        sock.send_all(view(cipher->encrypt_message(view(rfb::build_fbu_request(false)))));
        LOG_INFO("negotiation", "msg 0x03 FBU request sent (cursor pseudo-encoding poll)");
    }
    std::vector<Bytes> leftover;
    offers::CanvasDims cd = read_video_answer(sock, *cipher, leftover);
    for (int attempt = 0; (!cd.w || !cd.h) && attempt < DEGENERATE_RETRY_LIMIT; ++attempt) {
        sleep_s(DEGENERATE_RETRY_INTERVAL_S);
        sock.send_all(view(cipher->encrypt_message(view(msg_1c))));
        LOG_INFO("negotiation", "0x1c re-query %d/%d (degenerate canvas)", attempt + 1, DEGENERATE_RETRY_LIMIT);
        cd = read_video_answer(sock, *cipher, leftover);
    }

    Result r;
    r.sock = std::move(sock);
    r.cipher = std::move(cipher);
    r.keys = keys;
    r.wrap_key = key;
    r.server_width = sw; r.server_height = sh;
    r.canvas_width = cd.w; r.canvas_height = cd.h; r.canvas_tiles = cd.tiles;
    r.video_decryptor = SrtpDecryptor::from_blob(view(keys.video_key_s));
    r.leftover_msgs = std::move(leftover);
    return r;
}

}  // namespace scshr::negotiation
