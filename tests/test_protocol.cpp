#include "tests/test.h"

#include "common/clock.h"
#include "net/tcp.h"
#include "protocol/bplist.h"
#include "protocol/clipboard.h"
#include "protocol/offers.h"
#include "protocol/rfb.h"

#include <winsock2.h>

#include <atomic>
#include <thread>

using namespace scshr;

TEST(bplist_roundtrip) {
    bplist::Dict d;
    d["a"] = bplist::Value(Bytes(300, 0xAB)); d["b"] = bplist::Value(int64_t(70000)); d["c"] = bplist::Value("héllo"); d["d"] = bplist::Value(int64_t(7));
    Bytes enc = bplist::dump(d);
    auto v = bplist::load(view(enc));
    CHECK(v && v->dict());
    CHECK_EQ(v->dict()->at("a").data()->size(), size_t(300));
    CHECK_EQ(*v->dict()->at("b").integer(), int64_t(70000));
    CHECK_EQ(*v->dict()->at("c").str(), std::string("héllo"));
    // Malformed inputs must not crash.
    for (size_t cut = 0; cut < enc.size(); cut += 7) { Bytes t(enc.begin(), enc.begin() + ptrdiff_t(cut)); (void)bplist::load(view(t)); }
    Bytes junk = enc; junk[enc.size() - 1] ^= 0xFF; (void)bplist::load(view(junk));
}

TEST(offers_ssrc_roundtrip) {
    offers::OfferOptions o; o.codec = offers::Codec::Avc; o.tiles_per_frame = 1; o.session_id_video = 12345; o.session_id_audio = 999;
    auto [vo, ao] = offers::create_offers(o);
    CHECK_EQ(offers::extract_offer_ssrc(view(vo), true).value_or(0), 12345u);
    CHECK_EQ(offers::extract_offer_ssrc(view(ao), false).value_or(0), 999u);
}

TEST(clipboard_roundtrip_and_reassembly) {
    Bytes m = clip::build_clipboard_send("copy ✓ me\nline2");
    clip::Reassembler r;
    auto part1 = ByteView(m.data(), 20), part2 = ByteView(m.data() + 20, m.size() - 20);
    CHECK(!r.feed(part1)); CHECK(r.in_progress());
    auto full = r.feed(part2);
    CHECK(full && full->size() == m.size());
    auto h = clip::parse_send_header(view(*full));
    auto inner = clip::inflate_sync_flush(ByteView(full->data() + 16, h->compressed));
    auto items = clip::parse_items(view(*inner));
    CHECK_EQ(*clip::text_from_items(items), std::string("copy ✓ me\nline2"));
    // Truncated inner archive must not read out of bounds.
    Bytes trunc(inner->begin(), inner->begin() + 9);
    (void)clip::parse_items(view(trunc));
}

TEST(layout_parse_bounds) {
    Bytes p(20, 0); put_be16(&p[18], 5);   // claims 5 displays with no bodies
    CHECK(!rfb::parse_apple_display_layout(view(p)));
    Bytes q(20 + 56, 0); put_be16(&q[2], 1920); put_be16(&q[4], 1080); put_be16(&q[6], 3840); put_be16(&q[8], 2160); put_be16(&q[18], 1);
    put_be32(&q[20 + 16], 7); put_be16(&q[20 + 32], 2160); put_be16(&q[20 + 34], 3840);
    auto li = rfb::parse_apple_display_layout(view(q));
    CHECK(li && li->rects.size() == 1 && li->rects[0].w == 3840 && li->backing_h == 2160);
}

// The 0x451 geometry header sits INSIDE the payload (after the u16 prefix): ver | scaled_w/h | backing_w/h.
// Regression: the session used to read it 2 bytes early (version → scaled_w, …, backing_w → backing_h), which
// set the runtime canvas to (scaled_h, backing_w) and cropped the picture to a stretched left slice.
TEST(layout_geometry_header) {
    Bytes p(10, 0); put_be16(&p[0], 7); put_be16(&p[2], 1632); put_be16(&p[4], 918); put_be16(&p[6], 3264); put_be16(&p[8], 1836);
    auto g = rfb::parse_apple_display_geometry(view(p));
    CHECK(g && g->scaled_w == 1632 && g->scaled_h == 918 && g->backing_w == 3264 && g->backing_h == 1836);
    CHECK(!rfb::parse_apple_display_geometry(ByteView(p.data(), 9)));
    // Header-only layouts (no display rects) still carry usable geometry, exactly like session.py.
    CHECK(!rfb::parse_apple_display_layout(view(p)) && rfb::parse_apple_display_geometry(view(p)));
}

// The handshake's reads run with timeouts up to a minute (the Mac's "Allow" popup), and the viewer's
// close path waits for the connecting thread. Regression: a set cancel hook must cut a read short
// instead of letting the process outlive its window for the rest of the timeout.
TEST(tcp_read_aborts_on_cancel) {
    net::winsock_init();
    SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_port = 0; sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(::bind(srv, reinterpret_cast<sockaddr*>(&sa), sizeof sa) == 0);
    int len = sizeof sa; getsockname(srv, reinterpret_cast<sockaddr*>(&sa), &len);
    CHECK(listen(srv, 1) == 0);

    std::atomic<bool> cancel{false};
    net::TcpSocket s = net::TcpSocket::connect("127.0.0.1", ntohs(sa.sin_port), 2.0, [&] { return cancel.load(); });
    s.set_timeout(60.0);                       // the server never answers: only the cancel can end this
    std::thread waker([&] { std::this_thread::sleep_for(std::chrono::milliseconds(150)); cancel = true; });
    const int64_t t0 = now_ns();
    bool threw = false;
    try { s.recv_exact(1); } catch (const std::exception&) { threw = true; }
    const int64_t waited_ms = (now_ns() - t0) / 1'000'000;
    waker.join();
    closesocket(srv);
    CHECK(threw);
    CHECK(waited_ms < 2000);
}
