#include "tests/test.h"

#include "protocol/bplist.h"
#include "protocol/clipboard.h"
#include "protocol/offers.h"
#include "protocol/rfb.h"

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
