#include "protocol/rfb.h"
#include "crypto/crypto.h"

#include <algorithm>
#include <cmath>

namespace scshr::rfb {

namespace {
// 32-byte ViewerInfo command mask Apple's Screen Sharing.app sets (byte-diffed against a native handshake).
Bytes apple_viewer_command_mask() {
    Bytes m(32, 0);
    m[0] = 0xb0; m[2] = 0x0c; m[3] = 0x03; m[4] = 0x90; m[10] = 0x40;
    return m;
}
}  // namespace

const uint8_t APPLE_0X12_FOLLOWUP[12] = {0x12, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01};

std::optional<LayoutInfo> parse_apple_display_layout(ByteView p) {
    if (p.size() < 20) return std::nullopt;
    LayoutInfo li;
    li.scaled_w = be16(p.data() + 2); li.scaled_h = be16(p.data() + 4);
    li.backing_w = be16(p.data() + 6); li.backing_h = be16(p.data() + 8);
    const size_t count = be16(p.data() + 18);
    constexpr size_t ENTRY = 56;
    size_t off = 20;
    for (size_t i = 0; i < count; ++i) {
        if (off + ENTRY > p.size()) break;
        const uint32_t did = be32(p.data() + off + 16);
        const int py0 = be16(p.data() + off + 28), px0 = be16(p.data() + off + 30);
        const int py1 = be16(p.data() + off + 32), px1 = be16(p.data() + off + 34);
        if (px1 > px0 && py1 > py0) li.rects.push_back({did, px0, py0, px1 - px0, py1 - py0});
        off += ENTRY;
    }
    if (li.rects.empty()) return std::nullopt;
    return li;
}

Bytes build_set_encodings() {
    Writer w;
    w.u8(0x02).u8(0).u16(uint16_t(std::size(HP_ENCODINGS_FULL)));
    for (int32_t e : HP_ENCODINGS_FULL) w.i32(e);
    return w.out;
}

Bytes build_post_encryption_toggle() { return unhex("1200000200010000"); }

Bytes build_key_event(bool down, uint32_t keysym) {
    Writer w; w.u8(0x04).u8(down ? 1 : 0).u16(0).u32(keysym); return w.out;
}

Bytes build_pointer_event(uint8_t buttons, int x, int y) {
    Writer w; w.u8(0x05).u8(buttons).u16(uint16_t(std::clamp(x, 0, 0xFFFF))).u16(uint16_t(std::clamp(y, 0, 0xFFFF))); return w.out;
}

Bytes build_fbu_request(bool incremental, uint16_t x, uint16_t y, uint16_t w, uint16_t h) {
    Writer wr; wr.u8(0x03).u8(incremental ? 1 : 0).u16(x).u16(y).u16(w).u16(h); return wr.out;
}

Bytes build_viewer_info_only() {
    Writer w;
    w.u8(0x21).u8(0).u16(0x3E).u16(1).u32(2).u32(6).u32(1).u32(0).u32(15).u32(3).u32(0);
    w.raw(view(apple_viewer_command_mask()));
    return w.out;
}

Bytes build_viewer_info() {
    Bytes b = build_viewer_info_only();
    b.insert(b.end(), APPLE_0X12_FOLLOWUP, APPLE_0X12_FOLLOWUP + 12);
    return b;
}

Bytes build_virtual_display(int width, int height, double hidpi_scale, bool hdr, std::string_view display_name, int mode_count) {
    const size_t di_size = 0x9C + 28 * size_t(mode_count);
    Bytes di(di_size, 0);
    put_be16(&di[0], uint16_t(di_size));
    const size_t nlen = std::min<size_t>(display_name.size(), 119);
    std::memcpy(&di[2], display_name.data(), nlen);
    put_be32(&di[0x7A], 1);  // DYNAMIC_RESOLUTION
    put_be32(&di[0x7E], 4);  // virtual display
    { float f = 369.4545593261719f; uint32_t u; std::memcpy(&u, &f, 4); put_be32(&di[0x82], u); }
    { float f = 207.81817626953125f; uint32_t u; std::memcpy(&u, &f, 4); put_be32(&di[0x86], u); }
    put_be16(&di[0x92], 0); put_be16(&di[0x94], 0);
    put_be32(&di[0x96], 7);
    put_be16(&di[0x9A], uint16_t(mode_count));
    static const int NATIVE_MODES[5][4] = {{3840, 2160, 1920, 1080}, {2880, 1800, 1440, 900}, {3840, 2160, 1920, 1080}, {2880, 1620, 1440, 810}, {2624, 1696, 1312, 848}};
    const double sx = width ? width / 1920.0 : 1.0, sy = height ? height / 1080.0 : 1.0;
    const uint32_t mode_flags = hdr ? 1 : 0;
    for (int i = 0; i < mode_count; ++i) {
        const int* base = NATIVE_MODES[i % 5];
        const int msw = int(base[2] * sx + 0.5), msh = int(base[3] * sy + 0.5);
        const int mw = int(msw * hidpi_scale + 0.5), mh = int(msh * hidpi_scale + 0.5);
        uint8_t* m = &di[0x9C + 28 * size_t(i)];
        put_be32(m, uint32_t(mw)); put_be32(m + 4, uint32_t(mh)); put_be32(m + 8, uint32_t(msw)); put_be32(m + 12, uint32_t(msh));
        double hz = 60.0; uint64_t u; std::memcpy(&u, &hz, 8); put_be64(m + 16, u);
        put_be32(m + 24, mode_flags);
    }
    put_be32(&di[0x8A], 3840); put_be32(&di[0x8E], 2160);
    Writer w;
    w.u8(0x1D).u8(0).u16(uint16_t(8 + di_size)).u16(1).u16(1).u32(0);
    w.raw(view(di));
    return w.out;
}

Bytes build_auto_framebuffer_update(uint16_t width, uint16_t height) {
    Bytes b(16, 0);
    b[0] = 0x09; b[3] = 0x01; b[4] = b[5] = b[6] = b[7] = 0xFF;
    put_be16(&b[12], width); put_be16(&b[14], height);
    return b;
}

Bytes build_msg10_pointer(ByteView cbc_key16, uint8_t buttons, int x, int y) {
    uint8_t pt[16] = {};
    pt[10] = 0xff; pt[11] = buttons;
    put_be16(&pt[12], uint16_t(x & 0xffff)); put_be16(&pt[14], uint16_t(y & 0xffff));
    Bytes out(18);
    out[0] = 0x10; out[1] = 0;
    crypto::Aes128Ecb ecb(cbc_key16.subspan(0, 16));
    ecb.encrypt_block(pt, out.data() + 2);
    return out;
}

}  // namespace scshr::rfb
