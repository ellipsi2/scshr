#pragma once
// RFB 3.889 + Apple HP client→server message builders and server→client parsers.
// Byte-compatible with proxy/protocol/rfb.py, apple.py, negotiation.py builders.
#include "common/bytes.h"

#include <optional>
#include <string>
#include <vector>

namespace scshr::rfb {

inline constexpr std::string_view PROTOCOL_VERSION = "RFB 003.889\n";

// Apple's non-standard pointer mask (bits 1/2 swapped vs RFC 6143).
constexpr uint8_t BTN_LEFT = 1 << 0, BTN_RIGHT = 1 << 1, BTN_MIDDLE = 1 << 2, BTN_SCROLL_UP = 1 << 3, BTN_SCROLL_DOWN = 1 << 4;

constexpr int32_t HP_ENCODINGS_FULL[] = {1010, 1011, 1002, 6, 16, 1104, 1100, -223, 1101, 1105, 1107, 1109, 1110};

struct DisplayRect { uint32_t display_id; int x, y, w, h; bool operator==(const DisplayRect&) const = default; };

struct LayoutInfo {
    uint16_t scaled_w = 0, scaled_h = 0, backing_w = 0, backing_h = 0;
    std::vector<DisplayRect> rects;  // per physical display, backing pixels
};
// Parse an AppleDisplayLayout (0x451) rect payload (after the u16 prefix). nullopt if unparseable.
std::optional<LayoutInfo> parse_apple_display_layout(ByteView payload);

Bytes build_set_encodings();
Bytes build_post_encryption_toggle();                       // 0x12 cmd=2
Bytes build_key_event(bool down, uint32_t keysym);
Bytes build_pointer_event(uint8_t buttons, int x, int y);
Bytes build_fbu_request(bool incremental, uint16_t x = 0, uint16_t y = 0, uint16_t w = 0xFFFF, uint16_t h = 0xFFFF);
Bytes build_viewer_info();                                  // 0x21 with Apple command mask + the 0x12 follow-up appended
Bytes build_viewer_info_only();
extern const uint8_t APPLE_0X12_FOLLOWUP[12];
Bytes build_virtual_display(int width, int height, double hidpi_scale = 2.0, bool hdr = false,
                            std::string_view display_name = "iShareScreen Virtual Display", int mode_count = 5);
Bytes build_auto_framebuffer_update(uint16_t w, uint16_t h);

// msg 0x10 HandleEncryptedEventMessage pointer wrapper (AES-128-ECB under the record-layer CBC key).
Bytes build_msg10_pointer(ByteView cbc_key16, uint8_t buttons, int x, int y);

}  // namespace scshr::rfb
