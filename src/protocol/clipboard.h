#pragma once
// Apple RFB clipboard extension (msg 0x15 / 0x0b / 0x1f), port of proxy/protocol/clipboard.py.
#include "common/bytes.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace scshr::clip {

constexpr uint8_t MSG_AUTO_PASTEBOARD = 0x15, MSG_CLIPBOARD_REQUEST = 0x0b, MSG_CLIPBOARD_SEND = 0x1f;

struct Item { std::string primary_uti; Bytes primary_data; std::vector<std::pair<std::string, Bytes>> aliases; };

Bytes build_auto_pasteboard_msg(uint16_t mode = 1);
Bytes build_clipboard_request(bool promise_only = false);
Bytes build_clipboard_send(std::string_view utf8_text);

struct SendHeader { uint8_t promise; uint32_t reserved, uncompressed, compressed; };
std::optional<SendHeader> parse_send_header(ByteView data);
std::optional<Bytes> inflate_sync_flush(ByteView deflate_stream);    // Z_SYNC_FLUSH-framed zlib stream
Bytes deflate_sync_flush(ByteView raw);
std::vector<Item> parse_items(ByteView decompressed);
std::optional<std::string> text_from_items(const std::vector<Item>& items);

// Reassembles a 0x1f spanning several record-layer frames.
class Reassembler {
public:
    bool in_progress() const { return !buf_.empty(); }
    std::optional<Bytes> feed(ByteView msg);
private:
    Bytes buf_;
    size_t expected_ = 0;
};

}  // namespace scshr::clip
