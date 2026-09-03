#include "protocol/clipboard.h"

#include <miniz.h>

namespace scshr::clip {

Bytes build_auto_pasteboard_msg(uint16_t mode) { Writer w; w.u8(0x15).u8(0).u16(mode).u32(0); return w.out; }
Bytes build_clipboard_request(bool promise_only) { Bytes b(8, 0); b[0] = 0x0b; b[1] = promise_only ? 1 : 0; return b; }

Bytes deflate_sync_flush(ByteView raw) {
    mz_stream s{};
    mz_deflateInit(&s, MZ_DEFAULT_COMPRESSION);
    Bytes out(mz_deflateBound(&s, mz_ulong(raw.size())) + 64);
    s.next_in = raw.data(); s.avail_in = uint32_t(raw.size());
    s.next_out = out.data(); s.avail_out = uint32_t(out.size());
    mz_deflate(&s, MZ_SYNC_FLUSH);
    out.resize(s.total_out);
    mz_deflateEnd(&s);
    return out;
}

std::optional<Bytes> inflate_sync_flush(ByteView in) {
    mz_stream s{};
    if (mz_inflateInit(&s) != MZ_OK) return std::nullopt;
    Bytes out;
    out.resize(std::max<size_t>(in.size() * 4, 4096));
    s.next_in = in.data(); s.avail_in = uint32_t(in.size());
    size_t produced = 0;
    for (;;) {
        s.next_out = out.data() + produced; s.avail_out = uint32_t(out.size() - produced);
        const int rc = mz_inflate(&s, MZ_SYNC_FLUSH);
        produced = s.total_out;
        if (rc == MZ_STREAM_END) break;
        if (rc == MZ_OK) {
            if (s.avail_in == 0 && s.avail_out != 0) break;   // consumed all input (sync-flushed stream)
            if (s.avail_out == 0) { out.resize(out.size() * 2); continue; }
            continue;
        }
        if (rc == MZ_BUF_ERROR && s.avail_in == 0) break;
        mz_inflateEnd(&s);
        return std::nullopt;
    }
    mz_inflateEnd(&s);
    out.resize(produced);
    return out;
}

Bytes build_clipboard_send(std::string_view text) {
    static constexpr std::string_view uti = "public.utf8-plain-text";
    Writer inner;
    inner.u32(1).u32(uint32_t(uti.size())).str(uti).u32(0).u32(0).u32(uint32_t(text.size())).str(text);
    Bytes comp = deflate_sync_flush(view(inner.out));
    Writer w;
    w.u8(MSG_CLIPBOARD_SEND).u8(0).u8(0).u8(0).u32(0).u32(uint32_t(inner.size())).u32(uint32_t(comp.size())).raw(view(comp));
    return w.out;
}

std::optional<SendHeader> parse_send_header(ByteView d) {
    if (d.size() < 16 || d[0] != MSG_CLIPBOARD_SEND) return std::nullopt;
    return SendHeader{d[2], be32(d.data() + 4), be32(d.data() + 8), be32(d.data() + 12)};
}

std::vector<Item> parse_items(ByteView d) {
    std::vector<Item> items;
    if (d.size() < 4) return items;
    Reader r(d);
    auto lp = [&]() -> ByteView { const uint32_t n = r.u32(); return r.bytes(n); };
    const uint32_t count = r.u32();
    for (uint32_t i = 0; i < count && r.ok(); ++i) {
        Item it;
        ByteView uti = lp(); it.primary_uti.assign(uti.begin(), uti.end());
        r.u32();
        const uint32_t ac = r.u32();
        for (uint32_t a = 0; a < ac && r.ok(); ++a) { ByteView an = lp(); ByteView av = lp(); it.aliases.emplace_back(std::string(an.begin(), an.end()), to_bytes(av)); }
        it.primary_data = to_bytes(lp());
        if (!r.ok()) break;
        items.push_back(std::move(it));
    }
    return items;
}

std::optional<std::string> text_from_items(const std::vector<Item>& items) {
    for (auto& it : items) if (it.primary_uti == "public.utf8-plain-text") return std::string(it.primary_data.begin(), it.primary_data.end());
    for (auto& it : items) {
        if (it.primary_uti.rfind("public.", 0) == 0 && it.primary_uti.find("text") != std::string::npos) {
            if (it.primary_uti.find("utf16") != std::string::npos) {
                const bool be = it.primary_uti.find("external") != std::string::npos;
                std::u16string u; for (size_t i = 0; i + 1 < it.primary_data.size(); i += 2) u.push_back(char16_t(be ? (it.primary_data[i] << 8 | it.primary_data[i + 1]) : (it.primary_data[i + 1] << 8 | it.primary_data[i])));
                std::string out;
                for (size_t i = 0; i < u.size(); ++i) {
                    uint32_t cp = u[i];
                    if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < u.size()) { cp = 0x10000 + ((cp - 0xD800) << 10) + (u[i + 1] - 0xDC00); ++i; }
                    if (cp < 0x80) out.push_back(char(cp));
                    else if (cp < 0x800) { out.push_back(char(0xC0 | (cp >> 6))); out.push_back(char(0x80 | (cp & 0x3F))); }
                    else if (cp < 0x10000) { out.push_back(char(0xE0 | (cp >> 12))); out.push_back(char(0x80 | ((cp >> 6) & 0x3F))); out.push_back(char(0x80 | (cp & 0x3F))); }
                    else { out.push_back(char(0xF0 | (cp >> 18))); out.push_back(char(0x80 | ((cp >> 12) & 0x3F))); out.push_back(char(0x80 | ((cp >> 6) & 0x3F))); out.push_back(char(0x80 | (cp & 0x3F))); }
                }
                return out;
            }
            return std::string(it.primary_data.begin(), it.primary_data.end());
        }
    }
    for (auto& it : items) if (it.primary_uti == "com.apple.traditional-mac-plain-text") {
        std::string out; for (uint8_t c : it.primary_data) { if (c < 0x80) out.push_back(char(c)); else { out.push_back(char(0xC0 | (c >> 6))); out.push_back(char(0x80 | (c & 0x3F))); } }
        return out;
    }
    return std::nullopt;
}

std::optional<Bytes> Reassembler::feed(ByteView msg) {
    if (buf_.empty()) {
        auto h = parse_send_header(msg);
        if (!h) return std::nullopt;
        expected_ = 16 + size_t(h->compressed);
    }
    buf_.insert(buf_.end(), msg.begin(), msg.end());
    if (buf_.size() >= expected_) {
        Bytes full(buf_.begin(), buf_.begin() + ptrdiff_t(expected_));
        buf_.clear(); expected_ = 0;
        return full;
    }
    return std::nullopt;
}

}  // namespace scshr::clip
