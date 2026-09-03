#include "protocol/bplist.h"

#include <functional>

namespace scshr::bplist {

namespace {

// ── writer (mirrors plistlib._BinaryPlistWriter) ────────────────────────────
struct FlatObj { const Value* val; std::string key; bool is_key; };

struct WriterState {
    Writer w;
    std::vector<size_t> offsets;
    int ref_size = 1;

    void write_size(uint8_t token, size_t size) {
        if (size < 15) w.u8(uint8_t(token | size));
        else if (size < 256) { w.u8(uint8_t(token | 0x0f)); w.u8(0x10); w.u8(uint8_t(size)); }
        else if (size < 65536) { w.u8(uint8_t(token | 0x0f)); w.u8(0x11); w.u16(uint16_t(size)); }
        else { w.u8(uint8_t(token | 0x0f)); w.u8(0x12); w.u32(uint32_t(size)); }
    }
    void write_ref(size_t r) {
        if (ref_size == 1) w.u8(uint8_t(r)); else if (ref_size == 2) w.u16(uint16_t(r)); else w.u32(uint32_t(r));
    }
};

// Flatten order = plistlib: object, then (for dict) sorted keys, then values (recursively). Scalars are
// deduplicated by (type, value); we only need flat dicts so a simple linear table suffices.
struct Flat {
    std::vector<std::variant<std::string, const Value*>> objs;   // string = key object
    std::vector<std::pair<std::string, std::string>> str_dedup;  // (kind, repr) → index
    std::vector<size_t> dedup_idx;

    std::optional<size_t> find(const std::string& kind, const std::string& repr) const {
        for (size_t i = 0; i < str_dedup.size(); ++i) if (str_dedup[i].first == kind && str_dedup[i].second == repr) return dedup_idx[i];
        return std::nullopt;
    }
    void add_scalar_key(const std::string& kind, const std::string& repr, std::variant<std::string, const Value*> o) {
        if (find(kind, repr)) return;
        str_dedup.emplace_back(kind, repr); dedup_idx.push_back(objs.size()); objs.push_back(std::move(o));
    }
    std::string repr_of(const Value& v) {
        if (auto s = v.str()) return "s:" + *s;
        if (auto b = v.data()) return "b:" + std::string(b->begin(), b->end());
        if (auto i = v.integer()) return "i:" + std::to_string(*i);
        return "";
    }
    void flatten(const Value& v) {
        const std::string r = repr_of(v);
        if (!r.empty()) { add_scalar_key("scalar", r, &v); return; }
        objs.push_back(&v);
        if (auto d = v.dict()) {
            for (auto& kv : *d) add_scalar_key("scalar", "s:" + kv.first, kv.first);
            for (auto& kv : *d) flatten(kv.second);
        }
    }
    size_t ref_of_key(const std::string& k) const { return *find("scalar", "s:" + k); }
    size_t ref_of(const Value& v) {
        const std::string r = repr_of(v);
        if (!r.empty()) return *find("scalar", r);
        for (size_t i = 0; i < objs.size(); ++i) if (auto p = std::get_if<const Value*>(&objs[i]); p && *p == &v) return i;
        return 0;
    }
};

void write_string(WriterState& ws, const std::string& s) {
    bool ascii = true; for (unsigned char c : s) if (c >= 0x80) { ascii = false; break; }
    if (ascii) { ws.write_size(0x50, s.size()); ws.w.str(s); }
    else {
        // UTF-16BE
        std::u16string u;
        for (size_t i = 0; i < s.size();) {
            unsigned char c = s[i]; uint32_t cp; size_t n;
            if (c < 0x80) { cp = c; n = 1; } else if ((c & 0xE0) == 0xC0) { cp = c & 0x1F; n = 2; } else if ((c & 0xF0) == 0xE0) { cp = c & 0x0F; n = 3; } else { cp = c & 0x07; n = 4; }
            for (size_t j = 1; j < n && i + j < s.size(); ++j) cp = (cp << 6) | (s[i + j] & 0x3F);
            i += n;
            if (cp >= 0x10000) { cp -= 0x10000; u.push_back(char16_t(0xD800 + (cp >> 10))); u.push_back(char16_t(0xDC00 + (cp & 0x3FF))); } else u.push_back(char16_t(cp));
        }
        ws.write_size(0x60, u.size());
        for (char16_t c : u) ws.w.u16(c);
    }
}

void write_object(WriterState& ws, Flat& f, const std::variant<std::string, const Value*>& o) {
    ws.offsets.push_back(ws.w.size());
    if (auto ks = std::get_if<std::string>(&o)) { write_string(ws, *ks); return; }
    const Value& v = **std::get_if<const Value*>(&o);
    if (auto s = v.str()) { write_string(ws, *s); return; }
    if (auto b = v.data()) { ws.write_size(0x40, b->size()); ws.w.raw(view(*b)); return; }
    if (auto i = v.integer()) {
        const int64_t x = *i;
        if (x >= 0 && x < (1 << 8)) { ws.w.u8(0x10); ws.w.u8(uint8_t(x)); }
        else if (x >= 0 && x < (1 << 16)) { ws.w.u8(0x11); ws.w.u16(uint16_t(x)); }
        else if (x >= 0 && x < (1LL << 32)) { ws.w.u8(0x12); ws.w.u32(uint32_t(x)); }
        else { ws.w.u8(0x13); ws.w.u64(uint64_t(x)); }
        return;
    }
    if (auto d = v.dict()) {
        ws.write_size(0xD0, d->size());
        for (auto& kv : *d) ws.write_ref(f.ref_of_key(kv.first));
        for (auto& kv : *d) ws.write_ref(f.ref_of(kv.second));
        return;
    }
    ws.w.u8(0x00);  // null (unused)
}

}  // namespace

Bytes dump(const Dict& root) {
    Value rootv(root);
    Flat f;
    f.flatten(rootv);
    WriterState ws;
    const size_t num = f.objs.size();
    ws.ref_size = num < 256 ? 1 : num < 65536 ? 2 : 4;
    ws.w.str("bplist00");
    for (auto& o : f.objs) write_object(ws, f, o);
    const size_t table_off = ws.w.size();
    const size_t max_off = table_off;
    const int off_size = max_off < 256 ? 1 : max_off < 65536 ? 2 : 4;
    for (size_t off : ws.offsets) { if (off_size == 1) ws.w.u8(uint8_t(off)); else if (off_size == 2) ws.w.u16(uint16_t(off)); else ws.w.u32(uint32_t(off)); }
    ws.w.zeros(6).u8(uint8_t(off_size)).u8(uint8_t(ws.ref_size)).u64(num).u64(0).u64(table_off);
    return ws.w.out;
}

// ── reader ──────────────────────────────────────────────────────────────────
namespace {
struct ReaderState {
    ByteView d;
    std::vector<size_t> offsets;
    int ref_size = 1;
    int depth = 0;
    bool ok = true;

    uint64_t read_int_at(size_t& pos, int nbytes) {
        if (pos + size_t(nbytes) > d.size()) { ok = false; return 0; }
        uint64_t v = 0; for (int i = 0; i < nbytes; ++i) v = (v << 8) | d[pos + size_t(i)];
        pos += size_t(nbytes);
        return v;
    }
    bool read_size(size_t& pos, uint8_t marker, size_t& size) {
        size = marker & 0x0f;
        if (size != 0x0f) return true;
        if (pos >= d.size()) return false;
        const uint8_t m = d[pos++];
        if ((m >> 4) != 1) return false;
        const int n = 1 << (m & 0x0f);
        if (n > 8) return false;
        size = size_t(read_int_at(pos, n));
        return ok;
    }
    std::optional<Value> read_object(size_t ref) {
        if (ref >= offsets.size() || ++depth > 32) return std::nullopt;
        struct D { int& d; ~D() { --d; } } dg{depth};
        size_t pos = offsets[ref];
        if (pos >= d.size()) return std::nullopt;
        const uint8_t marker = d[pos++];
        const uint8_t top = marker >> 4;
        switch (top) {
        case 0x0:
            if (marker == 0x08) { Value v; v.v = false; return v; }
            if (marker == 0x09) { Value v; v.v = true; return v; }
            return Value{};
        case 0x1: { const int n = 1 << (marker & 0x0f); if (n > 8) return std::nullopt; Value v; v.v = int64_t(read_int_at(pos, n)); return ok ? std::optional<Value>(v) : std::nullopt; }
        case 0x2: { const int n = 1 << (marker & 0x0f); if (n != 4 && n != 8) return std::nullopt; uint64_t u = read_int_at(pos, n); double f = 0; if (n == 8) std::memcpy(&f, &u, 8); else { uint32_t u32 = uint32_t(u); float ff; std::memcpy(&ff, &u32, 4); f = ff; } Value v; v.v = f; return v; }
        case 0x4: { size_t n; if (!read_size(pos, marker, n) || pos + n > d.size()) return std::nullopt; return Value(Bytes(d.begin() + ptrdiff_t(pos), d.begin() + ptrdiff_t(pos + n))); }
        case 0x5: { size_t n; if (!read_size(pos, marker, n) || pos + n > d.size()) return std::nullopt; return Value(std::string(d.begin() + ptrdiff_t(pos), d.begin() + ptrdiff_t(pos + n))); }
        case 0x6: { size_t n; if (!read_size(pos, marker, n) || pos + n * 2 > d.size()) return std::nullopt; std::string s; for (size_t i = 0; i < n; ++i) { uint16_t c = be16(&d[pos + i * 2]); if (c < 0x80) s.push_back(char(c)); else if (c < 0x800) { s.push_back(char(0xC0 | (c >> 6))); s.push_back(char(0x80 | (c & 0x3F))); } else { s.push_back(char(0xE0 | (c >> 12))); s.push_back(char(0x80 | ((c >> 6) & 0x3F))); s.push_back(char(0x80 | (c & 0x3F))); } } return Value(std::move(s)); }
        case 0xA: {
            size_t n; if (!read_size(pos, marker, n) || pos + n * size_t(ref_size) > d.size()) return std::nullopt;
            auto arr = std::make_shared<Array>();
            for (size_t i = 0; i < n; ++i) { size_t r = size_t(read_int_at(pos, ref_size)); auto o = read_object(r); if (!o) return std::nullopt; arr->push_back(std::move(*o)); }
            Value v; v.v = arr; return v;
        }
        case 0xD: {
            size_t n; if (!read_size(pos, marker, n) || pos + n * 2 * size_t(ref_size) > d.size()) return std::nullopt;
            std::vector<size_t> krefs, vrefs;
            for (size_t i = 0; i < n; ++i) krefs.push_back(size_t(read_int_at(pos, ref_size)));
            for (size_t i = 0; i < n; ++i) vrefs.push_back(size_t(read_int_at(pos, ref_size)));
            auto dict = std::make_shared<Dict>();
            for (size_t i = 0; i < n; ++i) {
                auto k = read_object(krefs[i]); if (!k || !k->str()) return std::nullopt;
                auto v = read_object(vrefs[i]); if (!v) return std::nullopt;
                (*dict)[*k->str()] = std::move(*v);
            }
            Value v; v.v = dict; return v;
        }
        default: return std::nullopt;
        }
    }
};
}  // namespace

std::optional<Value> load(ByteView data) {
    if (data.size() < 8 + 32 || std::memcmp(data.data(), "bplist0", 7) != 0) return std::nullopt;
    const uint8_t* tr = data.data() + data.size() - 32;
    const int off_size = tr[6], ref_size = tr[7];
    const uint64_t num = be64(tr + 8), top = be64(tr + 16), table_off = be64(tr + 24);
    if (off_size < 1 || off_size > 8 || ref_size < 1 || ref_size > 8 || num == 0 || num > 100000) return std::nullopt;
    if (table_off >= data.size() || table_off + num * uint64_t(off_size) > data.size() - 32) return std::nullopt;
    if (top >= num) return std::nullopt;
    ReaderState rs; rs.d = data; rs.ref_size = ref_size;
    size_t pos = size_t(table_off);
    for (uint64_t i = 0; i < num; ++i) { rs.offsets.push_back(size_t(rs.read_int_at(pos, off_size))); if (!rs.ok) return std::nullopt; }
    for (size_t o : rs.offsets) if (o >= table_off) return std::nullopt;
    return rs.read_object(size_t(top));
}

}  // namespace scshr::bplist
