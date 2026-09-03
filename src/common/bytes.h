#pragma once
// Byte-level helpers: big-endian field access, span/vector aliases, hex.
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace scshr {

using Bytes = std::vector<uint8_t>;
using ByteView = std::span<const uint8_t>;

inline uint16_t be16(const uint8_t* p) { return uint16_t((p[0] << 8) | p[1]); }
inline uint32_t be32(const uint8_t* p) { return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3]; }
inline uint64_t be64(const uint8_t* p) { return (uint64_t(be32(p)) << 32) | be32(p + 4); }
inline void put_be16(uint8_t* p, uint16_t v) { p[0] = uint8_t(v >> 8); p[1] = uint8_t(v); }
inline void put_be32(uint8_t* p, uint32_t v) { p[0] = uint8_t(v >> 24); p[1] = uint8_t(v >> 16); p[2] = uint8_t(v >> 8); p[3] = uint8_t(v); }
inline void put_be64(uint8_t* p, uint64_t v) { put_be32(p, uint32_t(v >> 32)); put_be32(p + 4, uint32_t(v)); }
inline void put_le32(uint8_t* p, uint32_t v) { p[0] = uint8_t(v); p[1] = uint8_t(v >> 8); p[2] = uint8_t(v >> 16); p[3] = uint8_t(v >> 24); }
inline uint32_t le32(const uint8_t* p) { return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24); }

// Growable big-endian writer (protocol message builders).
class Writer {
public:
    Bytes out;
    Writer& u8(uint8_t v) { out.push_back(v); return *this; }
    Writer& u16(uint16_t v) { out.push_back(uint8_t(v >> 8)); out.push_back(uint8_t(v)); return *this; }
    Writer& u32(uint32_t v) { uint8_t b[4]; put_be32(b, v); out.insert(out.end(), b, b + 4); return *this; }
    Writer& u64(uint64_t v) { uint8_t b[8]; put_be64(b, v); out.insert(out.end(), b, b + 8); return *this; }
    Writer& i32(int32_t v) { return u32(uint32_t(v)); }
    Writer& f32(float v) { uint32_t u; std::memcpy(&u, &v, 4); return u32(u); }
    Writer& f64(double v) { uint64_t u; std::memcpy(&u, &v, 8); return u64(u); }
    Writer& raw(ByteView b) { out.insert(out.end(), b.begin(), b.end()); return *this; }
    Writer& raw(const void* p, size_t n) { auto* q = static_cast<const uint8_t*>(p); out.insert(out.end(), q, q + n); return *this; }
    Writer& zeros(size_t n) { out.insert(out.end(), n, 0); return *this; }
    Writer& str(std::string_view s) { out.insert(out.end(), s.begin(), s.end()); return *this; }
    size_t size() const { return out.size(); }
    uint8_t* at(size_t off) { return out.data() + off; }
};

// Bounds-checked big-endian reader. `ok()` goes false on the first short read; values read
// after that are zero. Callers validate `ok()` once at the end (network input is untrusted).
class Reader {
public:
    explicit Reader(ByteView b) : d_(b) {}
    bool ok() const { return ok_; }
    size_t pos() const { return pos_; }
    size_t remaining() const { return d_.size() - pos_; }
    void seek(size_t p) { if (p > d_.size()) { ok_ = false; pos_ = d_.size(); } else pos_ = p; }
    void skip(size_t n) { seek(pos_ + n); }
    uint8_t u8() { if (!need(1)) return 0; return d_[pos_++]; }
    uint16_t u16() { if (!need(2)) return 0; uint16_t v = be16(&d_[pos_]); pos_ += 2; return v; }
    uint32_t u32() { if (!need(4)) return 0; uint32_t v = be32(&d_[pos_]); pos_ += 4; return v; }
    uint64_t u64() { if (!need(8)) return 0; uint64_t v = be64(&d_[pos_]); pos_ += 8; return v; }
    int32_t i32() { return int32_t(u32()); }
    ByteView bytes(size_t n) { if (!need(n)) return {}; ByteView v = d_.subspan(pos_, n); pos_ += n; return v; }
    ByteView rest() { ByteView v = d_.subspan(pos_); pos_ = d_.size(); return v; }
private:
    bool need(size_t n) { if (pos_ + n > d_.size()) { ok_ = false; return false; } return true; }
    ByteView d_;
    size_t pos_ = 0;
    bool ok_ = true;
};

inline Bytes to_bytes(ByteView v) { return Bytes(v.begin(), v.end()); }
inline Bytes to_bytes(std::string_view s) { return Bytes(s.begin(), s.end()); }
inline ByteView view(const Bytes& b) { return ByteView(b.data(), b.size()); }
inline ByteView view(std::string_view s) { return ByteView(reinterpret_cast<const uint8_t*>(s.data()), s.size()); }

std::string hex(ByteView b);
Bytes unhex(std::string_view h);

}  // namespace scshr
