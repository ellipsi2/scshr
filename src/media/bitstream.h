#pragma once
// RBSP helpers: emulation-prevention removal + MSB-first bit reader with Exp-Golomb.
#include "common/bytes.h"

namespace scshr {

inline Bytes remove_emulation_prevention(ByteView d) {
    Bytes out; out.reserve(d.size());
    size_t i = 0, n = d.size();
    while (i < n) {
        if (i + 2 < n && d[i] == 0 && d[i + 1] == 0 && d[i + 2] == 3) { out.push_back(0); out.push_back(0); i += 3; }
        else out.push_back(d[i++]);
    }
    return out;
}

class BitReader {
public:
    explicit BitReader(ByteView d) : d_(d) {}
    size_t pos() const { return pos_; }
    uint32_t read1() {
        const size_t byte = pos_ >> 3;
        if (byte >= d_.size()) { ++pos_; return 0; }
        const uint32_t bit = 7 - (pos_ & 7);
        ++pos_;
        return (d_[byte] >> bit) & 1;
    }
    uint32_t read(int n) { uint32_t v = 0; for (int i = 0; i < n; ++i) v = (v << 1) | read1(); return v; }
    uint32_t read_ue() {
        int zeros = 0;
        while (read1() == 0 && zeros < 32) ++zeros;
        uint32_t suffix = 0;
        for (int i = zeros - 1; i >= 0; --i) suffix |= read1() << i;
        return ((1u << zeros) - 1) + suffix;
    }
    int32_t read_se() { const uint32_t c = read_ue(); return (c & 1) ? int32_t((c + 1) / 2) : -int32_t(c / 2); }
    bool overrun() const { return (pos_ >> 3) > d_.size(); }
private:
    ByteView d_;
    size_t pos_ = 0;
};

}  // namespace scshr
