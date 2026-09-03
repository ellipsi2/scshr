#include "media/avc_util.h"
#include "media/bitstream.h"

#include <vector>

namespace scshr {

bool avc_nal_is_keyframe(ByteView nal) {
    if (nal.size() < 2) return false;
    const int t = nal[0] & 0x1F;
    if (t == 5) return true;
    if (t != 1) return false;
    Bytes rbsp = remove_emulation_prevention(nal.subspan(1, std::min<size_t>(nal.size() - 1, 64)));
    BitReader br(view(rbsp));
    br.read_ue();                       // first_mb_in_slice
    const uint32_t slice_type = br.read_ue();
    if (br.overrun()) return false;
    return slice_type == 2 || slice_type == 7;
}

Bytes avc_patch_sps_dpb(ByteView sps) {
    if (sps.size() < 4 || (sps[0] & 0x1f) != 7) return to_bytes(sps);
    // Operate on the raw (emulation-prevention-included) bits exactly like the reference: Apple's SPS has
    // no 00 00 03 sequences in the header prefix we touch; the reference patch works on raw bits too.
    std::vector<uint8_t> bits;
    for (size_t i = 1; i < sps.size(); ++i) for (int b = 7; b >= 0; --b) bits.push_back((sps[i] >> b) & 1);
    size_t pos = 0;
    bool bad = false;
    auto u = [&](int n) { uint32_t v = 0; for (int i = 0; i < n; ++i) { if (pos >= bits.size()) { bad = true; return v; } v = (v << 1) | bits[pos++]; } return v; };
    auto ue = [&](size_t* start = nullptr, size_t* end = nullptr) -> uint32_t {
        const size_t s = pos; int z = 0;
        while (pos < bits.size() && bits[pos] == 0) { ++z; ++pos; if (z > 31) { bad = true; return 0; } }
        if (pos >= bits.size()) { bad = true; return 0; }
        ++pos;
        uint32_t val = (1u << z) - 1;
        if (z) val += u(z);
        if (start) *start = s; if (end) *end = pos;
        return val;
    };
    const uint32_t profile = u(8);
    u(8);
    const size_t level_start = pos;
    u(8);
    ue();
    switch (profile) {
    case 100: case 110: case 122: case 244: case 44: case 83: case 86: case 118: case 128: case 138: case 139: case 134: case 135: {
        const uint32_t cfi = ue();
        if (cfi == 3) u(1);
        ue(); ue(); u(1);
        if (u(1)) return to_bytes(sps);  // scaling matrix present: no surgery
        break;
    }
    default: break;
    }
    ue();
    const uint32_t poc = ue();
    if (poc == 0) ue();
    else if (poc == 1) { u(1); ue(); ue(); const uint32_t n = ue(); if (n > 255) return to_bytes(sps); for (uint32_t i = 0; i < n; ++i) ue(); }
    size_t ms = 0, me = 0;
    const uint32_t mnrf = ue(&ms, &me);
    if (bad) return to_bytes(sps);
    std::vector<uint8_t> nb = bits;
    if (mnrf < 16) {
        const uint32_t code = 17;  // ue(16)
        int nz = 0; while ((code >> (nz + 1)) != 0) ++nz;
        std::vector<uint8_t> enc(size_t(nz), 0);
        for (int j = nz; j >= 0; --j) enc.push_back((code >> j) & 1);
        nb.erase(nb.begin() + ptrdiff_t(ms), nb.begin() + ptrdiff_t(me));
        nb.insert(nb.begin() + ptrdiff_t(ms), enc.begin(), enc.end());
    }
    for (int i = 0; i < 8; ++i) nb[level_start + size_t(i)] = (60 >> (7 - i)) & 1;
    Bytes out; out.push_back(sps[0]);
    for (size_t i = 0; i < nb.size(); i += 8) {
        uint8_t byte = 0; size_t cnt = 0;
        for (size_t j = i; j < i + 8 && j < nb.size(); ++j) { byte = uint8_t((byte << 1) | nb[j]); ++cnt; }
        if (cnt < 8) byte = uint8_t(byte << (8 - cnt));
        out.push_back(byte);
    }
    return out;
}

}  // namespace scshr
