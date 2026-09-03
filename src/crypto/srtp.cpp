#include "crypto/srtp.h"

#include <algorithm>
#include <stdexcept>

namespace scshr {

namespace {
constexpr size_t RTP_HEADER_MIN = 12;

void split_blob(ByteView blob, ByteView& key, ByteView& salt) {
    if (blob.size() != SRTP_KEY_BLOB_LEN) throw std::runtime_error("SRTP key blob must be 46 bytes");
    key = blob.subspan(0, SRTP_MASTER_KEY_LEN);
    salt = blob.subspan(SRTP_MASTER_KEY_LEN, SRTP_MASTER_SALT_LEN);
}

// IV = (salt << 16) XOR (ssrc << 64) XOR (index << 16), as a 128-bit big-endian value.
void build_rtp_iv(const Bytes& salt14, uint32_t ssrc, uint64_t index, uint8_t iv[16]) {
    std::memcpy(iv, salt14.data(), 14); iv[14] = 0; iv[15] = 0;
    iv[4] ^= uint8_t(ssrc >> 24); iv[5] ^= uint8_t(ssrc >> 16); iv[6] ^= uint8_t(ssrc >> 8); iv[7] ^= uint8_t(ssrc);
    // index is 48-bit: occupies bytes 8..13 after the <<16 shift (bytes 8..13 of the 16-byte IV)
    iv[8] ^= uint8_t(index >> 40); iv[9] ^= uint8_t(index >> 32); iv[10] ^= uint8_t(index >> 24);
    iv[11] ^= uint8_t(index >> 16); iv[12] ^= uint8_t(index >> 8); iv[13] ^= uint8_t(index);
}

void build_rtcp_iv(const Bytes& salt14, uint32_t ssrc, uint32_t index, uint8_t iv[16]) {
    std::memcpy(iv, salt14.data(), 14); iv[14] = 0; iv[15] = 0;
    iv[4] ^= uint8_t(ssrc >> 24); iv[5] ^= uint8_t(ssrc >> 16); iv[6] ^= uint8_t(ssrc >> 8); iv[7] ^= uint8_t(ssrc);
    iv[10] ^= uint8_t(index >> 24); iv[11] ^= uint8_t(index >> 16); iv[12] ^= uint8_t(index >> 8); iv[13] ^= uint8_t(index);
}
}  // namespace

Bytes srtp_kdf(ByteView master_key, ByteView master_salt, uint8_t label, size_t out_len) {
    uint8_t iv0[14] = {};
    iv0[7] = label;
    for (int i = 0; i < 14; ++i) iv0[i] ^= master_salt[size_t(i)];
    crypto::AesEcbEnc ecb(master_key);
    Bytes out;
    uint64_t counter = 0;
    while (out.size() < out_len) {
        uint8_t block[16];
        std::memcpy(block, iv0, 14); block[14] = 0; block[15] = 0;
        // Add the counter to the 128-bit block (big-endian add, low bytes first).
        uint64_t c = counter;
        for (int i = 15; i >= 0 && c; --i) { c += block[i]; block[i] = uint8_t(c); c >>= 8; }
        uint8_t ks[16];
        ecb.encrypt_block(block, ks);
        out.insert(out.end(), ks, ks + 16);
        ++counter;
    }
    out.resize(out_len);
    return out;
}

// ── SrtpDecryptor ───────────────────────────────────────────────────────────
SrtpDecryptor::SrtpDecryptor(ByteView mk, ByteView ms)
    : cipher_key_(srtp_kdf(mk, ms, 0, 32)), auth_key_(srtp_kdf(mk, ms, 1, 20)), salt_(srtp_kdf(mk, ms, 2, 14)),
      aes_(view(cipher_key_)), hmac_(view(auth_key_)) {}

std::unique_ptr<SrtpDecryptor> SrtpDecryptor::from_blob(ByteView blob) {
    ByteView k, s; split_blob(blob, k, s);
    return std::make_unique<SrtpDecryptor>(k, s);
}

std::optional<SrtpDecryptor::SsrcState> SrtpDecryptor::state(uint32_t ssrc) const {
    auto it = states_.find(ssrc);
    if (it == states_.end() || !it->second.initialized) return std::nullopt;
    return it->second;
}

bool SrtpDecryptor::decrypt(uint8_t* pkt, size_t len, RtpHeaderInfo& hdr) {
    if (len < RTP_HEADER_MIN + SRTP_AUTH_TAG_LEN) return false;
    const size_t body_len = len - SRTP_AUTH_TAG_LEN;
    const uint16_t seq = be16(pkt + 2);
    const uint32_t ssrc = be32(pkt + 8);

    uint32_t roc_guess = 0, roc_cur = 0;
    auto it = states_.find(ssrc);
    if (it != states_.end() && it->second.initialized) {
        roc_cur = it->second.roc;
        const int diff = int(seq) - int(it->second.max_seq);
        if (diff > 0x7FFF) roc_guess = roc_cur > 0 ? roc_cur - 1 : 0;
        else if (diff < -0x7FFF) roc_guess = roc_cur + 1;
        else roc_guess = roc_cur;
    }
    // Candidate order (deduped, preserving order): guess, current, guess+1, max(0, guess-1).
    uint32_t cands[4]; int nc = 0;
    auto add = [&](uint32_t r) { for (int i = 0; i < nc; ++i) if (cands[i] == r) return; cands[nc++] = r; };
    add(roc_guess); add(roc_cur); add(roc_guess + 1); add(roc_guess > 0 ? roc_guess - 1 : 0);
    for (int i = 0; i < nc; ++i) {
        if (try_decrypt(pkt, len, body_len, seq, ssrc, cands[i], hdr)) {
            update_state(ssrc, cands[i], seq);
            ++counts_[ssrc];
            return true;
        }
    }
    return false;
}

bool SrtpDecryptor::try_decrypt(uint8_t* pkt, size_t /*len*/, size_t body_len, uint16_t seq, uint32_t ssrc, uint32_t roc, RtpHeaderInfo& hdr) {
    uint8_t roc_be[4]; put_be32(roc_be, roc);
    uint8_t tag[20];
    hmac_.tag({ByteView(pkt, body_len), ByteView(roc_be, 4)}, tag);
    if (!crypto::constant_time_eq(ByteView(tag, SRTP_AUTH_TAG_LEN), ByteView(pkt + body_len, SRTP_AUTH_TAG_LEN))) return false;

    const uint8_t b0 = pkt[0];
    const size_t cc = b0 & 0x0F;
    size_t hdr_len = RTP_HEADER_MIN + cc * 4;
    if ((b0 >> 4) & 1) {
        if (hdr_len + 4 > body_len) return false;
        const size_t ext_len = be16(pkt + hdr_len + 2);
        hdr_len += 4 + ext_len * 4;
    }
    if (hdr_len > body_len) return false;

    hdr.ssrc = ssrc; hdr.seq = seq; hdr.timestamp = be32(pkt + 4);
    hdr.pt = pkt[1] & 0x7F; hdr.marker = (pkt[1] & 0x80) != 0;
    hdr.header_len = hdr_len; hdr.payload_len = body_len - hdr_len;
    if (hdr.payload_len == 0) return true;

    const uint64_t index = (uint64_t(roc) << 16) | seq;
    uint8_t iv[16];
    build_rtp_iv(salt_, ssrc, index, iv);
    aes_.crypt(iv, pkt + hdr_len, pkt + hdr_len, hdr.payload_len);
    return true;
}

void SrtpDecryptor::update_state(uint32_t ssrc, uint32_t roc, uint16_t seq) {
    SsrcState& st = states_[ssrc];
    if (!st.initialized) { st.roc = roc; st.max_seq = seq; st.initialized = true; return; }
    const uint64_t nf = (uint64_t(roc) << 16) | seq, cf = (uint64_t(st.roc) << 16) | st.max_seq;
    if (nf > cf) { st.roc = roc; st.max_seq = seq; }
}

void SrtpDecryptor::forget_ssrcs_except(const std::vector<uint32_t>& keep) {
    auto keep_it = [&](uint32_t s) { return std::find(keep.begin(), keep.end(), s) != keep.end(); };
    for (auto it = counts_.begin(); it != counts_.end();) { if (keep_it(it->first)) ++it; else it = counts_.erase(it); }
    for (auto it = states_.begin(); it != states_.end();) { if (keep_it(it->first)) ++it; else it = states_.erase(it); }
}

std::vector<uint32_t> SrtpDecryptor::primary_ssrc_group(int tiles_per_frame, int tier) const {
    if (counts_.empty()) return {};
    const int grp = std::max(1, tiles_per_frame);
    std::vector<uint32_t> sorted;
    for (auto& kv : counts_) sorted.push_back(kv.first);
    std::sort(sorted.begin(), sorted.end());
    std::vector<std::vector<uint32_t>> groups{{sorted[0]}};
    for (size_t i = 1; i < sorted.size(); ++i) {
        auto& g = groups.back();
        if (sorted[i] - g.back() <= 1 && int(g.size()) < grp) g.push_back(sorted[i]);
        else groups.push_back({sorted[i]});
    }
    auto weight = [&](const std::vector<uint32_t>& g) { uint64_t s = 0; for (uint32_t x : g) s += counts_.at(x); return s; };
    std::stable_sort(groups.begin(), groups.end(), [&](const auto& a, const auto& b) { return weight(a) > weight(b); });
    const size_t idx = size_t(std::min<int>(tier, int(groups.size()) - 1));
    return groups[idx];
}

// ── SrtpEncryptor ───────────────────────────────────────────────────────────
SrtpEncryptor::SrtpEncryptor(ByteView mk, ByteView ms, uint32_t ssrc)
    : cipher_key_(srtp_kdf(mk, ms, 0, 32)), auth_key_(srtp_kdf(mk, ms, 1, 20)), salt_(srtp_kdf(mk, ms, 2, 14)),
      aes_(view(cipher_key_)), hmac_(view(auth_key_)), ssrc_(ssrc) {}

std::unique_ptr<SrtpEncryptor> SrtpEncryptor::from_blob(ByteView blob, uint32_t ssrc) {
    ByteView k, s; split_blob(blob, k, s);
    return std::make_unique<SrtpEncryptor>(k, s, ssrc);
}

Bytes SrtpEncryptor::encrypt(ByteView payload, uint8_t pt, bool marker) {
    std::lock_guard<std::mutex> lk(mu_);
    const uint16_t seq = uint16_t(seq_ & 0xFFFF);
    const uint32_t roc = roc_, ts = ts_;
    if (++seq_ > 0xFFFF) { seq_ = 0; ++roc_; }
    ts_ += 480;
    Bytes out(12 + payload.size() + SRTP_AUTH_TAG_LEN);
    out[0] = 0x80; out[1] = uint8_t((pt & 0x7F) | (marker ? 0x80 : 0));
    put_be16(&out[2], seq); put_be32(&out[4], ts); put_be32(&out[8], ssrc_);
    uint8_t iv[16];
    build_rtp_iv(salt_, ssrc_, (uint64_t(roc) << 16) | seq, iv);
    aes_.crypt(iv, payload.data(), out.data() + 12, payload.size());
    uint8_t roc_be[4]; put_be32(roc_be, roc);
    uint8_t tag[20];
    hmac_.tag({ByteView(out.data(), 12 + payload.size()), ByteView(roc_be, 4)}, tag);
    std::memcpy(out.data() + 12 + payload.size(), tag, SRTP_AUTH_TAG_LEN);
    return out;
}

// ── SRTCP ───────────────────────────────────────────────────────────────────
SrtcpDecryptor::SrtcpDecryptor(ByteView mk, ByteView ms)
    : cipher_key_(srtp_kdf(mk, ms, 3, 32)), auth_key_(srtp_kdf(mk, ms, 4, 20)), salt_(srtp_kdf(mk, ms, 5, 14)),
      aes_(view(cipher_key_)), hmac_(view(auth_key_)) {}

std::unique_ptr<SrtcpDecryptor> SrtcpDecryptor::from_blob(ByteView blob) {
    ByteView k, s; split_blob(blob, k, s);
    return std::make_unique<SrtcpDecryptor>(k, s);
}

std::optional<Bytes> SrtcpDecryptor::unprotect(ByteView pkt) {
    if (pkt.size() < 8 + 4 + SRTP_AUTH_TAG_LEN) return std::nullopt;
    const size_t body_len = pkt.size() - SRTP_AUTH_TAG_LEN;
    uint8_t tag[20];
    hmac_.tag({pkt.subspan(0, body_len)}, tag);
    if (!crypto::constant_time_eq(ByteView(tag, SRTP_AUTH_TAG_LEN), pkt.subspan(body_len))) return std::nullopt;
    const uint32_t e_index = be32(pkt.data() + body_len - 4);
    Bytes out(pkt.begin(), pkt.begin() + ptrdiff_t(body_len - 4));
    if (!(e_index & 0x80000000u)) return out;
    const uint32_t index = e_index & 0x7FFFFFFF;
    const uint32_t ssrc = be32(pkt.data() + 4);
    uint8_t iv[16];
    build_rtcp_iv(salt_, ssrc, index, iv);
    if (out.size() > 8) aes_.crypt(iv, out.data() + 8, out.data() + 8, out.size() - 8);
    return out;
}

SrtcpEncryptor::SrtcpEncryptor(ByteView mk, ByteView ms)
    : cipher_key_(srtp_kdf(mk, ms, 3, 32)), auth_key_(srtp_kdf(mk, ms, 4, 20)), salt_(srtp_kdf(mk, ms, 5, 14)),
      aes_(view(cipher_key_)), hmac_(view(auth_key_)) {}

std::unique_ptr<SrtcpEncryptor> SrtcpEncryptor::from_blob(ByteView blob) {
    ByteView k, s; split_blob(blob, k, s);
    return std::make_unique<SrtcpEncryptor>(k, s);
}

Bytes SrtcpEncryptor::protect(ByteView rtcp) {
    uint32_t index;
    { std::lock_guard<std::mutex> lk(mu_); index = index_++; }
    if (rtcp.size() < 8) return {};
    const uint32_t ssrc = be32(rtcp.data() + 4);
    Bytes out(rtcp.size() + 4 + SRTP_AUTH_TAG_LEN);
    std::memcpy(out.data(), rtcp.data(), 8);
    uint8_t iv[16];
    build_rtcp_iv(salt_, ssrc, index, iv);
    aes_.crypt(iv, rtcp.data() + 8, out.data() + 8, rtcp.size() - 8);
    put_be32(out.data() + rtcp.size(), 0x80000000u | index);
    uint8_t tag[20];
    hmac_.tag({ByteView(out.data(), rtcp.size() + 4)}, tag);
    std::memcpy(out.data() + rtcp.size() + 4, tag, SRTP_AUTH_TAG_LEN);
    return out;
}

}  // namespace scshr
