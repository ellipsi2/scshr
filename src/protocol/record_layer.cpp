#include "protocol/record_layer.h"

#include <stdexcept>

namespace scshr {

namespace {
constexpr size_t MAC_LEN = 20;
constexpr size_t BLOCK = 16;
constexpr uint32_t DECRYPT_COUNTER_WINDOW = 6;
}  // namespace

RecordLayer::RecordLayer(ByteView blob, ByteView wrap_key) {
    if (blob.size() != 36) throw std::runtime_error("enc1103 key blob must be 36 bytes");
    crypto::Aes128Ecb ecb(wrap_key);
    uint8_t iv[16];
    ecb.decrypt_block(blob.data() + 4, cbc_key_.data());
    ecb.decrypt_block(blob.data() + 20, iv);
    // Same key + IV both directions, independent CBC chains.
    enc_ = std::make_unique<crypto::Aes128CbcStream>(ByteView(cbc_key_), ByteView(iv, 16), true);
    dec_ = std::make_unique<crypto::Aes128CbcStream>(ByteView(cbc_key_), ByteView(iv, 16), false);
}

Bytes RecordLayer::encrypt_message(ByteView pt) {
    std::lock_guard<std::mutex> lk(mu_);
    const uint32_t counter = enc_ctr_;
    const size_t pad = (BLOCK - ((2 + pt.size() + MAC_LEN) % BLOCK)) % BLOCK;
    Bytes framed(2 + pt.size() + pad + MAC_LEN);
    put_be16(framed.data(), uint16_t(pt.size()));
    std::memcpy(framed.data() + 2, pt.data(), pt.size());
    // zero filler (receivers must not validate filler contents)
    uint8_t seq_be[4]; put_be32(seq_be, counter);
    sha_.reset();
    sha_.update(ByteView(seq_be, 4));
    sha_.update(ByteView(framed.data(), 2 + pt.size() + pad));
    auto mac = sha_.final();
    std::memcpy(framed.data() + 2 + pt.size() + pad, mac.data(), MAC_LEN);
    Bytes out(2 + framed.size());
    put_be16(out.data(), uint16_t(framed.size()));
    enc_->process(view(framed), out.data() + 2);
    enc_ctr_ = counter + 1;
    return out;
}

std::optional<Bytes> RecordLayer::decrypt_message(ByteView ct) {
    if (ct.empty() || ct.size() % BLOCK) return std::nullopt;
    Bytes pt(ct.size());
    uint32_t ctr_start;
    {
        std::lock_guard<std::mutex> lk(mu_);
        // CBC must consume every received block regardless of MAC outcome (chaining state).
        dec_->process(ct, pt.data());
        ctr_start = dec_ctr_;
        dec_ctr_ += 1;
    }
    if (pt.size() <= MAC_LEN) return pt;
    const size_t body_len = pt.size() - MAC_LEN;
    const uint8_t* mac = pt.data() + body_len;
    const uint32_t lo = ctr_start > 0 ? ctr_start - 1 : 0;
    for (uint32_t c = lo; c < ctr_start + DECRYPT_COUNTER_WINDOW; ++c) {
        uint8_t seq_be[4]; put_be32(seq_be, c);
        sha_.reset();
        sha_.update(ByteView(seq_be, 4));
        sha_.update(ByteView(pt.data(), body_len));
        auto d = sha_.final();
        if (std::memcmp(d.data(), mac, MAC_LEN) == 0) {
            { std::lock_guard<std::mutex> lk(mu_); dec_ctr_ = c + 1; }
            const size_t inner = be16(pt.data());
            if (2 + inner > body_len) return std::nullopt;
            return Bytes(pt.begin() + 2, pt.begin() + 2 + ptrdiff_t(inner));
        }
    }
    return std::nullopt;
}

size_t RecordLayer::decrypt_stream(ByteView data, std::vector<Bytes>& out) {
    size_t pos = 0;
    while (pos + 2 <= data.size()) {
        const size_t len = be16(data.data() + pos);
        if (len == 0 || len % BLOCK != 0 || pos + 2 + len > data.size()) break;
        auto msg = decrypt_message(data.subspan(pos + 2, len));
        pos += 2 + len;
        if (msg) out.push_back(std::move(*msg));
    }
    return pos;
}

}  // namespace scshr
