#pragma once
// SRTP / SRTCP (RFC 3711) AES-256-CM + HMAC-SHA1-80, exactly as the Python reference
// (proxy/protocol/srtp.py): per-SSRC ROC tracking with the guess/current/+1/-1 candidate
// order, in-place decrypt, 46-byte master key blobs (32 key || 14 salt).
#include "common/bytes.h"
#include "crypto/crypto.h"

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <vector>

namespace scshr {

constexpr size_t SRTP_KEY_BLOB_LEN = 46;
constexpr size_t SRTP_MASTER_KEY_LEN = 32;
constexpr size_t SRTP_MASTER_SALT_LEN = 14;
constexpr size_t SRTP_AUTH_TAG_LEN = 10;

struct RtpHeaderInfo {
    uint32_t ssrc = 0;
    uint32_t timestamp = 0;
    uint16_t seq = 0;
    uint8_t pt = 0;
    bool marker = false;
    size_t header_len = 0;   // bytes of RTP header (incl. CSRC + extension)
    size_t payload_len = 0;  // decrypted payload length following header
};

// RFC 3711 §4.3.1 AES-CM KDF. Exposed for tests/vectors.
Bytes srtp_kdf(ByteView master_key, ByteView master_salt, uint8_t label, size_t out_len);

class SrtpDecryptor {
public:
    SrtpDecryptor(ByteView master_key, ByteView master_salt);
    static std::unique_ptr<SrtpDecryptor> from_blob(ByteView blob46);

    // Authenticates + decrypts `pkt` IN PLACE. On success the payload bytes at
    // [hdr.header_len, hdr.header_len + hdr.payload_len) are plaintext. Returns false on auth failure.
    bool decrypt(uint8_t* pkt, size_t len, RtpHeaderInfo& hdr);

    // Per-SSRC packet counts (SSRC-group discovery / adoption).
    const std::unordered_map<uint32_t, uint64_t>& ssrc_counts() const { return counts_; }
    void forget_ssrcs_except(const std::vector<uint32_t>& keep);
    // Consecutive-SSRC group discovery (tier 0 = most packets), group size = tiles per frame.
    std::vector<uint32_t> primary_ssrc_group(int tiles_per_frame, int tier = 0) const;
    struct SsrcState { uint32_t roc = 0; uint16_t max_seq = 0; bool initialized = false; };
    std::optional<SsrcState> state(uint32_t ssrc) const;

private:
    bool try_decrypt(uint8_t* pkt, size_t len, size_t body_len, uint16_t seq, uint32_t ssrc, uint32_t roc, RtpHeaderInfo& hdr);
    void update_state(uint32_t ssrc, uint32_t roc, uint16_t seq);

    Bytes cipher_key_, auth_key_, salt_;
    crypto::AesCtr aes_;
    crypto::HmacSha1 hmac_;
    std::unordered_map<uint32_t, SsrcState> states_;
    std::unordered_map<uint32_t, uint64_t> counts_;
};

class SrtpEncryptor {
public:
    SrtpEncryptor(ByteView master_key, ByteView master_salt, uint32_t ssrc);
    static std::unique_ptr<SrtpEncryptor> from_blob(ByteView blob46, uint32_t ssrc);
    Bytes encrypt(ByteView payload, uint8_t pt = 101, bool marker = false);
    uint32_t ssrc() const { return ssrc_; }
private:
    Bytes cipher_key_, auth_key_, salt_;
    crypto::AesCtr aes_;
    crypto::HmacSha1 hmac_;
    uint32_t ssrc_;
    uint32_t seq_ = 0, roc_ = 0, ts_ = 0;
    std::mutex mu_;
};

class SrtcpDecryptor {
public:
    SrtcpDecryptor(ByteView master_key, ByteView master_salt);
    static std::unique_ptr<SrtcpDecryptor> from_blob(ByteView blob46);
    std::optional<Bytes> unprotect(ByteView pkt);
private:
    Bytes cipher_key_, auth_key_, salt_;
    crypto::AesCtr aes_;
    crypto::HmacSha1 hmac_;
};

class SrtcpEncryptor {
public:
    SrtcpEncryptor(ByteView master_key, ByteView master_salt);
    static std::unique_ptr<SrtcpEncryptor> from_blob(ByteView blob46);
    Bytes protect(ByteView rtcp);
private:
    Bytes cipher_key_, auth_key_, salt_;
    crypto::AesCtr aes_;
    crypto::HmacSha1 hmac_;
    uint32_t index_ = 0;
    std::mutex mu_;
};

}  // namespace scshr
