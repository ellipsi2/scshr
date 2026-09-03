#pragma once
// enc1103 record layer (RFC §6): AES-128-CBC persistent stream per direction, plain SHA-1 tag over
// (u32 seq || framed plaintext), u16 length prefix on the wire. Byte-compatible with the Python
// StreamCipher including its tolerant receive-counter window [ctr-1, ctr+5].
#include "common/bytes.h"
#include "crypto/crypto.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

namespace scshr {

class RecordLayer {
public:
    // `key_blob_36` = the 1103 encoding body (u32 generation || 16B enc_key || 16B enc_iv); `wrap_key` = auth-derived key.
    RecordLayer(ByteView key_blob_36, ByteView wrap_key16);

    // ECB key for msg 0x10 input wrapping (the daemon's cryptor switches to the CBC content key after msg 0x12).
    const std::array<uint8_t, 16>& cbc_key() const { return cbc_key_; }

    // Threading contract. Sending: the caller MUST hold send_mutex() across encrypt_message() and the
    // socket write, so the record counter order equals the wire order; encrypt_message() itself takes
    // no lock (a non-recursive mutex locked twice on one thread throws, which silently dropped every
    // post-negotiation control message — input, heartbeats, FIR/NACK — until this was made explicit).
    // Receiving: decrypt_* run on exactly one thread (the TCP reader) and keep their own hash context.
    Bytes encrypt_message(ByteView plaintext);            // framed record ready for the wire
    std::optional<Bytes> decrypt_message(ByteView ct);     // one record's ciphertext (no length prefix)
    // Decrypt as many complete records as `data` holds; returns consumed byte count.
    size_t decrypt_stream(ByteView data, std::vector<Bytes>& out);

    uint32_t send_counter() const { return enc_ctr_.load(); }
    uint32_t recv_counter() const { return dec_ctr_.load(); }
    std::mutex& send_mutex() { return send_mu_; }

private:
    std::array<uint8_t, 16> cbc_key_{};
    std::unique_ptr<crypto::Aes128CbcStream> enc_, dec_;
    std::atomic<uint32_t> enc_ctr_{0}, dec_ctr_{0};
    std::mutex send_mu_;
    crypto::Sha1 enc_sha_, dec_sha_;
};

}  // namespace scshr
