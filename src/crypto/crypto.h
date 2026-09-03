#pragma once
// Thin RAII wrappers over OpenSSL EVP for the exact primitives the protocol needs.
// No custom cryptography: AES / SHA / HMAC / RSA / PBKDF2 / bignum all come from libcrypto.
#include "common/bytes.h"

#include <array>
#include <memory>
#include <string>

typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_mac_ctx_st EVP_MAC_CTX;
typedef struct evp_mac_st EVP_MAC;
typedef struct evp_pkey_st EVP_PKEY;

namespace scshr::crypto {

std::array<uint8_t, 16> md5(ByteView d);
std::array<uint8_t, 20> sha1(ByteView d);
std::array<uint8_t, 32> sha256(ByteView d);
std::array<uint8_t, 64> sha512(ByteView d);
Bytes random_bytes(size_t n);
bool constant_time_eq(ByteView a, ByteView b);

// SHA-1 streaming context (record-layer integrity tag: SHA1(u32 seq || framed)).
class Sha1 {
public:
    Sha1();
    ~Sha1();
    Sha1(const Sha1&) = delete;
    Sha1& operator=(const Sha1&) = delete;
    void reset();
    void update(ByteView d);
    std::array<uint8_t, 20> final();
private:
    void* ctx_;
};

// AES-128-ECB single-block encrypt/decrypt (rekey unwrap, msg 0x10 input wrapper, SessionSelect creds).
class Aes128Ecb {
public:
    explicit Aes128Ecb(ByteView key16);
    ~Aes128Ecb();
    Aes128Ecb(const Aes128Ecb&) = delete;
    Aes128Ecb& operator=(const Aes128Ecb&) = delete;
    void encrypt_block(const uint8_t* in16, uint8_t* out16) const;
    void decrypt_block(const uint8_t* in16, uint8_t* out16) const;
    void encrypt(ByteView in, uint8_t* out) const;  // multiple of 16
private:
    EVP_CIPHER_CTX* enc_;
    EVP_CIPHER_CTX* dec_;
};

// Persistent AES-128-CBC stream (one per direction of the record layer; IV chains across records).
class Aes128CbcStream {
public:
    Aes128CbcStream(ByteView key16, ByteView iv16, bool encrypt);
    ~Aes128CbcStream();
    Aes128CbcStream(const Aes128CbcStream&) = delete;
    Aes128CbcStream& operator=(const Aes128CbcStream&) = delete;
    void process(ByteView in, uint8_t* out);  // in.size() multiple of 16
private:
    EVP_CIPHER_CTX* ctx_;
};

// AES-CTR (128 or 256 key) with a per-call IV; key schedule reused across packets.
class AesCtr {
public:
    explicit AesCtr(ByteView key);
    ~AesCtr();
    AesCtr(const AesCtr&) = delete;
    AesCtr& operator=(const AesCtr&) = delete;
    void crypt(const uint8_t iv16[16], const uint8_t* in, uint8_t* out, size_t n);
private:
    EVP_CIPHER_CTX* ctx_;
};

// AES-ECB encrypt of arbitrary key size (SRTP KDF: AES-CM keystream blocks under the master key).
class AesEcbEnc {
public:
    explicit AesEcbEnc(ByteView key);
    ~AesEcbEnc();
    AesEcbEnc(const AesEcbEnc&) = delete;
    AesEcbEnc& operator=(const AesEcbEnc&) = delete;
    void encrypt_block(const uint8_t* in16, uint8_t* out16) const;
private:
    EVP_CIPHER_CTX* ctx_;
};

// HMAC-SHA1 with a fixed key; `tag()` reinitialises from a keyed template (no per-packet key setup).
class HmacSha1 {
public:
    explicit HmacSha1(ByteView key);
    ~HmacSha1();
    HmacSha1(const HmacSha1&) = delete;
    HmacSha1& operator=(const HmacSha1&) = delete;
    // out20 receives the full 20-byte digest of the concatenation of parts.
    void tag(std::initializer_list<ByteView> parts, uint8_t out20[20]);
private:
    EVP_MAC* mac_;
    EVP_MAC_CTX* tmpl_;
    EVP_MAC_CTX* work_;
};

Bytes pbkdf2_hmac_sha512(ByteView password, ByteView salt, uint64_t iterations, size_t dklen);

// RSA public key from DER SubjectPublicKeyInfo; PKCS#1 v1.5 encryption.
class RsaPublicKey {
public:
    static std::unique_ptr<RsaPublicKey> from_der(ByteView der);
    ~RsaPublicKey();
    int bits() const;
    Bytes encrypt_pkcs1(ByteView msg) const;
private:
    explicit RsaPublicKey(EVP_PKEY* k) : key_(k) {}
    EVP_PKEY* key_;
};

// Big-number helpers for SRP-6a (all big-endian byte strings, fixed width where the protocol pads).
struct BigNum;
Bytes bn_modexp(ByteView base, ByteView exp, ByteView mod, size_t out_len);                // base^exp mod m
Bytes bn_mod(ByteView a, ByteView mod, size_t out_len);                                     // a mod m
Bytes bn_srp_premaster(ByteView B, ByteView k, ByteView g, ByteView x, ByteView a, ByteView u, ByteView N, size_t out_len);
Bytes bn_add_mul_mod_nm1(ByteView a, ByteView u, ByteView x);                             // a + u*x (no modulus; exponent)

}  // namespace scshr::crypto
