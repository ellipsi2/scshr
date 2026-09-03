#include "crypto/crypto.h"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <stdexcept>

namespace scshr::crypto {

namespace {
template <size_t N>
std::array<uint8_t, N> digest(const EVP_MD* md, ByteView d) {
    std::array<uint8_t, N> out{};
    unsigned int len = 0;
    EVP_Digest(d.data(), d.size(), out.data(), &len, md, nullptr);
    return out;
}
[[noreturn]] void fail(const char* what) { throw std::runtime_error(std::string("crypto: ") + what); }
}  // namespace

std::array<uint8_t, 16> md5(ByteView d) { return digest<16>(EVP_md5(), d); }
std::array<uint8_t, 20> sha1(ByteView d) { return digest<20>(EVP_sha1(), d); }
std::array<uint8_t, 32> sha256(ByteView d) { return digest<32>(EVP_sha256(), d); }
std::array<uint8_t, 64> sha512(ByteView d) { return digest<64>(EVP_sha512(), d); }

Bytes random_bytes(size_t n) {
    Bytes b(n);
    if (n && RAND_bytes(b.data(), int(n)) != 1) fail("RAND_bytes");
    return b;
}

bool constant_time_eq(ByteView a, ByteView b) {
    if (a.size() != b.size()) return false;
    uint8_t acc = 0;
    for (size_t i = 0; i < a.size(); ++i) acc |= uint8_t(a[i] ^ b[i]);
    return acc == 0;
}

// ── SHA-1 ──────────────────────────────────────────────────────────────────
Sha1::Sha1() : ctx_(EVP_MD_CTX_new()) { reset(); }
Sha1::~Sha1() { EVP_MD_CTX_free(static_cast<EVP_MD_CTX*>(ctx_)); }
void Sha1::reset() { EVP_DigestInit_ex(static_cast<EVP_MD_CTX*>(ctx_), EVP_sha1(), nullptr); }
void Sha1::update(ByteView d) { EVP_DigestUpdate(static_cast<EVP_MD_CTX*>(ctx_), d.data(), d.size()); }
std::array<uint8_t, 20> Sha1::final() {
    std::array<uint8_t, 20> out{}; unsigned int n = 0;
    EVP_DigestFinal_ex(static_cast<EVP_MD_CTX*>(ctx_), out.data(), &n);
    return out;
}

// ── AES-128-ECB ─────────────────────────────────────────────────────────────
Aes128Ecb::Aes128Ecb(ByteView key16) : enc_(EVP_CIPHER_CTX_new()), dec_(EVP_CIPHER_CTX_new()) {
    if (key16.size() != 16) fail("AES-128 key must be 16 bytes");
    EVP_EncryptInit_ex(enc_, EVP_aes_128_ecb(), nullptr, key16.data(), nullptr);
    EVP_CIPHER_CTX_set_padding(enc_, 0);
    EVP_DecryptInit_ex(dec_, EVP_aes_128_ecb(), nullptr, key16.data(), nullptr);
    EVP_CIPHER_CTX_set_padding(dec_, 0);
}
Aes128Ecb::~Aes128Ecb() { EVP_CIPHER_CTX_free(enc_); EVP_CIPHER_CTX_free(dec_); }
void Aes128Ecb::encrypt_block(const uint8_t* in16, uint8_t* out16) const {
    int n = 0; EVP_EncryptUpdate(enc_, out16, &n, in16, 16);
}
void Aes128Ecb::decrypt_block(const uint8_t* in16, uint8_t* out16) const {
    int n = 0; EVP_DecryptUpdate(dec_, out16, &n, in16, 16);
}
void Aes128Ecb::encrypt(ByteView in, uint8_t* out) const {
    int n = 0; EVP_EncryptUpdate(enc_, out, &n, in.data(), int(in.size()));
}

// ── AES-128-CBC persistent stream ───────────────────────────────────────────
Aes128CbcStream::Aes128CbcStream(ByteView key16, ByteView iv16, bool encrypt) : ctx_(EVP_CIPHER_CTX_new()) {
    if (key16.size() != 16 || iv16.size() != 16) fail("AES-128-CBC key/iv must be 16 bytes");
    if (encrypt) EVP_EncryptInit_ex(ctx_, EVP_aes_128_cbc(), nullptr, key16.data(), iv16.data());
    else EVP_DecryptInit_ex(ctx_, EVP_aes_128_cbc(), nullptr, key16.data(), iv16.data());
    EVP_CIPHER_CTX_set_padding(ctx_, 0);
}
Aes128CbcStream::~Aes128CbcStream() { EVP_CIPHER_CTX_free(ctx_); }
void Aes128CbcStream::process(ByteView in, uint8_t* out) {
    int n = 0;
    // EVP_CipherUpdate keeps the CBC chaining state across calls (last ciphertext block = next IV).
    EVP_CipherUpdate(ctx_, out, &n, in.data(), int(in.size()));
}

// ── AES-CTR ─────────────────────────────────────────────────────────────────
AesCtr::AesCtr(ByteView key) : ctx_(EVP_CIPHER_CTX_new()) {
    const EVP_CIPHER* c = key.size() == 32 ? EVP_aes_256_ctr() : key.size() == 16 ? EVP_aes_128_ctr() : nullptr;
    if (!c) fail("AES-CTR key must be 16 or 32 bytes");
    EVP_EncryptInit_ex(ctx_, c, nullptr, key.data(), nullptr);
}
AesCtr::~AesCtr() { EVP_CIPHER_CTX_free(ctx_); }
void AesCtr::crypt(const uint8_t iv16[16], const uint8_t* in, uint8_t* out, size_t n) {
    // Re-init IV only; key schedule already set (cipher=NULL, key=NULL keeps it).
    EVP_EncryptInit_ex(ctx_, nullptr, nullptr, nullptr, iv16);
    int outl = 0;
    EVP_EncryptUpdate(ctx_, out, &outl, in, int(n));
}

AesEcbEnc::AesEcbEnc(ByteView key) : ctx_(EVP_CIPHER_CTX_new()) {
    const EVP_CIPHER* c = key.size() == 32 ? EVP_aes_256_ecb() : key.size() == 16 ? EVP_aes_128_ecb() : nullptr;
    if (!c) fail("AES-ECB key must be 16 or 32 bytes");
    EVP_EncryptInit_ex(ctx_, c, nullptr, key.data(), nullptr);
    EVP_CIPHER_CTX_set_padding(ctx_, 0);
}
AesEcbEnc::~AesEcbEnc() { EVP_CIPHER_CTX_free(ctx_); }
void AesEcbEnc::encrypt_block(const uint8_t* in16, uint8_t* out16) const {
    int n = 0; EVP_EncryptUpdate(ctx_, out16, &n, in16, 16);
}

// ── HMAC-SHA1 ───────────────────────────────────────────────────────────────
HmacSha1::HmacSha1(ByteView key) {
    mac_ = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (!mac_) fail("EVP_MAC_fetch HMAC");
    tmpl_ = EVP_MAC_CTX_new(mac_);
    char digest_name[] = "SHA1";
    OSSL_PARAM params[] = { OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest_name, 0), OSSL_PARAM_construct_end() };
    if (EVP_MAC_init(tmpl_, key.data(), key.size(), params) != 1) fail("EVP_MAC_init");
    work_ = EVP_MAC_CTX_dup(tmpl_);
}
HmacSha1::~HmacSha1() { EVP_MAC_CTX_free(work_); EVP_MAC_CTX_free(tmpl_); EVP_MAC_free(mac_); }
void HmacSha1::tag(std::initializer_list<ByteView> parts, uint8_t out20[20]) {
    // Re-init with NULL key reuses the keyed state from the template (OpenSSL 3: EVP_MAC_init(ctx,NULL,0,NULL) resets).
    EVP_MAC_init(work_, nullptr, 0, nullptr);
    for (const ByteView& p : parts) EVP_MAC_update(work_, p.data(), p.size());
    size_t n = 0;
    EVP_MAC_final(work_, out20, &n, 20);
}

Bytes pbkdf2_hmac_sha512(ByteView password, ByteView salt, uint64_t iterations, size_t dklen) {
    Bytes out(dklen);
    if (PKCS5_PBKDF2_HMAC(reinterpret_cast<const char*>(password.data()), int(password.size()), salt.data(), int(salt.size()),
                          int(iterations), EVP_sha512(), int(dklen), out.data()) != 1)
        fail("PBKDF2");
    return out;
}

// ── RSA ─────────────────────────────────────────────────────────────────────
std::unique_ptr<RsaPublicKey> RsaPublicKey::from_der(ByteView der) {
    const unsigned char* p = der.data();
    EVP_PKEY* k = d2i_PUBKEY(nullptr, &p, long(der.size()));
    if (!k) return nullptr;
    return std::unique_ptr<RsaPublicKey>(new RsaPublicKey(k));
}
RsaPublicKey::~RsaPublicKey() { EVP_PKEY_free(key_); }
int RsaPublicKey::bits() const { return EVP_PKEY_get_bits(key_); }
Bytes RsaPublicKey::encrypt_pkcs1(ByteView msg) const {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key_, nullptr);
    if (!ctx) fail("EVP_PKEY_CTX_new");
    Bytes out;
    size_t outlen = 0;
    if (EVP_PKEY_encrypt_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0 ||
        EVP_PKEY_encrypt(ctx, nullptr, &outlen, msg.data(), msg.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx); fail("RSA encrypt size");
    }
    out.resize(outlen);
    if (EVP_PKEY_encrypt(ctx, out.data(), &outlen, msg.data(), msg.size()) <= 0) { EVP_PKEY_CTX_free(ctx); fail("RSA encrypt"); }
    out.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return out;
}

// ── bignum ──────────────────────────────────────────────────────────────────
namespace {
struct Bn {
    BIGNUM* p;
    Bn() : p(BN_new()) {}
    explicit Bn(ByteView b) : p(BN_bin2bn(b.data(), int(b.size()), nullptr)) {}
    ~Bn() { BN_clear_free(p); }
    Bn(const Bn&) = delete;
    Bn& operator=(const Bn&) = delete;
};
Bytes bn_out(const BIGNUM* b, size_t out_len) {
    Bytes out(out_len);
    if (out_len == 0) { out.resize(size_t(BN_num_bytes(b))); BN_bn2bin(b, out.data()); return out; }
    if (BN_bn2binpad(b, out.data(), int(out_len)) < 0) fail("bn2binpad");
    return out;
}
}  // namespace

Bytes bn_modexp(ByteView base, ByteView exp, ByteView mod, size_t out_len) {
    Bn b(base), e(exp), m(mod), r;
    BN_CTX* ctx = BN_CTX_new();
    BN_mod_exp(r.p, b.p, e.p, m.p, ctx);
    BN_CTX_free(ctx);
    return bn_out(r.p, out_len);
}

Bytes bn_mod(ByteView a, ByteView mod, size_t out_len) {
    Bn x(a), m(mod), r;
    BN_CTX* ctx = BN_CTX_new();
    BN_mod(r.p, x.p, m.p, ctx);
    BN_CTX_free(ctx);
    return bn_out(r.p, out_len);
}

Bytes bn_add_mul_mod_nm1(ByteView a, ByteView u, ByteView x) {
    Bn A(a), U(u), X(x), r;
    BN_CTX* ctx = BN_CTX_new();
    BN_mul(r.p, U.p, X.p, ctx);
    BN_add(r.p, r.p, A.p);
    BN_CTX_free(ctx);
    return bn_out(r.p, 0);
}

// S = (B - k*g^x mod N)^(a + u*x) mod N   (SRP-6a client premaster)
Bytes bn_srp_premaster(ByteView Bb, ByteView kb, ByteView gb, ByteView xb, ByteView ab, ByteView ub, ByteView Nb, size_t out_len) {
    Bn B(Bb), k(kb), g(gb), x(xb), a(ab), u(ub), N(Nb), t, e, r;
    BN_CTX* ctx = BN_CTX_new();
    BN_mod_exp(t.p, g.p, x.p, N.p, ctx);      // g^x
    BN_mod_mul(t.p, t.p, k.p, N.p, ctx);      // k*g^x
    BN_mod_sub(t.p, B.p, t.p, N.p, ctx);      // B - k*g^x mod N
    BN_mul(e.p, u.p, x.p, ctx);
    BN_add(e.p, e.p, a.p);                    // a + u*x
    BN_mod_exp(r.p, t.p, e.p, N.p, ctx);
    BN_CTX_free(ctx);
    return bn_out(r.p, out_len);
}

}  // namespace scshr::crypto
