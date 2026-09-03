#include "protocol/auth.h"
#include "common/log.h"
#include "crypto/crypto.h"

namespace scshr::auth {

namespace {
constexpr size_t SRP_HASH_LEN = 64, SRP_MODULUS_LEN = 512, SRP_PBKDF2_DK_LEN = 128;
constexpr size_t RSA_MODULUS_PAYLOAD_LEN = 256, CRED_FIELD_LEN = 64;

std::unique_ptr<crypto::RsaPublicKey> rsa1_init(net::TcpSocket& sock) {
    static const uint8_t init[] = {0x21, 0x00, 0x00, 0x00, 0x0a, 0x01, 0x00, 'R', 'S', 'A', '1', 0x00, 0x00, 0x00, 0x00};
    sock.send_all(ByteView(init, sizeof init));
    const uint32_t pkt_len = be32(sock.recv_exact(4).data());
    if (pkt_len < 6 || pkt_len > 65536) throw AuthError("RSA1 init: bad packet length");
    Bytes pkt = sock.recv_exact(pkt_len);
    const uint32_t key_len = be32(pkt.data() + 2);
    if (6 + size_t(key_len) > pkt.size()) throw AuthError("RSA1 init: bad key length");
    auto key = crypto::RsaPublicKey::from_der(ByteView(pkt.data() + 6, key_len));
    if (!key) throw AuthError("RSA1 init: server public key did not parse");
    LOG_INFO("auth", "RSA1 init: server pubkey %d bits", key->bits());
    return key;
}

Bytes pack_ard_credential(const std::string& v) {
    Bytes d(v.begin(), v.end());
    d.push_back(0);
    if (d.size() < CRED_FIELD_LEN) { Bytes r = crypto::random_bytes(CRED_FIELD_LEN - d.size()); d.insert(d.end(), r.begin(), r.end()); }
    d.resize(CRED_FIELD_LEN);
    return d;
}
}  // namespace

// ── non-SRP ─────────────────────────────────────────────────────────────────
std::array<uint8_t, 16> do_nonsrp_auth(net::TcpSocket& sock, const std::string& username, const std::string& password) {
    auto pub = rsa1_init(sock);
    Bytes aes_key = crypto::random_bytes(16);
    Bytes creds = pack_ard_credential(username);
    Bytes pw = pack_ard_credential(password);
    creds.insert(creds.end(), pw.begin(), pw.end());
    Bytes enc_creds(creds.size());
    crypto::Aes128Ecb(view(aes_key)).encrypt(view(creds), enc_creds.data());
    Bytes enc_key = pub->encrypt_pkcs1(view(aes_key));
    Writer blob;
    blob.raw("\x01\x00RSA1", 6).raw("\x00\x01", 2).raw(view(enc_creds)).raw("\x00\x01", 2).raw(view(enc_key));
    Writer msg; msg.u32(uint32_t(blob.size())).raw(view(blob.out));
    sock.send_all(view(msg.out));
    sock.recv_exact(4);
    const uint32_t result = be32(sock.recv_exact(4).data());
    if (result != 0) throw AuthError("non-SRP auth rejected: result=" + std::to_string(result));
    LOG_INFO("auth", "AUTH OK (non-SRP)");
    std::array<uint8_t, 16> k; std::memcpy(k.data(), aes_key.data(), 16);
    return k;
}

// ── SRP ─────────────────────────────────────────────────────────────────────
SrpChallenge parse_srp_challenge(ByteView s) {
    Reader r(s);
    r.seek(12);
    if (r.u8() != 0) throw AuthError("SRP parse: missing DER zero marker at offset 12");
    SrpChallenge ch;
    ch.N = to_bytes(r.bytes(SRP_MODULUS_LEN));
    const uint16_t g_len = r.u16();
    ByteView gb = r.bytes(g_len);
    uint32_t g = 0; for (uint8_t b : gb) g = (g << 8) | b;
    ch.g = g;
    const uint8_t salt_len = r.u8();
    ch.salt = to_bytes(r.bytes(salt_len));
    const uint16_t b_len = r.u16();
    ch.B = to_bytes(r.bytes(b_len));
    ch.iterations = r.u64();
    const uint16_t cap_len = r.u16();
    ch.cap = to_bytes(r.bytes(cap_len));
    if (!r.ok()) throw AuthError("SRP parse: challenge truncated");
    if (ch.N.size() != SRP_MODULUS_LEN) throw AuthError("expected 4096-bit SRP modulus");
    if (ch.iterations > 1000000) throw AuthError("SRP iteration count exceeds 1M cap");
    return ch;
}

Bytes derive_x(ByteView salt, uint64_t iterations, const std::string& password) {
    Bytes dk = crypto::pbkdf2_hmac_sha512(view(std::string_view(password)), salt, iterations, SRP_PBKDF2_DK_LEN);
    Bytes inner_in; inner_in.push_back(':'); inner_in.insert(inner_in.end(), dk.begin(), dk.end());
    auto inner = crypto::sha512(view(inner_in));
    Bytes x_in(salt.begin(), salt.end()); x_in.insert(x_in.end(), inner.begin(), inner.end());
    auto x = crypto::sha512(view(x_in));
    return Bytes(x.begin(), x.end());
}

SrpProof solve_srp(const SrpChallenge& ch, const std::string& password, ByteView a_override) {
    Bytes g_padded(SRP_MODULUS_LEN, 0);
    g_padded[SRP_MODULUS_LEN - 1] = uint8_t(ch.g);  // g fits one byte (5)
    Bytes k_in = ch.N; k_in.insert(k_in.end(), g_padded.begin(), g_padded.end());
    auto k = crypto::sha512(view(k_in));

    // a = urandom(64) % (N - 1) + 1
    Bytes a;
    if (!a_override.empty()) a = to_bytes(a_override);
    else {
        Bytes rnd = crypto::random_bytes(64);
        Bytes n_minus_1 = ch.N;
        for (size_t i = n_minus_1.size(); i-- > 0;) { if (n_minus_1[i] > 0) { --n_minus_1[i]; break; } n_minus_1[i] = 0xFF; }
        a = crypto::bn_mod(view(rnd), view(n_minus_1), 0);
        // +1 with carry
        bool carry = true;
        for (size_t i = a.size(); i-- > 0 && carry;) { if (a[i] == 0xFF) a[i] = 0; else { ++a[i]; carry = false; } }
        if (carry) a.insert(a.begin(), 1);
    }
    Bytes gb{uint8_t(ch.g)};
    Bytes A = crypto::bn_modexp(view(gb), view(a), view(ch.N), SRP_MODULUS_LEN);
    Bytes u_in = A; u_in.insert(u_in.end(), ch.B.begin(), ch.B.end());
    auto u = crypto::sha512(view(u_in));
    Bytes x = crypto::bn_mod(view(derive_x(view(ch.salt), ch.iterations, password)), view(ch.N), 0);
    Bytes S = crypto::bn_srp_premaster(view(ch.B), ByteView(k), view(gb), view(x), view(a), ByteView(u), view(ch.N), SRP_MODULUS_LEN);
    auto K = crypto::sha512(view(S));
    auto hN = crypto::sha512(view(ch.N));
    auto hg = crypto::sha512(view(g_padded));
    Bytes m1_in;
    for (size_t i = 0; i < 64; ++i) m1_in.push_back(uint8_t(hN[i] ^ hg[i]));
    auto hI = crypto::sha512(ByteView{});
    m1_in.insert(m1_in.end(), hI.begin(), hI.end());
    m1_in.insert(m1_in.end(), ch.salt.begin(), ch.salt.end());
    m1_in.insert(m1_in.end(), A.begin(), A.end());
    m1_in.insert(m1_in.end(), ch.B.begin(), ch.B.end());
    m1_in.insert(m1_in.end(), K.begin(), K.end());
    auto M1 = crypto::sha512(view(m1_in));
    SrpProof p; p.A = A; p.M1 = Bytes(M1.begin(), M1.end()); p.K = Bytes(K.begin(), K.end());
    return p;
}

std::array<uint8_t, 16> do_srp_auth(net::TcpSocket& sock, const std::string& username, const std::string& password) {
    auto pub = rsa1_init(sock);
    // c2s1: username-bearing payload RSA-encrypted into the 'modulus' slot.
    Writer inner; inner.u32(uint32_t(username.size())).str(username).zeros(3);
    Writer payload; payload.u32(uint32_t(inner.size())).raw(view(inner.out));
    Bytes enc = pub->encrypt_pkcs1(view(payload.out));
    if (enc.size() != RSA_MODULUS_PAYLOAD_LEN) throw AuthError("expected 256B RSA block");
    Writer c2s1;
    c2s1.u8(1).u8(0).raw("RSA1\x00\x02", 6).u16(uint16_t(RSA_MODULUS_PAYLOAD_LEN)).raw(view(enc)).zeros(384);
    Writer msg; msg.u32(650).raw(view(c2s1.out));
    sock.send_all(view(msg.out));

    const uint32_t s2c1_len = be32(sock.recv_exact(4).data());
    if (s2c1_len < 1000 || s2c1_len > 65536) {
        if (s2c1_len < 65536) sock.recv_exact(s2c1_len);
        throw AuthError("SRP challenge too short (" + std::to_string(s2c1_len) + "B); server fell back to non-SRP path");
    }
    Bytes s2c1 = sock.recv_exact(s2c1_len);
    SrpChallenge ch = parse_srp_challenge(view(s2c1));
    LOG_INFO("auth", "SRP challenge: N=%zub g=%u salt=%zuB iters=%llu cap=%.*s", ch.N.size() * 8, ch.g, ch.salt.size(),
             (unsigned long long)ch.iterations, int(ch.cap.size()), reinterpret_cast<const char*>(ch.cap.data()));
    SrpProof proof = solve_srp(ch, password);

    Bytes civ = crypto::random_bytes(16);
    Writer sd;
    sd.u16(uint16_t(SRP_MODULUS_LEN)).raw(view(proof.A)).u8(uint8_t(SRP_HASH_LEN)).raw(view(proof.M1))
      .u16(uint16_t(ch.cap.size())).raw(view(ch.cap)).u8(16).raw(view(civ));
    Writer pay;
    pay.u8(1).u8(0).raw("RSA1\x00\x02", 6).u16(uint16_t(sd.size() + 4)).u32(uint32_t(sd.size())).raw(view(sd.out));
    if (pay.size() < 1076) pay.zeros(1076 - pay.size());
    Writer m2; m2.u32(1076).raw(view(pay.out));
    sock.send_all(view(m2.out));

    const uint32_t m2_len = be32(sock.recv_exact(4).data());
    if (m2_len > 65536) throw AuthError("SRP: bad M2 length");
    sock.recv_exact(m2_len);  // M2 not verified (matches reference behaviour; server's result is canonical)
    const uint32_t result = be32(sock.recv_exact(4).data());
    if (result != 0) throw AuthError("SRP auth rejected: result=" + std::to_string(result));
    LOG_INFO("auth", "AUTH OK (SRP)");
    auto key = crypto::sha256(view(proof.K));
    std::array<uint8_t, 16> out; std::memcpy(out.data(), key.data(), 16);
    return out;
}

}  // namespace scshr::auth
