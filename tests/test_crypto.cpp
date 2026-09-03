// Crypto/protocol invariants that do not need the Python oracle (that lives in tests/diff_vectors.py).
#include "tests/test.h"

#include "crypto/crypto.h"
#include "crypto/srtp.h"
#include "protocol/record_layer.h"

using namespace scshr;

TEST(srtp_roundtrip_and_roc) {
    Bytes blob = crypto::random_bytes(46);
    auto enc = SrtpEncryptor::from_blob(view(blob), 0x42);
    auto dec = SrtpDecryptor::from_blob(view(blob));
    Bytes payload(500, 7);
    for (int i = 0; i < 70000; ++i) {   // crosses the 65536 sequence wrap → ROC 1
        Bytes p = enc->encrypt(view(payload), 100, i % 3 == 0);
        RtpHeaderInfo h;
        const bool ok = dec->decrypt(p.data(), p.size(), h);
        if (!ok || std::memcmp(p.data() + h.header_len, payload.data(), 500) != 0) { CHECK(false); break; }
    }
    CHECK_EQ(dec->state(0x42)->roc, 1u);
}

TEST(srtp_rejects_tamper_and_short) {
    Bytes blob = crypto::random_bytes(46);
    auto enc = SrtpEncryptor::from_blob(view(blob), 1);
    auto dec = SrtpDecryptor::from_blob(view(blob));
    Bytes p = enc->encrypt(view(Bytes(100, 1)), 100);
    p[30] ^= 1;
    RtpHeaderInfo h;
    CHECK(!dec->decrypt(p.data(), p.size(), h));
    Bytes s(15, 0);
    CHECK(!dec->decrypt(s.data(), s.size(), h));
}

TEST(record_layer_roundtrip_and_counter_window) {
    Bytes wrap = crypto::random_bytes(16), key = crypto::random_bytes(16), iv = crypto::random_bytes(16);
    crypto::Aes128Ecb ecb(view(wrap));
    Bytes blob(36, 0); ecb.encrypt_block(key.data(), blob.data() + 4); ecb.encrypt_block(iv.data(), blob.data() + 20);
    RecordLayer a(view(blob), view(wrap)), b(view(blob), view(wrap));
    Bytes stream;
    for (int i = 0; i < 20; ++i) { Bytes m(size_t(i * 7 + 1), uint8_t(i)); Bytes e = a.encrypt_message(view(m)); stream.insert(stream.end(), e.begin(), e.end()); }
    std::vector<Bytes> out;
    const size_t consumed = b.decrypt_stream(view(stream), out);
    CHECK_EQ(consumed, stream.size()); CHECK_EQ(out.size(), size_t(20));
    CHECK_EQ(out[19].size(), size_t(19 * 7 + 1));
    // Tampered record: MAC mismatch → dropped, counter still advances by one (tolerant window resyncs later records).
    RecordLayer c(view(blob), view(wrap)), d(view(blob), view(wrap));
    Bytes e1 = c.encrypt_message(view(Bytes{1})), e2 = c.encrypt_message(view(Bytes{2}));
    e1[5] ^= 0x80;
    std::vector<Bytes> o2;
    Bytes s2 = e1; s2.insert(s2.end(), e2.begin(), e2.end());
    d.decrypt_stream(view(s2), o2);
    CHECK_EQ(o2.size(), size_t(1));   // second record survives thanks to the [ctr-1, ctr+5] window
}

TEST(hmac_context_reuse_is_stateless) {
    Bytes k = crypto::random_bytes(20);
    crypto::HmacSha1 h(view(k));
    uint8_t t1[20], t2[20];
    Bytes d = crypto::random_bytes(1000);
    h.tag({view(d)}, t1); h.tag({view(Bytes(3, 9))}, t2); h.tag({view(d)}, t2);
    CHECK(std::memcmp(t1, t2, 20) == 0);
}
