// Tunnel pairing / route-policy / config-generation tests.
//
// The golden SCST1 / SCCL1 strings below are also produced by tools/scshr-macos-tunnel.sh
// (`render-server-code` / `render-client-code`), so this file and the macOS script are checked
// against each other by tests/tunnel_shell_test.sh.
#include "tests/test.h"

#include "tunnel/wgconfig.h"

#include <stdexcept>
#include <string>

using namespace scshr;
using namespace scshr::tunnel;

namespace {

// Deterministic 32-byte keys: bytes 0..31, and (7i+3) mod 256.
const std::string kMacPub = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
const std::string kWinPub = "AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw=";
const std::string kServerCode =
    "SCST1:az1BQUVDQXdRRkJnY0lDUW9MREEwT0R4QVJFaE1VRlJZWEdCa2FHeHdkSGg4PQplPW15LW1hYy5leGFtcGxlLm5ldApwPTUxODIwCnM9MTAuNzcuNzcuMQpjPTEwLjc3Ljc3LjI";
const std::string kClientCode =
    "SCCL1:az1Bd29SR0I4bUxUUTdRa2xRVjE1bGJITjZnWWlQbHAya3E3SzV3TWZPMWR3PQpjPTEwLjc3Ljc3LjI";

ServerDescriptor sample_server() {
    ServerDescriptor d;
    d.public_key = kMacPub;
    d.endpoint_host = "my-mac.example.net";
    d.listen_port = 51820;
    return d;
}

bool server_rejected(const std::string& code) {
    ServerDescriptor d;
    std::string why;
    return !decode_server(code, d, why) && !why.empty();
}

// Re-encodes a server descriptor body with one field replaced, so malformed-input tests exercise
// the decoder rather than base64.
std::string server_code_from_body(const std::string& body) { return "SCST1:" + base64url_encode(body); }

}  // namespace

TEST(tunnel_server_descriptor_roundtrip) {
    const std::string code = encode_server(sample_server());
    CHECK_EQ(code, kServerCode);
    ServerDescriptor d;
    std::string why;
    CHECK(decode_server(code, d, why));
    CHECK_EQ(d.public_key, kMacPub);
    CHECK_EQ(d.endpoint_host, std::string("my-mac.example.net"));
    CHECK_EQ(int(d.listen_port), 51820);
    CHECK_EQ(d.mac_ip, std::string("10.77.77.1"));
    CHECK_EQ(d.win_ip, std::string("10.77.77.2"));
}

TEST(tunnel_client_descriptor_roundtrip) {
    ClientDescriptor c;
    c.public_key = kWinPub;
    const std::string code = encode_client(c);
    CHECK_EQ(code, kClientCode);
    ClientDescriptor back;
    std::string why;
    CHECK(decode_client(code, back, why));
    CHECK_EQ(back.public_key, kWinPub);
    CHECK_EQ(back.win_ip, std::string("10.77.77.2"));
}

TEST(tunnel_descriptors_carry_no_private_key) {
    // A pairing descriptor decodes to exactly the published fields — nothing else rides along.
    std::string body;
    CHECK(base64url_decode(kServerCode.substr(6), body));
    CHECK_EQ(body, "k=" + kMacPub + "\ne=my-mac.example.net\np=51820\ns=10.77.77.1\nc=10.77.77.2");
    CHECK(body.find("PrivateKey") == std::string::npos);
    CHECK(base64url_decode(kClientCode.substr(6), body));
    CHECK_EQ(body, "k=" + kWinPub + "\nc=10.77.77.2");
}

TEST(tunnel_unsupported_versions_rejected) {
    CHECK(server_rejected("SCST2:" + kServerCode.substr(6)));
    CHECK(server_rejected("SCST0:" + kServerCode.substr(6)));
    CHECK(server_rejected(kClientCode));                        // client code where a server code belongs
    ClientDescriptor c;
    std::string why;
    CHECK(!decode_client(kServerCode, c, why));
    CHECK(!decode_client("SCCL9:" + kClientCode.substr(6), c, why));
}

TEST(tunnel_malformed_descriptors_rejected) {
    CHECK(server_rejected(""));
    CHECK(server_rejected("SCST1:"));
    CHECK(server_rejected("SCST1:!!!!"));                                   // not base64url
    CHECK(server_rejected("SCST1:" + kServerCode.substr(6) + "="));         // padding is not base64url
    CHECK(server_rejected("SCST1:" + kServerCode.substr(6) + "AAAA"));      // trailing garbage
    CHECK(server_rejected(server_code_from_body("k=" + kMacPub)));          // missing fields
    CHECK(server_rejected(server_code_from_body(
        "k=" + kMacPub + "\ne=my-mac.example.net\np=51820\ns=10.77.77.1\nc=10.77.77.2\nx=1")));   // extra field
    CHECK(server_rejected(server_code_from_body(
        "e=my-mac.example.net\nk=" + kMacPub + "\np=51820\ns=10.77.77.1\nc=10.77.77.2")));        // reordered
    CHECK(server_rejected(server_code_from_body(
        "k=" + kMacPub + "\ne=my-mac.example.net\np=51820\ns=10.77.77.1\nc=10.77.77.2\n")));      // trailing newline
}

TEST(tunnel_invalid_keys_rejected) {
    CHECK(!valid_wg_key(""));
    CHECK(!valid_wg_key("short"));
    CHECK(!valid_wg_key(std::string(44, 'A')));                             // no trailing '='
    CHECK(!valid_wg_key(kMacPub.substr(0, 43) + "A"));                      // 33 bytes worth
    CHECK(!valid_wg_key("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh$="));   // bad alphabet
    CHECK(!valid_wg_key("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh_="));   // base64url spelling
    CHECK(valid_wg_key(kMacPub));
    CHECK(valid_wg_key(kWinPub));
    CHECK(server_rejected(server_code_from_body(
        "k=notakey\ne=my-mac.example.net\np=51820\ns=10.77.77.1\nc=10.77.77.2")));
}

TEST(tunnel_endpoint_validation) {
    CHECK(valid_endpoint_host("my-mac.example.net"));
    CHECK(valid_endpoint_host("mac"));
    CHECK(valid_endpoint_host("203.0.113.7"));
    CHECK(valid_endpoint_host("[2001:db8::1]"));
    CHECK(valid_endpoint_host("[2001:0db8:0000:0000:0000:0000:0000:0001]"));
    CHECK(!valid_endpoint_host(""));
    CHECK(!valid_endpoint_host("0.0.0.0"));
    CHECK(!valid_endpoint_host("255.255.255.255"));
    CHECK(!valid_endpoint_host("127.0.0.1"));
    CHECK(!valid_endpoint_host("239.1.2.3"));            // multicast
    CHECK(!valid_endpoint_host("999.1.2.3"));
    CHECK(!valid_endpoint_host("10.0.0.1.5"));
    CHECK(!valid_endpoint_host("-bad.example.net"));
    CHECK(!valid_endpoint_host("bad-.example.net"));
    CHECK(!valid_endpoint_host("has space.example.net"));
    CHECK(!valid_endpoint_host("[::]"));
    CHECK(!valid_endpoint_host("[::1]"));
    CHECK(!valid_endpoint_host("[ff02::1]"));            // multicast
    CHECK(!valid_endpoint_host("[2001:db8:::1]"));
    CHECK(!valid_endpoint_host("[not:hex:zz::1]"));
    // Endpoint ports.
    CHECK(server_rejected(server_code_from_body("k=" + kMacPub + "\ne=mac\np=0\ns=10.77.77.1\nc=10.77.77.2")));
    CHECK(server_rejected(server_code_from_body("k=" + kMacPub + "\ne=mac\np=70000\ns=10.77.77.1\nc=10.77.77.2")));
    CHECK(server_rejected(server_code_from_body("k=" + kMacPub + "\ne=mac\np=51820x\ns=10.77.77.1\nc=10.77.77.2")));
}

TEST(tunnel_route_policy) {
    std::string why;
    CHECK(route_allowed("10.77.77.1/32", &why));
    CHECK(route_allowed("10.77.77.2/32", &why));
    // Default routes.
    CHECK(!route_allowed("0.0.0.0/0", &why));
    CHECK(!route_allowed("::/0", &why));
    // Broad private blocks.
    CHECK(!route_allowed("10.0.0.0/8", &why));
    CHECK(!route_allowed("172.16.0.0/12", &why));
    CHECK(!route_allowed("192.168.0.0/16", &why));
    CHECK(!route_allowed("10.77.77.0/24", &why));
    CHECK(!route_allowed("10.77.77.0/31", &why));
    // Host routes that are still not the paired peer.
    CHECK(!route_allowed("8.8.8.8/32", &why));
    CHECK(!route_allowed("192.168.1.5/32", &why));
    CHECK(!route_allowed("127.0.0.1/32", &why));
    CHECK(!route_allowed("224.0.0.1/32", &why));
    CHECK(!route_allowed("255.255.255.255/32", &why));
    CHECK(!route_allowed("10.77.77.0/32", &why));      // network address
    CHECK(!route_allowed("10.77.77.255/32", &why));    // subnet broadcast
    CHECK(!route_allowed("10.77.77.1", &why));         // no prefix at all
    CHECK(!route_allowed("10.77.77.1/033", &why));
    CHECK(!route_allowed("garbage", &why));
    // Descriptors carrying an unexpected subnet are rejected as a whole.
    CHECK(server_rejected(server_code_from_body("k=" + kMacPub + "\ne=mac\np=51820\ns=192.168.1.1\nc=10.77.77.2")));
    CHECK(server_rejected(server_code_from_body("k=" + kMacPub + "\ne=mac\np=51820\ns=10.77.77.1\nc=10.77.77.1")));
}

TEST(tunnel_windows_config_generation) {
    WindowsTunnelConfig c;
    c.private_key = kWinPub;      // any valid key shape; the private half never leaves the machine
    c.peer_public_key = kMacPub;
    c.endpoint_host = "my-mac.example.net";
    const std::string conf = render_windows_conf(c);
    CHECK_EQ(conf,
             "# Generated by scshr init - do not edit by hand.\n"
             "# scshr application tunnel: one Windows peer <-> one macOS peer, no default route, no DNS.\n"
             "[Interface]\n"
             "PrivateKey = " + kWinPub + "\n"
             "Address = 10.77.77.2/32\n"
             "\n"
             "[Peer]\n"
             "PublicKey = " + kMacPub + "\n"
             "AllowedIPs = 10.77.77.1/32\n"
             "Endpoint = my-mac.example.net:51820\n"
             "PersistentKeepalive = 25\n");
    // Idempotent: identical input renders identical bytes (this is what makes `init` a no-op).
    CHECK_EQ(conf, render_windows_conf(c));
    // Never a default route, never DNS, never a routing table override.
    CHECK(conf.find("0.0.0.0/0") == std::string::npos);
    CHECK(conf.find("::/0") == std::string::npos);
    CHECK(conf.find("\nDNS") == std::string::npos);      // the word only appears in the header comment
    CHECK(conf.find("\nTable") == std::string::npos);
    CHECK(conf.find("\nMTU") == std::string::npos);
}

TEST(tunnel_windows_config_rejects_bad_input) {
    auto throws = [](WindowsTunnelConfig c) {
        try { render_windows_conf(c); } catch (const std::invalid_argument&) { return true; }
        return false;
    };
    WindowsTunnelConfig base;
    base.private_key = kWinPub;
    base.peer_public_key = kMacPub;
    base.endpoint_host = "my-mac.example.net";
    CHECK(!throws(base));
    { auto c = base; c.peer_ip = "0.0.0.0"; CHECK(throws(c)); }
    { auto c = base; c.peer_ip = "192.168.1.1"; CHECK(throws(c)); }
    { auto c = base; c.peer_ip = c.win_ip; CHECK(throws(c)); }
    { auto c = base; c.endpoint_host = "0.0.0.0"; CHECK(throws(c)); }
    { auto c = base; c.endpoint_port = 0; CHECK(throws(c)); }
    { auto c = base; c.private_key = "bogus"; CHECK(throws(c)); }
    { auto c = base; c.peer_public_key = "bogus"; CHECK(throws(c)); }
    { auto c = base; c.win_ip = "10.99.0.2"; CHECK(throws(c)); }
}

TEST(tunnel_status_parsing) {
    const std::string resp =
        "private_key=e8b1cd0a4bd9de89b2f9f1e6f9de1b8c1f2a3b4c5d6e7f8091a2b3c4d5e6f708\n"
        "public_key=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n"
        "listen_port=51820\n"
        "public_key=030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dc\n"
        "endpoint=203.0.113.7:51820\n"
        "allowed_ip=10.77.77.1/32\n"
        "last_handshake_time_sec=1700000000\n"
        "last_handshake_time_nsec=250000000\n"
        "persistent_keepalive_interval=25\n"
        "rx_bytes=4096\n"
        "tx_bytes=8192\n"
        "errno=0\n\n";
    TunnelStatus st;
    std::string err;
    CHECK(parse_uapi_status(resp, st, err));
    CHECK(st.valid);
    CHECK_EQ(st.interface_public_key, kMacPub);
    CHECK_EQ(st.peer_public_key, kWinPub);
    CHECK_EQ(int(st.listen_port), 51820);
    CHECK_EQ(st.endpoint, std::string("203.0.113.7:51820"));
    CHECK_EQ(st.allowed_ip, std::string("10.77.77.1/32"));
    CHECK_EQ(st.rx_bytes, uint64_t(4096));
    CHECK_EQ(st.tx_bytes, uint64_t(8192));
    CHECK_EQ(st.last_handshake_unix, int64_t(1700000000));
    CHECK_EQ(int(st.persistent_keepalive), 25);

    TunnelStatus bad;
    CHECK(!parse_uapi_status("errno=1\n\n", bad, err));
    CHECK(!parse_uapi_status("public_key=00\nerrno=0\n\n", bad, err));      // short key
    CHECK(!parse_uapi_status("listen_port=51820\n", bad, err));             // truncated, no errno
    CHECK(!parse_uapi_status("garbage\nerrno=0\n\n", bad, err));            // no '='
}

TEST(tunnel_secret_redaction) {
    const std::string conf =
        "[Interface]\nPrivateKey = " + kWinPub + "\nAddress = 10.77.77.2/32\n"
        "[Peer]\nPublicKey = " + kMacPub + "\nPresharedKey = " + kMacPub + "\n";
    const std::string red = redact_secrets(conf);
    CHECK(red.find(kWinPub) == std::string::npos);
    CHECK(red.find("PrivateKey = <redacted>") != std::string::npos);
    CHECK(red.find("PresharedKey = <redacted>") != std::string::npos);
    CHECK(red.find("PublicKey = " + kMacPub) != std::string::npos);   // public material survives
    const std::string uapi = redact_secrets("private_key=deadbeef\npublic_key=cafe\n");
    CHECK(uapi.find("deadbeef") == std::string::npos);
    CHECK(uapi.find("public_key=cafe") != std::string::npos);
}

TEST(tunnel_key_fingerprint) {
    const std::string fp = key_fingerprint(kMacPub);
    CHECK_EQ(fp.size(), size_t(16));
    CHECK(fp != key_fingerprint(kWinPub));
    CHECK_EQ(fp, key_fingerprint(kMacPub));           // stable
    CHECK_EQ(key_fingerprint("bogus"), std::string("<invalid>"));
    CHECK(fp.find(kMacPub.substr(0, 8)) == std::string::npos);   // not the key itself
}
