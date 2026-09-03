// Pairing-wizard parsing tests: settings persistence format, the SCST1 scraper, the macOS preflight
// report and SSH host parsing. Everything here is pure — nothing touches the network, SSH or the
// registry, so the suite stays runnable on a machine that has never seen a Mac.
#include "tests/test.h"

#include "app/settings.h"
#include "app/setup.h"
#include "app/ssh_client.h"

#include <string>
#include <utility>

using namespace scshr;
using namespace scshr::app;

namespace {

// Same golden as tests/test_tunnel.cpp (and tools/scshr-macos-tunnel.sh render-server-code).
const std::string kServerCode =
    "SCST1:az1BQUVDQXdRRkJnY0lDUW9MREEwT0R4QVJFaE1VRlJZWEdCa2FHeHdkSGg4PQplPW15LW1hYy5leGFtcGxlLm5ldApwPTUxODIwCnM9MTAuNzcuNzcuMQpjPTEwLjc3Ljc3LjI";

}  // namespace

TEST(setup_settings_roundtrip) {
    Settings s;
    s.mac_label = "Studio Mac";
    s.ssh_host = "studio.local";
    s.ssh_port = 2222;
    s.ssh_user = "admin";
    s.ssh_hostkey_sha256 = "abcDEF123+/xyz";
    s.screen_user = "viewer";
    s.remember_password = true;
    s.audio = false;
    s.display = "combined";
    s.separate_session = false;
    s.paired = true;

    const std::string text = serialize_settings(s);
    CHECK_EQ(text, serialize_settings(parse_settings(text)));   // deterministic + stable

    const Settings r = parse_settings(text);
    CHECK_EQ(r.mac_label, s.mac_label);
    CHECK_EQ(r.ssh_host, s.ssh_host);
    CHECK_EQ(r.ssh_port, s.ssh_port);
    CHECK_EQ(r.ssh_user, s.ssh_user);
    CHECK_EQ(r.ssh_hostkey_sha256, s.ssh_hostkey_sha256);
    CHECK_EQ(r.screen_user, s.screen_user);
    CHECK_EQ(r.remember_password, true);
    CHECK_EQ(r.audio, false);
    CHECK_EQ(r.display, s.display);
    CHECK_EQ(r.separate_session, false);
    CHECK_EQ(r.paired, true);
}

TEST(setup_settings_tolerates_foreign_keys) {
    // A file written by a newer build must still load: unknown keys are skipped, known ones survive.
    const Settings r = parse_settings(
        "# comment line\n"
        "future_feature=42\n"
        "ssh_host=mac.local\n"
        "\n"
        "not a key value line\n"
        "audio=false\n"
        "remember_password=yes\n"
        "paired=1\n"
        "ssh_port=99999\n");            // out of range: ignored, default kept
    CHECK_EQ(r.ssh_host, std::string("mac.local"));
    CHECK_EQ(r.audio, false);
    CHECK_EQ(r.remember_password, true);
    CHECK_EQ(r.paired, true);
    CHECK_EQ(r.ssh_port, uint16_t(22));
    CHECK_EQ(r.display, std::string("all"));   // untouched default
    CHECK_EQ(r.separate_session, true);        // default: own session
}

TEST(setup_settings_bool_spellings) {
    CHECK_EQ(parse_settings("audio=0\n").audio, false);
    CHECK_EQ(parse_settings("audio=no\n").audio, false);
    CHECK_EQ(parse_settings("audio=off\n").audio, false);
    CHECK_EQ(parse_settings("audio=1\n").audio, true);
    CHECK_EQ(parse_settings("audio=true\n").audio, true);
    CHECK_EQ(parse_settings("audio=maybe\n").audio, true);   // unparsable: default kept
}

TEST(setup_extract_server_code) {
    const std::string noisy =
        "scshr macOS tunnel\n"
        "  identity   : created\n"
        "  listen port: 51820 (UDP)\n"
        "  firewall   : pf anchor installed\n"
        "\n"
        "Give this to Windows:\n"
        "\n" + kServerCode + "\n";
    CHECK_EQ(extract_server_code(noisy), kServerCode);

    // Trailing punctuation and surrounding quotes must not become part of the token.
    CHECK_EQ(extract_server_code("code: '" + kServerCode + "'.\n"), kServerCode);
    // The last valid code wins when a transcript echoes an older one first.
    CHECK_EQ(extract_server_code("SCST1:notvalid\nold\n" + kServerCode + "\n"), kServerCode);
}

TEST(setup_extract_server_code_rejects_malformed) {
    CHECK(extract_server_code("").empty());
    CHECK(extract_server_code("no code here at all\n").empty());
    CHECK(extract_server_code("SCST1:%%%%\n").empty());
    CHECK(extract_server_code("SCST2:" + kServerCode.substr(6) + "\n").empty());   // wrong version
    CHECK(extract_server_code(kServerCode + "AAAA\n").empty());                    // trailing garbage
    CHECK(extract_server_code(kServerCode.substr(0, kServerCode.size() - 4) + "\n").empty());
}

TEST(setup_parse_preflight) {
    const Preflight p = parse_preflight(
        "macos_version=15.3.1\n"
        "arch=arm64\n"
        "helper=ok\n"
        "pf_conf=present\n"
        "screen_sharing=disabled\n"
        "sudo=ok\n"
        "firewall=on\n");   // appended last by the macOS helper: parsing must not depend on key order
    CHECK(p.ok);
    CHECK(p.error.empty());
    CHECK_EQ(p.firewall, std::string("on"));
    CHECK_EQ(p.macos_version, std::string("15.3.1"));
    CHECK_EQ(p.arch, std::string("arm64"));
    CHECK_EQ(p.helper, std::string("ok"));
    CHECK_EQ(p.pf_conf, std::string("present"));
    CHECK_EQ(p.screen_sharing, std::string("disabled"));

    const Preflight junk = parse_preflight("sudo: a password is required\n");
    CHECK(!junk.ok);
    CHECK(!junk.error.empty());

    const Preflight partial = parse_preflight("arch=x86_64\n");   // no version → not usable
    CHECK(!partial.ok);
}

TEST(setup_parse_ssh_host) {
    std::string h;
    uint16_t p = 0;

    CHECK(parse_ssh_host("mac.local", h, p));
    CHECK_EQ(h, std::string("mac.local"));
    CHECK_EQ(p, uint16_t(22));

    CHECK(parse_ssh_host("mac.local:2222", h, p));
    CHECK_EQ(h, std::string("mac.local"));
    CHECK_EQ(p, uint16_t(2222));

    CHECK(parse_ssh_host("[fe80::1]:22", h, p));
    CHECK_EQ(h, std::string("fe80::1"));
    CHECK_EQ(p, uint16_t(22));

    CHECK(parse_ssh_host("[fe80::1]", h, p));
    CHECK_EQ(h, std::string("fe80::1"));
    CHECK_EQ(p, uint16_t(22));

    CHECK(!parse_ssh_host("bad:port:x", h, p));
    CHECK(!parse_ssh_host("", h, p));
    CHECK(!parse_ssh_host("mac.local:", h, p));
    CHECK(!parse_ssh_host("mac.local:0", h, p));
    CHECK(!parse_ssh_host("mac.local:65536", h, p));
    CHECK(!parse_ssh_host("mac.local:22x", h, p));
    CHECK(!parse_ssh_host(":22", h, p));
    CHECK(!parse_ssh_host("[fe80::1]x", h, p));
}

TEST(setup_compose_ssh_host) {
    CHECK_EQ(compose_ssh_host("mac.local", 22), std::string("mac.local"));
    CHECK_EQ(compose_ssh_host("mac.local", 2222), std::string("mac.local:2222"));
    CHECK_EQ(compose_ssh_host("fe80::1", 22), std::string("[fe80::1]"));
    CHECK_EQ(compose_ssh_host("fe80::1", 2222), std::string("[fe80::1]:2222"));

    // Settings store the bare host, so compose → parse must return exactly what was stored.
    const std::pair<const char*, uint16_t> cases[] = {
        {"mac.local", 22}, {"mac.local", 2222}, {"192.168.1.20", 22}, {"fe80::1", 22}, {"fe80::1", 5522}};
    for (const auto& [host, port] : cases) {
        std::string h;
        uint16_t p = 0;
        CHECK(parse_ssh_host(compose_ssh_host(host, port), h, p));
        CHECK_EQ(h, std::string(host));
        CHECK_EQ(p, port);
    }
}
