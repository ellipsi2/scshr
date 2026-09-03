#include "app/tunnel_cli.h"

#include "common/log.h"
#include "tunnel/win_tunnel.h"

#include <windows.h>

#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace scshr::app {
namespace {

using namespace scshr::tunnel;

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n' || s[a] == '\'' || s[a] == '"')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n' || s[b - 1] == '\'' || s[b - 1] == '"')) --b;
    return s.substr(a, b - a);
}

std::string prompt_server_code() {
    std::fprintf(stderr, "paste the macOS pairing code (SCST1:...): ");
    std::string line;
    if (!std::getline(std::cin, line)) throw std::runtime_error("no pairing code supplied");
    return trim(line);
}

const char* service_state_name(ServiceState s) {
    switch (s) {
        case ServiceState::Absent: return "not installed";
        case ServiceState::Stopped: return "stopped";
        case ServiceState::StartPending: return "starting";
        case ServiceState::Running: return "running";
        default: return "unknown";
    }
}

std::string handshake_age(int64_t unix_sec) {
    if (unix_sec <= 0) return "never (awaiting the first packet from either side)";
    const int64_t age = int64_t(std::time(nullptr)) - unix_sec;
    char buf[64];
    std::snprintf(buf, sizeof buf, "%lld s ago", static_cast<long long>(age < 0 ? 0 : age));
    return buf;
}

// Writes the human-readable result of an elevated `init` where the non-elevated parent can read it.
void emit(const std::string& path, const std::string& text) {
    if (path.empty()) return;
    FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return;
    std::fwrite(text.data(), 1, text.size(), f);
    std::fclose(f);
}

int cmd_init(int argc, char** argv) {
    std::string server_code, out_path;
    for (int i = 2; i < argc; ++i) {
        const std::string k = argv[i];
        if (k == "--server-code" && i + 1 < argc) server_code = trim(argv[++i]);
        else if (k == "--init-output" && i + 1 < argc) out_path = argv[++i];   // internal: elevated child → parent
        else if (k == "-h" || k == "--help") {
            std::puts("scshr init [--server-code SCST1:...]\n"
                      "  Creates the local WireGuard identity, pairs with the macOS host and installs the\n"
                      "  scshr tunnel service. Repeat runs reconcile the existing configuration.");
            return 0;
        } else {
            std::fprintf(stderr, "unknown argument for init: %s\n", argv[i]);
            return 2;
        }
    }

    validate_components();   // fail before anything is mutated

    if (!is_elevated()) {
        // Collect the pairing code in this console, then do the privileged work in an elevated
        // child and print its result back here so the user never has to chase a second window.
        if (server_code.empty()) server_code = prompt_server_code();
        ServerDescriptor probe;
        std::string why;
        if (!decode_server(server_code, probe, why)) {
            std::fprintf(stderr, "invalid macOS pairing code: %s\n", why.c_str());
            return 2;
        }
        wchar_t tmp_dir[MAX_PATH] = {}, tmp_file[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, tmp_dir);
        if (!GetTempFileNameW(tmp_dir, L"scs", 0, tmp_file)) { std::fprintf(stderr, "cannot create a temporary file\n"); return 1; }
        char narrow_tmp[MAX_PATH * 2] = {};
        WideCharToMultiByte(CP_UTF8, 0, tmp_file, -1, narrow_tmp, sizeof narrow_tmp - 1, nullptr, nullptr);
        std::vector<char*> child;
        std::string a0 = argv[0], a1 = "init", a2 = "--server-code", a4 = "--init-output";
        child = {a0.data(), a1.data(), a2.data(), server_code.data(), a4.data(), narrow_tmp};
        const int rc = relaunch_elevated(int(child.size()), child.data());
        if (FILE* f = _wfopen(tmp_file, L"rb")) {
            char buf[1024];
            size_t n = 0;
            while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) std::fwrite(buf, 1, n, stdout);
            std::fclose(f);
        }
        DeleteFileW(tmp_file);
        return rc;
    }

    if (server_code.empty()) server_code = prompt_server_code();
    ServerDescriptor srv;
    std::string why;
    if (!decode_server(server_code, srv, why)) {
        std::fprintf(stderr, "invalid macOS pairing code: %s\n", why.c_str());
        return 2;
    }

    const Components comps = validate_components();
    bool identity_created = false;
    const KeyPair id = load_or_create_identity(comps, identity_created);

    WindowsTunnelConfig wc;
    wc.private_key = id.private_key;
    wc.win_ip = srv.win_ip;
    wc.peer_public_key = srv.public_key;
    wc.peer_ip = srv.mac_ip;
    wc.endpoint_host = srv.endpoint_host;
    wc.endpoint_port = srv.listen_port;
    const std::string conf = render_windows_conf(wc);

    const ServiceState before = service_state();
    const bool service_existed = before != ServiceState::Absent;
    const auto previous_conf = read_conf();
    bool changed = false;
    try {
        changed = write_conf_if_changed(conf);
        install_service();
        if (changed && before == ServiceState::Running) stop_service();
        if (service_state() != ServiceState::Running) start_service();

        const RouteAudit audit = audit_routes(srv.mac_ip);
        if (!audit.ok()) {
            std::string msg = "tunnel route validation failed:";
            for (const auto& p : audit.problems) msg += "\n  - " + p;
            throw std::runtime_error(msg);
        }
    } catch (...) {
        // Roll back to the pre-init state rather than leaving a half-installed tunnel behind.
        if (!service_existed) { stop_service(); delete_service(); }
        else if (before != ServiceState::Running) stop_service();
        if (changed) restore_conf(previous_conf);
        throw;
    }

    TunnelState st;
    st.local_public_key = id.public_key;
    st.peer_public_key = srv.public_key;
    st.endpoint_host = srv.endpoint_host;
    st.endpoint_port = srv.listen_port;
    st.win_ip = srv.win_ip;
    st.mac_ip = srv.mac_ip;
    save_state(st);

    ClientDescriptor cd;
    cd.public_key = id.public_key;
    cd.win_ip = srv.win_ip;
    const std::string client_code = encode_client(cd);

    TunnelStatus status;
    std::string status_err;
    const bool have_status = query_status(status, status_err);

    std::string report;
    report += "scshr tunnel installed.\n";
    report += "  identity        : " + std::string(identity_created ? "created" : "existing (preserved)") +
              ", fingerprint " + key_fingerprint(id.public_key) + "\n";
    report += "  configuration   : " + std::string(changed ? "written" : "already current") + "\n";
    report += "  " + describe_windows_conf(wc) + "\n";
    report += "  routes          : only " + srv.mac_ip + "/32 via the scshr adapter; default route and DNS unchanged\n";
    report += "  handshake       : " + (have_status ? handshake_age(status.last_handshake_unix)
                                                    : std::string("unavailable (") + status_err + ")") + "\n";
    if (!have_status || status.last_handshake_unix == 0)
        report += "  the tunnel is installed and awaiting peer authorization on the Mac.\n";
    report += "\nGive this to the Mac:\n\n    sudo ./tools/scshr-macos-tunnel.sh pair '" + client_code + "'\n\n";
    std::fputs(report.c_str(), stdout);
    emit(out_path, report);
    return 0;
}

int cmd_status() {
    // The pairing state and the WireGuard driver are readable only by SYSTEM and Administrators,
    // so an unelevated console cannot tell "not configured" from "not allowed to look".
    if (!is_elevated()) {
        std::puts("scshr tunnel: status needs Administrator (the pairing state and the WireGuard\n"
                  "             driver are restricted to SYSTEM and Administrators)");
        return 1;
    }
    const auto state = load_state();
    if (!state) {
        std::puts("scshr tunnel: not configured (run `scshr init`)");
        return 1;
    }
    const ServiceState svc = service_state();
    std::printf("scshr tunnel\n");
    std::printf("  state           : %s\n", service_state_name(svc));
    std::printf("  local address   : %s/32 (fingerprint %s)\n", state->win_ip.c_str(), key_fingerprint(state->local_public_key).c_str());
    std::printf("  peer address    : %s/32 (fingerprint %s)\n", state->mac_ip.c_str(), key_fingerprint(state->peer_public_key).c_str());
    std::printf("  public endpoint : %s:%u\n", state->endpoint_host.c_str(), unsigned(state->endpoint_port));

    TunnelStatus st;
    std::string err;
    if (query_status(st, err)) {
        std::printf("  handshake       : %s\n", handshake_age(st.last_handshake_unix).c_str());
        std::printf("  transfer        : %llu B received / %llu B sent\n",
                    static_cast<unsigned long long>(st.rx_bytes), static_cast<unsigned long long>(st.tx_bytes));
        std::printf("  peer allowed-ips: %s\n", st.allowed_ip.empty() ? "(none)" : st.allowed_ip.c_str());
        std::printf("  keepalive       : %u s\n", unsigned(st.persistent_keepalive));
        if (!st.peer_public_key.empty() && st.peer_public_key != state->peer_public_key)
            std::printf("  WARNING         : the running tunnel is bound to a different peer than the stored pairing\n");
    } else {
        std::printf("  handshake       : unavailable (%s)\n", err.c_str());
    }

    const RouteAudit audit = audit_routes(state->mac_ip);
    std::printf("  route validation: %s\n", audit.ok() ? "ok (peer /32 only, default route and DNS untouched)" : "FAILED");
    for (const auto& p : audit.problems) std::printf("      - %s\n", p.c_str());
    std::printf("  isolation       : macOS Screen Sharing exposure is enforced by the Mac PF anchor\n"
                "                    (`sudo ./tools/scshr-macos-tunnel.sh status` on the Mac)\n");
    return audit.ok() && svc == ServiceState::Running ? 0 : 1;
}

int cmd_tunnel(int argc, char** argv) {
    const std::string sub = argc > 2 ? argv[2] : "";
    if (sub == "uninstall") {
        bool reset = false;
        for (int i = 3; i < argc; ++i) {
            if (std::string(argv[i]) == "--reset-identity") reset = true;
            else { std::fprintf(stderr, "unknown argument: %s\n", argv[i]); return 2; }
        }
        if (!is_elevated()) return relaunch_elevated(argc, argv);
        std::vector<std::string> removed;
        uninstall(reset, removed);
        if (removed.empty()) std::puts("scshr tunnel: nothing to remove");
        for (const auto& r : removed) std::printf("removed %s\n", r.c_str());
        if (!reset) std::puts("identity keys preserved (use --reset-identity to discard them)");
        std::puts("unrelated WireGuard tunnels, software and firewall state were not touched");
        return 0;
    }
    if (sub == "status") return cmd_status();
    std::puts("scshr tunnel status | uninstall [--reset-identity]");
    return sub.empty() ? 0 : 2;
}

}  // namespace

bool run_tunnel_command(int argc, char** argv, int& exit_code) {
    if (argc < 2) return false;
    const std::string cmd = argv[1];
    try {
        if (cmd == "init") { exit_code = cmd_init(argc, argv); return true; }
        if (cmd == "status") { exit_code = cmd_status(); return true; }
        if (cmd == "tunnel") { exit_code = cmd_tunnel(argc, argv); return true; }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "scshr %s failed: %s\n", cmd.c_str(), redact_secrets(e.what()).c_str());
        exit_code = 1;
        return true;
    }
    return false;
}

std::string resolve_session_host(const std::string& requested_host, bool direct) {
    if (direct) {
        LOG_WARN("tunnel", "--direct: bypassing the scshr tunnel (development mode; never a production fallback)");
        return requested_host;
    }
    // Verifying the live tunnel (peer key, AllowedIPs) means querying the WireGuard driver, which
    // only Administrators may open — so a production session cannot run unelevated at all.
    if (!is_elevated())
        throw std::runtime_error("a tunnel session needs Administrator: verifying the paired peer requires the "
                                 "WireGuard driver and the pairing state, both restricted to SYSTEM and "
                                 "Administrators — start scshr from an elevated console (or pass --direct for a "
                                 "development session)");
    const auto state = load_state();
    if (!state) throw std::runtime_error("scshr tunnel is not configured — run `scshr init` (or pass --direct for a development session)");
    if (!requested_host.empty() && requested_host != state->mac_ip)
        throw std::runtime_error("--host " + requested_host + " is not the paired tunnel address " + state->mac_ip +
                                 " — scshr never falls back to a public or LAN address (use --direct to override for development)");
    if (service_state() != ServiceState::Running)
        throw std::runtime_error("the scshr tunnel service is not running — run `scshr init` to repair it");

    const RouteAudit audit = audit_routes(state->mac_ip);
    if (!audit.ok()) {
        std::string msg = "the scshr tunnel failed route validation:";
        for (const auto& p : audit.problems) msg += "\n  - " + p;
        throw std::runtime_error(msg);
    }

    TunnelStatus st;
    std::string err;
    if (!query_status(st, err)) throw std::runtime_error("the scshr tunnel is not usable: " + err);
    if (st.peer_public_key.empty() || st.peer_public_key != state->peer_public_key)
        throw std::runtime_error("the running tunnel is bound to a different peer than the stored pairing — refusing to connect");
    if (st.allowed_ip != state->mac_ip + "/32")
        throw std::runtime_error("the running tunnel allows " + (st.allowed_ip.empty() ? std::string("nothing") : st.allowed_ip) +
                                 " instead of exactly " + state->mac_ip + "/32 — refusing to connect");

    LOG_INFO("tunnel", "session via scshr tunnel: %s -> %s (peer %s, last handshake %s)",
             state->win_ip.c_str(), state->mac_ip.c_str(), key_fingerprint(state->peer_public_key).c_str(),
             handshake_age(st.last_handshake_unix).c_str());
    return state->mac_ip;
}

}  // namespace scshr::app
