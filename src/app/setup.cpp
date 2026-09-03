#include "app/setup.h"

#include "app/ssh_client.h"
#include "app/tunnel_cli.h"
#include "tunnel/win_tunnel.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>

#include <chrono>
#include <cstdlib>
#include <ctime>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace scshr::app {
namespace {

using namespace scshr::tunnel;

constexpr int kSteps = 8;
constexpr uint16_t kRfbPort = 5900;
const char* const kHelperFiles[] = {"scshr-macos-tunnel.sh", "scshr-tunnel-darwin-arm64", "scshr-tunnel-darwin-amd64"};

int64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(a, b - a);
}

// POSIX single-quoting: safe for every byte, including the ones a shell would otherwise expand.
std::string sh_quote(const std::string& s) {
    std::string out = "'";
    for (char c : s) { if (c == '\'') out += "'\\''"; else out += c; }
    return out + "'";
}

// A sudo refusal reads very differently from a helper failure; say the useful thing.
bool looks_like_sudo_refusal(const SshResult& r) {
    const std::string all = r.stdout_text + "\n" + r.stderr_text;
    return all.find("is not in the sudoers") != std::string::npos ||
           all.find("Sorry, try again") != std::string::npos ||
           all.find("incorrect password attempt") != std::string::npos ||
           all.find("no password was provided") != std::string::npos;
}

std::string tail(const std::string& text, size_t lines) {
    std::vector<std::string> v;
    size_t pos = 0;
    while (pos <= text.size()) {
        const size_t nl = text.find('\n', pos);
        const std::string l = trim(text.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos));
        if (!l.empty()) v.push_back(l);
        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
    std::string out;
    for (size_t i = v.size() > lines ? v.size() - lines : 0; i < v.size(); ++i) {
        if (!out.empty()) out += " / ";
        out += v[i];
    }
    return out;
}

int major_version(const std::string& v) {
    return int(std::strtol(v.c_str(), nullptr, 10));
}

// Blocking connect with a deadline (the RFB probe only ever talks to the tunnel address).
SOCKET connect_timed(const std::string& ip, uint16_t port, int timeout_ms, const std::function<bool()>& cancelled) {
    addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST;
    addrinfo* res = nullptr;
    if (getaddrinfo(ip.c_str(), std::to_string(unsigned(port)).c_str(), &hints, &res) != 0 || !res) return INVALID_SOCKET;
    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) { freeaddrinfo(res); return INVALID_SOCKET; }
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    const int rc = connect(s, res->ai_addr, int(res->ai_addrlen));
    bool ok = rc == 0;
    if (!ok && WSAGetLastError() == WSAEWOULDBLOCK) {
        // Waited in short slices so a cancel during the probe is noticed quickly.
        for (int rest = timeout_ms; rest > 0 && !ok; rest -= 250) {
            if (cancelled && cancelled()) break;
            fd_set wr;
            FD_ZERO(&wr);
            FD_SET(s, &wr);
            timeval tv{0, (rest < 250 ? rest : 250) * 1000};
            const int sel = select(0, nullptr, &wr, nullptr, &tv);
            if (sel < 0) break;
            if (sel == 0) continue;
            int err = 0, len = int(sizeof err);
            getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len);
            ok = err == 0;
            break;
        }
    }
    freeaddrinfo(res);
    if (!ok) { closesocket(s); return INVALID_SOCKET; }
    u_long blocking = 0;
    ioctlsocket(s, FIONBIO, &blocking);
    return s;
}

struct Cancelled : std::runtime_error { Cancelled() : std::runtime_error("cancelled") {} };

std::string headline_for(const SshError& e) {
    switch (e.kind) {
        case SshError::Kind::Auth: return "The Mac rejected the user name or password";
        case SshError::Kind::HostKeyChanged: return "The Mac's identity has changed";
        case SshError::Kind::Timeout: return "The Mac took too long to answer";
        case SshError::Kind::Network: return "This PC cannot reach the Mac";
        default: return "The Mac did not respond as expected";
    }
}

}  // namespace

// ── verification primitives ───────────────────────────────────────────────────────────────

bool ping_peer(const std::string& ip, int total_ms, const std::function<bool()>& cancelled) {
    in_addr addr = {};
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) return false;
    const HANDLE h = IcmpCreateFile();
    if (h == INVALID_HANDLE_VALUE) return false;
    char payload[32] = {};
    std::vector<char> reply(sizeof(ICMP_ECHO_REPLY) + sizeof payload + 16);
    const int64_t deadline = now_ms() + total_ms;
    bool ok = false;
    do {
        if (cancelled && cancelled()) break;
        const int wait = int(deadline - now_ms());
        const DWORD n = IcmpSendEcho(h, addr.S_un.S_addr, payload, sizeof payload, nullptr, reply.data(),
                                     DWORD(reply.size()), DWORD(wait > 1000 ? 1000 : (wait > 0 ? wait : 1)));
        if (n > 0 && reinterpret_cast<ICMP_ECHO_REPLY*>(reply.data())->Status == IP_SUCCESS) { ok = true; break; }
    } while (now_ms() < deadline);
    IcmpCloseHandle(h);
    return ok;
}

bool probe_rfb(const std::string& ip, uint16_t port, std::string& banner, int timeout_ms,
               const std::function<bool()>& cancelled) {
    banner.clear();
    const SOCKET s = connect_timed(ip, port, timeout_ms, cancelled);
    if (s == INVALID_SOCKET) return false;
    DWORD to = DWORD(timeout_ms);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&to), sizeof to);
    char buf[16] = {};
    const int n = recv(s, buf, 12, 0);
    closesocket(s);
    if (n < 4) return false;
    banner = trim(std::string(buf, size_t(n)));
    return banner.rfind("RFB ", 0) == 0;
}

// ── parsing (unit-tested) ─────────────────────────────────────────────────────────────────

std::string extract_server_code(const std::string& text) {
    static const std::string kTag = "SCST1:";
    std::string best;
    size_t pos = 0;
    while ((pos = text.find(kTag, pos)) != std::string::npos) {
        size_t end = pos + kTag.size();
        while (end < text.size()) {
            const char c = text[end];
            const bool body = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
            if (!body) break;
            ++end;
        }
        const std::string candidate = text.substr(pos, end - pos);
        ServerDescriptor d;
        std::string why;
        if (decode_server(candidate, d, why)) best = candidate;   // keep the last valid one
        pos = end;
    }
    return best;
}

Preflight parse_preflight(const std::string& text) {
    Preflight p;
    size_t pos = 0;
    while (pos <= text.size()) {
        const size_t nl = text.find('\n', pos);
        const std::string line = trim(text.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos));
        if (nl == std::string::npos) pos = text.size() + 1; else pos = nl + 1;
        const size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        const std::string k = trim(line.substr(0, eq)), v = trim(line.substr(eq + 1));
        if (k == "macos_version") p.macos_version = v;
        else if (k == "arch") p.arch = v;
        else if (k == "screen_sharing") p.screen_sharing = v;
        else if (k == "pf_conf") p.pf_conf = v;
        else if (k == "helper") p.helper = v;
        else if (k == "firewall") p.firewall = v;
    }
    p.ok = !p.macos_version.empty() && !p.arch.empty();
    if (!p.ok) p.error = "The Mac did not report what it is running.";
    return p;
}

// ── the wizard ────────────────────────────────────────────────────────────────────────────

SetupOutcome run_setup(const SetupRequest& req, const SetupProgress& pr) {
    SetupOutcome out;
    const auto say = [&](const std::string& s) { if (pr.on_log) pr.on_log(s); };
    const auto step = [&](int n, const char* title) {
        if (pr.cancelled && pr.cancelled()) throw Cancelled();
        if (pr.on_step) pr.on_step(n, kSteps, title);
    };

    std::unique_ptr<SshClient> ssh;
    std::string tmpdir;
    // True between a successful `init` on the Mac and a completed pairing. In that window the Mac's
    // PF anchor is already blocking Screen Sharing for every other device while nothing can yet use
    // it, so any failure has to put the Mac back.
    bool mac_needs_rollback = false;
    // Destroyed before `ssh`, so the remote temp directory goes away on every path, failures included.
    struct Cleanup {
        std::function<void()> f;
        ~Cleanup() { if (f) try { f(); } catch (...) {} }
    } cleanup;

    const std::string pw_stdin = req.password + "\n";
    const auto run_helper = [&](const std::string& args, int timeout_s) {
        return ssh->exec("sudo -S -p '' /bin/bash " + sh_quote(tmpdir + "/scshr-macos-tunnel.sh") + " " + args,
                         pw_stdin, timeout_s);
    };
    const auto require = [&](const SshResult& r, const char* what) {
        if (r.exit_code == 0) return;
        if (looks_like_sudo_refusal(r)) throw std::runtime_error("The Mac account must be an administrator (sudo)");
        if (r.exit_code < 0) throw std::runtime_error(std::string(what) + ": the step did not finish cleanly");
        const std::string why = tail(r.stderr_text.empty() ? r.stdout_text : r.stderr_text, 3);
        throw std::runtime_error(std::string(what) + (why.empty() ? "" : ": " + why));
    };
    // Best-effort undo of step 4, using the SSH session and temp dir that are still open.
    const auto rollback_mac = [&]() -> std::string {
        try {
            const SshResult r = run_helper("uninstall", 300);
            if (r.exit_code == 0) return "The Mac was returned to how it was.";
        } catch (...) {
        }
        return "The Mac could not be put back, so it still allows Screen Sharing only through this PC. "
               "To undo that, run this on the Mac: sudo /usr/local/libexec/scshr-macos-tunnel.sh uninstall";
    };

    try {
        if (!is_elevated())
            throw std::runtime_error("Setting up the tunnel needs Administrator rights on this PC.");

        std::string host;
        uint16_t port = 22;
        if (!parse_ssh_host(trim(req.ssh_host), host, port))
            throw std::runtime_error("\"" + req.ssh_host + "\" is not a valid Mac address. Use a name like "
                                     "\"my-mac.local\", or \"my-mac.local:2222\" for a different SSH port.");
        if (trim(req.ssh_user).empty())
            throw std::runtime_error("Enter the name of an administrator account on the Mac.");

        // A pinned host key belongs to one Mac at one address. Pointing setup at a different machine
        // is a new trust decision, not a key change, so only pin when the address is the stored one.
        const auto stored = load_settings();
        const bool same_mac = stored && stored->ssh_host == host && stored->ssh_port == port;
        const std::string expected = same_mac ? req.expected_hostkey : std::string();

        // 1 ── connect
        step(1, "Connecting to the Mac");
        SshTarget t;
        t.host = host;
        t.port = port;
        t.user = trim(req.ssh_user);
        t.password = req.password;
        t.cancelled = pr.cancelled;
        ssh = std::make_unique<SshClient>(t, expected, [&](const std::string& l) { say(l); });
        out.hostkey_sha256 = ssh->hostkey_sha256();

        // 2 ── upload the helper bundle
        step(2, "Copying the helper to the Mac");
        const SshResult mk = ssh->exec("mktemp -d /tmp/scshr-setup.XXXXXX", {}, 30);
        tmpdir = trim(mk.stdout_text);
        if (mk.exit_code != 0 || tmpdir.rfind("/tmp/scshr-setup.", 0) != 0)
            throw std::runtime_error("The Mac would not create a temporary folder for the setup files.");
        cleanup.f = [&ssh, tmpdir] {
            if (ssh) ssh->exec("rm -rf " + sh_quote(tmpdir), {}, 30);
        };
        ssh->exec("chmod 700 " + sh_quote(tmpdir), {}, 30);

        const std::wstring local = exe_dir() + L"\\mac\\";
        for (const char* name : kHelperFiles) {
            const auto blob = read_file(local + widen(name));
            if (!blob)
                throw std::runtime_error("The macOS helper files are missing next to scshr.exe (mac\\" +
                                         std::string(name) + "). Reinstall scshr.");
            say(std::string("Copying ") + name + " (" + std::to_string(blob->size() / 1024) + " KB)…");
            ssh->upload(tmpdir + "/" + name, *blob, 0755);
        }
        ssh->exec("chmod 755 " + sh_quote(tmpdir + "/scshr-tunnel-darwin-arm64") + " " +
                      sh_quote(tmpdir + "/scshr-tunnel-darwin-amd64") + " " +
                      sh_quote(tmpdir + "/scshr-macos-tunnel.sh"), {}, 30);

        // 3 ── preflight
        step(3, "Checking the Mac");
        const SshResult pfr = run_helper("preflight", 120);
        const Preflight pf = parse_preflight(pfr.stdout_text);
        if (pfr.exit_code != 0 && looks_like_sudo_refusal(pfr))
            throw std::runtime_error("The Mac account must be an administrator (sudo)");
        if (!pf.ok) throw std::runtime_error(pf.error + " " + tail(pfr.stderr_text, 2));
        out.mac_arch = pf.arch;
        out.macos_version = pf.macos_version;
        say("macOS " + pf.macos_version + " on " + pf.arch + ".");
        if (pf.helper == "missing")
            throw std::runtime_error("The tunnel helper for this Mac's processor did not arrive. Try Set up again.");
        if (pf.arch == "x86_64")
            out.warnings.push_back("This is an Intel Mac. High Performance mode needs an Apple silicon Mac, so the "
                                   "picture quality will be lower.");
        if (major_version(pf.macos_version) > 0 && major_version(pf.macos_version) < 14)
            out.warnings.push_back("This Mac runs macOS " + pf.macos_version +
                                   ". High Performance screen sharing needs macOS 14 or newer.");
        if (pf.firewall == "on")
            out.warnings.push_back("The Mac's firewall is on; scshr registered its helper with it. If the connection "
                                   "test fails, check System Settings > Network > Firewall.");

        // 4 ── build the Mac half
        step(4, "Setting up the Mac");
        const std::string endpoint = req.endpoint_override.empty() ? host : req.endpoint_override;
        const SshResult initr = run_helper("init --endpoint " + sh_quote(endpoint) +
                                              " --listen-port " + std::to_string(unsigned(req.listen_port)),
                                          300);
        require(initr, "The Mac could not set up its side of the tunnel");
        mac_needs_rollback = true;
        const std::string server_code = extract_server_code(initr.stdout_text);
        if (server_code.empty())
            throw std::runtime_error("The Mac did not return a pairing code. " + tail(initr.stdout_text, 3));
        say("The Mac produced its pairing code.");

        // 5 ── build the Windows half
        step(5, "Setting up this PC");
        std::string report;
        const std::string client_code = install_windows_tunnel(server_code, &report);
        say(report);

        ServerDescriptor srv;
        std::string why;
        decode_server(server_code, srv, why);   // already validated by install_windows_tunnel
        const std::string mac_ip = srv.mac_ip.empty() ? std::string(kDefaultMacTunnelIp) : srv.mac_ip;

        // 6 ── pair
        step(6, "Pairing");
        require(run_helper("pair " + sh_quote(client_code), 120), "The Mac would not accept this PC as a peer");

        // Both halves exist and trust each other: this is the state worth keeping even if the tunnel
        // turns out to be unreachable, so save it now and stop undoing the Mac.
        mac_needs_rollback = false;
        Settings s = stored.value_or(Settings{});
        s.paired = true;
        s.ssh_host = host;
        s.ssh_port = port;
        s.ssh_user = t.user;
        if (s.screen_user.empty()) s.screen_user = t.user;
        s.mac_label = host;   // follows the Mac actually paired, so a re-run cannot keep a stale label
        s.ssh_hostkey_sha256 = out.hostkey_sha256;
        save_settings(s);

        // 7 ── Screen Sharing
        step(7, "Turning on Screen Sharing");
        const SshResult ssr = run_helper("enable-screen-sharing", 180);
        const bool ss_enabled = ssr.stdout_text.find("screen_sharing=enabled") != std::string::npos;

        // 8 ── verify
        step(8, "Testing the connection");
        say("Waking the tunnel…");
        const bool pings = ping_peer(mac_ip, 20000, pr.cancelled);   // the first echo also starts the handshake
        TunnelStatus ts;
        std::string status_err;
        if (query_status(ts, status_err)) out.handshake_seen = ts.last_handshake_unix > 0;
        if (pings) say("The Mac answered on the tunnel address.");

        if (!out.handshake_seen) {
            out.ok = false;
            out.headline = "This PC cannot reach the Mac's tunnel port";
            out.detail = "UDP port " + std::to_string(unsigned(req.listen_port)) + " must reach the Mac. If the Mac "
                         "is behind a home router, forward UDP port " + std::to_string(unsigned(req.listen_port)) +
                         " to the Mac and run Set up again.";
            return out;
        }

        std::string banner;
        out.screen_sharing_reachable = probe_rfb(mac_ip, kRfbPort, banner, 3000, pr.cancelled);
        // Only doubt the Mac's Screen Sharing state when nothing actually answered on 5900: Remote
        // Management serves the same port, so a banner is better evidence than the launchd report.
        if (!out.screen_sharing_reachable) {
            if (!ss_enabled)
                out.warnings.push_back("Screen Sharing is still off on the Mac. Turn on \"Screen Sharing\" in System "
                                       "Settings > General > Sharing.");
            out.ok = false;
            out.headline = "The tunnel is working but Screen Sharing did not answer";
            out.detail = "The Mac is reachable, but nothing answered on the screen sharing port. Turn on \"Screen "
                         "Sharing\" in System Settings > General > Sharing on the Mac, then use Check connection.";
            return out;
        }

        out.ok = true;
        out.headline = "Your Mac is ready to use";
        out.detail = "The tunnel is up and the Mac answered on the screen sharing port (" + banner +
                     "). You can start a session now.";
        return out;
    } catch (const Cancelled&) {
        out.ok = false;
        out.headline = "Setup was stopped";
        out.detail = mac_needs_rollback ? rollback_mac() : "Nothing further was changed on the Mac.";
        return out;
    } catch (const SshError& e) {
        out.ok = false;
        // A cancel surfaces from the SSH wait loops as a timeout; report it as the stop it was.
        if (pr.cancelled && pr.cancelled()) {
            out.headline = "Setup was stopped";
            out.detail = mac_needs_rollback ? rollback_mac() : "Nothing further was changed on the Mac.";
            return out;
        }
        out.headline = headline_for(e);
        out.detail = e.what();
        if (mac_needs_rollback) out.detail += " " + rollback_mac();
        return out;
    } catch (const std::exception& e) {
        out.ok = false;
        out.headline = "Setup did not finish";
        out.detail = redact_secrets(e.what());
        if (mac_needs_rollback) out.detail += " " + rollback_mac();
        return out;
    }
}

// ── status ────────────────────────────────────────────────────────────────────────────────

LinkStatus check_link(int timeout_ms) {
    LinkStatus st;
    const auto state = load_state();
    const auto settings = load_settings();
    if (!state) {
        st.problem = "This PC has not been set up yet. Run Set up to connect it to your Mac.";
        return st;
    }
    st.configured = settings.has_value();
    if (!st.configured)
        st.problem = "The tunnel is installed but the Mac details were not saved. Run Set up again.";

    st.service_running = service_state() == ServiceState::Running;
    if (!st.service_running && st.problem.empty())
        st.problem = "The scshr tunnel service is not running on this PC. Run Set up again to repair it.";

    st.peer_pings = ping_peer(state->mac_ip, timeout_ms);

    TunnelStatus ts;
    std::string err;
    if (query_status(ts, err)) {
        st.last_handshake_unix = ts.last_handshake_unix;
        const int64_t age = int64_t(std::time(nullptr)) - ts.last_handshake_unix;
        st.handshake_recent = ts.last_handshake_unix > 0 && age >= 0 && age < 180;
    }

    // An RFB banner is proof the whole path works, so it settles the question before any of the
    // indirect signals (handshake age, launchd state) get to declare a problem.
    st.screen_sharing_reachable = probe_rfb(state->mac_ip, kRfbPort, st.rfb_banner, timeout_ms);
    if (st.screen_sharing_reachable) return st;

    if (st.problem.empty())
        st.problem = st.handshake_recent
                         ? "The tunnel is up but the Mac is not answering Screen Sharing. Turn on \"Screen Sharing\" "
                           "in System Settings > General > Sharing on the Mac."
                         : "This PC cannot reach the Mac's tunnel port. UDP port " +
                               std::to_string(unsigned(state->endpoint_port)) + " must reach the Mac. If the Mac is "
                               "behind a home router, forward UDP port " +
                               std::to_string(unsigned(state->endpoint_port)) + " to the Mac and run Set up again.";
    return st;
}

// ── undo ──────────────────────────────────────────────────────────────────────────────────

std::vector<std::string> run_unpair(const SetupRequest* req, bool reset_identity) {
    std::vector<std::string> lines;
    if (req) {
        try {
            std::string host;
            uint16_t port = 22;
            if (!parse_ssh_host(trim(req->ssh_host), host, port)) throw std::runtime_error("the Mac address is not valid");
            SshTarget t;
            t.host = host;
            t.port = port;
            t.user = trim(req->ssh_user);
            t.password = req->password;
            // Same rule as run_setup: the pin only applies to the Mac it was recorded for.
            const auto stored = load_settings();
            const bool same_mac = stored && stored->ssh_host == host && stored->ssh_port == port;
            SshClient ssh(t, same_mac ? req->expected_hostkey : std::string(),
                          [&](const std::string& l) { lines.push_back(l); });
            const SshResult mk = ssh.exec("mktemp -d /tmp/scshr-setup.XXXXXX", {}, 30);
            const std::string dir = trim(mk.stdout_text);
            if (mk.exit_code != 0 || dir.rfind("/tmp/scshr-setup.", 0) != 0)
                throw std::runtime_error("the Mac would not create a temporary folder");
            ssh.exec("chmod 700 " + sh_quote(dir), {}, 30);
            const auto blob = read_file(exe_dir() + L"\\mac\\scshr-macos-tunnel.sh");
            if (!blob) throw std::runtime_error("the macOS helper script is missing next to scshr.exe");
            ssh.upload(dir + "/scshr-macos-tunnel.sh", *blob, 0755);
            const SshResult r = ssh.exec("sudo -S -p '' /bin/bash " + sh_quote(dir + "/scshr-macos-tunnel.sh") +
                                             " uninstall" + (reset_identity ? " --reset-identity" : ""),
                                         req->password + "\n", 300);
            ssh.exec("rm -rf " + sh_quote(dir), {}, 30);
            const std::string text = tail(r.stdout_text + "\n" + r.stderr_text, 6);
            lines.push_back(r.exit_code == 0 ? "The Mac was reset: " + text
                                             : "The Mac could not be reset: " + text);
        } catch (const std::exception& e) {
            lines.push_back(std::string("The Mac could not be reset: ") + redact_secrets(e.what()));
        }
    }
    try {
        std::vector<std::string> removed;
        uninstall(reset_identity, removed);
        if (removed.empty()) lines.push_back("This PC had nothing to remove.");
        for (const auto& r : removed) lines.push_back("Removed " + r + " from this PC.");
    } catch (const std::exception& e) {
        lines.push_back(std::string("This PC could not be fully cleaned up: ") + redact_secrets(e.what()));
    }
    delete_settings();
    credential_delete(kScreenSharingCredential);
    lines.push_back("The saved Mac details and password were removed from this PC.");
    return lines;
}

}  // namespace scshr::app
