#include "app/ssh_client.h"

#include "tunnel/pairing.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <libssh2.h>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>

namespace scshr::app {
namespace {

using Kind = SshError::Kind;

void global_init() {
    static std::once_flag once;
    static bool ok = false;
    std::call_once(once, [] {
        WSADATA wsa = {};
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return;
        ok = libssh2_init(0) == 0;
    });
    if (!ok) throw SshError(Kind::Network, "Windows networking or the SSH library could not be started");
}

// OpenSSH prints SHA-256 fingerprints as unpadded standard base64; normalise both sides so a pin
// written by either spelling still compares equal.
std::string strip_padding(std::string s) {
    while (!s.empty() && s.back() == '=') s.pop_back();
    return s;
}

int64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

// The last libssh2 error as a short sentence (never contains credentials).
std::string session_error(LIBSSH2_SESSION* s) {
    char* msg = nullptr;
    int len = 0;
    const int rc = libssh2_session_last_error(s, &msg, &len, 0);
    std::string text = msg && len > 0 ? std::string(msg, size_t(len)) : std::string("error");
    return text + " (code " + std::to_string(rc) + ")";
}

void kbd_callback(const char*, int, const char*, int, int num_prompts,
                  const LIBSSH2_USERAUTH_KBDINT_PROMPT*, LIBSSH2_USERAUTH_KBDINT_RESPONSE* responses,
                  void** abstract) {
    const auto* pw = static_cast<const std::string*>(*abstract);
    if (!pw) return;
    for (int i = 0; i < num_prompts; ++i) {
        // libssh2 frees these with free(); every prompt gets the same answer (macOS sshd asks once).
        responses[i].text = static_cast<char*>(std::malloc(pw->size() + 1));
        if (!responses[i].text) { responses[i].length = 0; continue; }
        std::memcpy(responses[i].text, pw->data(), pw->size());
        responses[i].text[pw->size()] = '\0';
        responses[i].length = unsigned(pw->size());
    }
}

// Waits until the socket is ready in whichever direction libssh2 is blocked on.
int wait_socket(SOCKET sock, LIBSSH2_SESSION* session, int timeout_ms) {
    fd_set rd, wr;
    FD_ZERO(&rd);
    FD_ZERO(&wr);
    const int dir = libssh2_session_block_directions(session);
    if (dir & LIBSSH2_SESSION_BLOCK_INBOUND) FD_SET(sock, &rd);
    if (dir & LIBSSH2_SESSION_BLOCK_OUTBOUND) FD_SET(sock, &wr);
    if (!dir) FD_SET(sock, &rd);   // no hint: wait for readability
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    return select(0, rd.fd_count ? &rd : nullptr, wr.fd_count ? &wr : nullptr, nullptr, &tv);
}

// Every wait in this file goes through here, so a cancel is never more than a second away.
void throw_if_cancelled(const std::function<bool()>& cancelled) {
    if (cancelled && cancelled()) throw SshError(Kind::Timeout, "Setup was stopped");
}

SOCKET connect_with_timeout(const std::string& host, uint16_t port, int timeout_s,
                            const std::function<bool()>& cancelled) {
    addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* res = nullptr;
    const std::string service = std::to_string(unsigned(port));
    if (getaddrinfo(host.c_str(), service.c_str(), &hints, &res) != 0 || !res)
        throw SshError(Kind::Network, "The name \"" + host + "\" could not be found on the network");

    SOCKET sock = INVALID_SOCKET;
    std::string last = "the Mac did not answer";
    for (addrinfo* a = res; a && sock == INVALID_SOCKET; a = a->ai_next) {
        SOCKET s = socket(a->ai_family, a->ai_socktype, a->ai_protocol);
        if (s == INVALID_SOCKET) continue;
        u_long nb = 1;
        ioctlsocket(s, FIONBIO, &nb);
        const int rc = connect(s, a->ai_addr, int(a->ai_addrlen));
        if (rc == 0) { sock = s; break; }
        if (WSAGetLastError() != WSAEWOULDBLOCK) { last = "the connection was refused"; closesocket(s); continue; }
        int sel = 0;
        for (int waited = 0; waited < timeout_s && sel == 0; ++waited) {
            if (cancelled && cancelled()) { closesocket(s); freeaddrinfo(res); throw_if_cancelled(cancelled); }
            fd_set wr, ex;
            FD_ZERO(&wr); FD_SET(s, &wr);
            FD_ZERO(&ex); FD_SET(s, &ex);
            timeval tv{1, 0};
            sel = select(0, nullptr, &wr, &ex, &tv);
            if (sel > 0 && FD_ISSET(s, &ex)) sel = -1;
        }
        if (sel <= 0) { last = "the Mac did not answer within " + std::to_string(timeout_s) + " seconds"; closesocket(s); continue; }
        int err = 0, len = int(sizeof err);
        getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len);
        if (err != 0) { last = "the connection was refused"; closesocket(s); continue; }
        sock = s;
    }
    freeaddrinfo(res);
    if (sock == INVALID_SOCKET)
        throw SshError(Kind::Network, "Cannot reach " + host + " on port " + std::to_string(unsigned(port)) +
                                          ": " + last + ". Check that the Mac is on and that Remote Login is "
                                          "turned on in System Settings > General > Sharing.");
    u_long blocking = 0;
    ioctlsocket(sock, FIONBIO, &blocking);
    return sock;
}

}  // namespace

struct SshClient::Impl {
    SOCKET sock = INVALID_SOCKET;
    LIBSSH2_SESSION* session = nullptr;
    std::string password;                                  // needed by the keyboard-interactive callback
    std::function<void(const std::string&)> log;
    std::function<bool()> cancelled;
    void say(const std::string& s) const { if (log) log(s); }
    // One wait slice: never longer than a second, so a cancel is noticed promptly.
    void wait(int budget_ms) const {
        throw_if_cancelled(cancelled);
        wait_socket(sock, session, budget_ms > 0 && budget_ms < 1000 ? budget_ms : 1000);
    }
    ~Impl() {
        if (session) {
            libssh2_session_disconnect(session, "bye");
            libssh2_session_free(session);
        }
        if (sock != INVALID_SOCKET) closesocket(sock);
    }
};

SshClient::SshClient(const SshTarget& target, const std::string& expected_hostkey_sha256,
                     std::function<void(const std::string&)> log, int connect_timeout_s) {
    global_init();
    auto* impl = new Impl();
    impl->log = std::move(log);
    impl->password = target.password;
    impl->cancelled = target.cancelled;
    p_ = impl;
    try {
        impl->say("Connecting to " + target.host + " on port " + std::to_string(unsigned(target.port)) + "…");
        impl->sock = connect_with_timeout(target.host, target.port, connect_timeout_s, target.cancelled);

        impl->session = libssh2_session_init();
        if (!impl->session) throw SshError(Kind::Protocol, "The SSH library could not be started");
        libssh2_session_set_blocking(impl->session, 1);
        libssh2_session_set_timeout(impl->session, long(connect_timeout_s) * 1000);
        *libssh2_session_abstract(impl->session) = &impl->password;

        if (libssh2_session_handshake(impl->session, impl->sock) != 0)
            throw SshError(Kind::Protocol, "The Mac did not complete an SSH handshake: " + session_error(impl->session));

        const char* hash = libssh2_hostkey_hash(impl->session, LIBSSH2_HOSTKEY_HASH_SHA256);
        if (!hash) throw SshError(Kind::Protocol, "The Mac did not present an SSH host key");
        hostkey_ = strip_padding(tunnel::base64_std_encode(std::string(hash, 32)));

        if (!expected_hostkey_sha256.empty() && strip_padding(expected_hostkey_sha256) != hostkey_)
            throw SshError(Kind::HostKeyChanged,
                           "The Mac's identity has changed since it was set up. This can mean the Mac was "
                           "reinstalled, or that something else is answering at this address. Set up again "
                           "only if you know why it changed.");
        impl->say("Identity of the Mac: SHA256:" + hostkey_);

        // ── authentication ────────────────────────────────────────────────────────────────
        std::string methods;
        if (const char* list = libssh2_userauth_list(impl->session, target.user.c_str(), unsigned(target.user.size())))
            methods = list;
        if (libssh2_userauth_authenticated(impl->session)) {
            impl->say("The Mac accepted the connection without a password.");
        } else {
            bool authed = false;
            if (methods.empty() || methods.find("password") != std::string::npos) {
                if (libssh2_userauth_password(impl->session, target.user.c_str(), target.password.c_str()) == 0)
                    authed = true;
            }
            if (!authed && (methods.empty() || methods.find("keyboard-interactive") != std::string::npos)) {
                if (libssh2_userauth_keyboard_interactive(impl->session, target.user.c_str(), &kbd_callback) == 0)
                    authed = true;
            }
            if (!authed)
                throw SshError(Kind::Auth, "The Mac rejected the user name or password. Use the name and password "
                                           "of an administrator account on the Mac.");
        }
        impl->say("Signed in as " + target.user + ".");
    } catch (...) {
        delete impl;
        p_ = nullptr;
        throw;
    }
}

SshClient::~SshClient() { delete p_; }

SshResult SshClient::exec(const std::string& command, const std::string& stdin_data, int timeout_s) {
    if (!p_ || !p_->session) throw SshError(Kind::Protocol, "The connection to the Mac was closed");
    LIBSSH2_SESSION* s = p_->session;
    const int64_t deadline = now_ms() + int64_t(timeout_s) * 1000;
    const auto left = [&] { return int(deadline - now_ms()); };
    const auto check_deadline = [&] {
        if (left() <= 0) throw SshError(Kind::Timeout, "The Mac did not finish the step within " +
                                                           std::to_string(timeout_s) + " seconds");
    };

    // Declared before Restore so it is destroyed AFTER it: freeing a channel while the session is
    // still non-blocking can return EAGAIN and leak the channel.
    struct Free {
        LIBSSH2_CHANNEL* c = nullptr;
        ~Free() { if (c) libssh2_channel_free(c); }
    } freer;
    libssh2_session_set_blocking(s, 0);
    struct Restore {
        LIBSSH2_SESSION* s;
        ~Restore() { libssh2_session_set_blocking(s, 1); }
    } restore{s};

    LIBSSH2_CHANNEL* ch = nullptr;
    while (!(ch = libssh2_channel_open_session(s))) {
        if (libssh2_session_last_errno(s) != LIBSSH2_ERROR_EAGAIN)
            throw SshError(Kind::Protocol, "The Mac refused to open a command channel: " + session_error(s));
        check_deadline();
        p_->wait(left());
    }
    freer.c = ch;

    int rc = 0;
    while ((rc = libssh2_channel_exec(ch, command.c_str())) == LIBSSH2_ERROR_EAGAIN) {
        check_deadline();
        p_->wait(left());
    }
    if (rc != 0) throw SshError(Kind::Protocol, "The Mac refused to run the command: " + session_error(s));

    size_t written = 0;
    while (written < stdin_data.size()) {
        const auto n = libssh2_channel_write(ch, stdin_data.data() + written, stdin_data.size() - written);
        if (n == LIBSSH2_ERROR_EAGAIN) { check_deadline(); p_->wait(left()); continue; }
        if (n < 0) throw SshError(Kind::Protocol, "Sending data to the Mac failed: " + session_error(s));
        written += size_t(n);
    }
    while (libssh2_channel_send_eof(ch) == LIBSSH2_ERROR_EAGAIN) {
        check_deadline();
        p_->wait(left());
    }

    SshResult out;
    char buf[8192];
    for (;;) {
        bool progress = false;
        for (int stream = 0; stream < 2; ++stream) {
            for (;;) {
                const auto n = libssh2_channel_read_ex(ch, stream == 0 ? 0 : SSH_EXTENDED_DATA_STDERR, buf, sizeof buf);
                if (n == LIBSSH2_ERROR_EAGAIN || n <= 0) break;
                (stream == 0 ? out.stdout_text : out.stderr_text).append(buf, size_t(n));
                progress = true;
            }
        }
        if (libssh2_channel_eof(ch) == 1) break;
        if (!progress) {
            check_deadline();
            p_->wait(left());
        }
    }

    bool closed = false;
    while (!closed) {
        const int crc = libssh2_channel_close(ch);
        if (crc != LIBSSH2_ERROR_EAGAIN) { closed = crc == 0; break; }
        if (left() <= 0) break;
        p_->wait(left());
    }
    // A channel that never closed has no trustworthy exit status; -1 tells the caller "unfinished".
    out.exit_code = closed ? libssh2_channel_get_exit_status(ch) : -1;
    return out;
}

void SshClient::upload(const std::string& remote_path, const std::string& data, int mode) {
    if (!p_ || !p_->session) throw SshError(Kind::Protocol, "The connection to the Mac was closed");
    LIBSSH2_SESSION* s = p_->session;
    struct Free {
        LIBSSH2_CHANNEL* c = nullptr;
        ~Free() { if (c) libssh2_channel_free(c); }
    } freer;
    libssh2_session_set_blocking(s, 0);
    struct Restore {
        LIBSSH2_SESSION* s;
        ~Restore() { libssh2_session_set_blocking(s, 1); }
    } restore{s};

    LIBSSH2_CHANNEL* ch = nullptr;
    while (!(ch = libssh2_scp_send64(s, remote_path.c_str(), mode, libssh2_int64_t(data.size()), 0, 0))) {
        if (libssh2_session_last_errno(s) != LIBSSH2_ERROR_EAGAIN)
            throw SshError(Kind::Protocol, "Could not copy a file to the Mac (" + remote_path + "): " + session_error(s));
        p_->wait(0);
    }
    freer.c = ch;

    size_t written = 0;
    while (written < data.size()) {
        const auto n = libssh2_channel_write(ch, data.data() + written, data.size() - written);
        if (n == LIBSSH2_ERROR_EAGAIN) { p_->wait(0); continue; }
        if (n < 0) throw SshError(Kind::Protocol, "Copying " + remote_path + " to the Mac failed: " + session_error(s));
        written += size_t(n);
    }
    while (libssh2_channel_send_eof(ch) == LIBSSH2_ERROR_EAGAIN) p_->wait(0);
    while (libssh2_channel_wait_eof(ch) == LIBSSH2_ERROR_EAGAIN) p_->wait(0);
    while (libssh2_channel_wait_closed(ch) == LIBSSH2_ERROR_EAGAIN) p_->wait(0);
}

std::string compose_ssh_host(const std::string& host, uint16_t port) {
    // A bare IPv6 literal needs brackets before a port can be appended unambiguously.
    const std::string h = host.find(':') != std::string::npos ? "[" + host + "]" : host;
    return port == 22 ? h : h + ":" + std::to_string(unsigned(port));
}

bool parse_ssh_host(const std::string& text, std::string& host, uint16_t& port) {
    const auto parse_port = [&](const std::string& p) {
        if (p.empty() || p.size() > 5) return false;
        for (char c : p) if (c < '0' || c > '9') return false;
        const long v = std::strtol(p.c_str(), nullptr, 10);
        if (v < 1 || v > 65535) return false;
        port = uint16_t(v);
        return true;
    };
    host.clear();
    port = 22;
    if (text.empty()) return false;
    if (text[0] == '[') {
        const size_t close = text.find(']');
        if (close == std::string::npos || close == 1) return false;
        host = text.substr(1, close - 1);
        const std::string rest = text.substr(close + 1);
        if (rest.empty()) return true;
        if (rest[0] != ':') return false;
        return parse_port(rest.substr(1));
    }
    const size_t colon = text.find(':');
    if (colon == std::string::npos) { host = text; return !host.empty(); }
    if (text.find(':', colon + 1) != std::string::npos) return false;   // bare IPv6 or junk: require brackets
    host = text.substr(0, colon);
    if (host.empty()) return false;
    return parse_port(text.substr(colon + 1));
}

}  // namespace scshr::app
