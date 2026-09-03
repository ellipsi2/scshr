#pragma once
// Minimal SSH client over libssh2 (statically linked; OpenSSL backend — the same libcrypto scshr
// already ships). Used ONLY by the pairing wizard: it never touches the media path.
//
//   * password and keyboard-interactive authentication (macOS sshd offers either),
//   * remote command execution with stdin data + separate stdout/stderr + exit status,
//   * file upload (SCP),
//   * host-key pinning: SHA-256 fingerprint, trust on first use, hard failure if it changes.
#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>

namespace scshr::app {

struct SshTarget {
    std::string host;
    uint16_t port = 22;
    std::string user;
    std::string password;
    // Polled (about once a second) inside every wait loop; true aborts with SshError{Timeout}.
    std::function<bool()> cancelled;
};

struct SshResult {
    int exit_code = -1;          // -1 = the channel closed without an exit status
    std::string stdout_text;
    std::string stderr_text;
};

struct SshError : std::runtime_error {
    enum class Kind { Network, HostKeyChanged, Auth, Protocol, Timeout };
    Kind kind;
    SshError(Kind k, const std::string& what) : std::runtime_error(what), kind(k) {}
};

class SshClient {
public:
    // Connects and authenticates. `expected_hostkey_sha256` (base64, as printed by OpenSSH without
    // the "SHA256:" prefix) empty = trust on first use; the observed fingerprint is available from
    // hostkey_sha256() afterwards. A mismatch throws SshError{HostKeyChanged} before any auth.
    // `log` receives short human-readable progress lines (never the password).
    SshClient(const SshTarget& target, const std::string& expected_hostkey_sha256,
              std::function<void(const std::string&)> log, int connect_timeout_s = 15);
    ~SshClient();
    SshClient(const SshClient&) = delete;
    SshClient& operator=(const SshClient&) = delete;

    std::string hostkey_sha256() const { return hostkey_; }

    // Runs `command` through the remote login shell. `stdin_data` is written in full, then EOF is
    // sent. Blocks until the channel closes or `timeout_s` elapses (→ SshError{Timeout}).
    SshResult exec(const std::string& command, const std::string& stdin_data = {}, int timeout_s = 120);

    // Uploads `data` to `remote_path` (SCP), creating/replacing the file with `mode`.
    void upload(const std::string& remote_path, const std::string& data, int mode = 0644);

private:
    struct Impl;
    Impl* p_ = nullptr;
    std::string hostkey_;
};

// Splits "host", "host:port", "[v6]:port" into host + port (default 22). False on malformed input.
bool parse_ssh_host(const std::string& text, std::string& host, uint16_t& port);
// The inverse: "host", "host:port", or "[v6]:port" when `host` is a bare IPv6 literal.
std::string compose_ssh_host(const std::string& host, uint16_t port);

}  // namespace scshr::app
