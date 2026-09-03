#pragma once
// User-facing settings for the launcher / pairing wizard (non-secret), plus the optional remembered
// Screen Sharing password (Windows Credential Manager, DPAPI-backed, never on disk in clear text).
//
// The settings file is `%ProgramData%\scshr\settings` (same SYSTEM + Administrators ACL as the tunnel
// state) as key=value lines. Unknown keys are ignored so old builds tolerate new fields.
#include <cstdint>
#include <optional>
#include <string>

namespace scshr::app {

struct Settings {
    std::string mac_label;            // friendly name shown in the UI (defaults to ssh_host)
    std::string ssh_host;             // hostname/IP used for SSH and as the WireGuard endpoint
    uint16_t ssh_port = 22;
    std::string ssh_user;             // macOS account used for SSH + sudo during setup
    std::string ssh_hostkey_sha256;   // base64 SHA-256 of the Mac's SSH host key (trust on first use)
    std::string screen_user;          // macOS account used for Screen Sharing login (defaults to ssh_user)
    bool remember_password = false;   // Screen Sharing password kept in Credential Manager
    bool audio = true;
    std::string display = "all";      // "all" | "combined" | "<N>"
    bool separate_session = true;     // log in to an own virtual session; false = share the console user's screen
    bool paired = false;              // set once the wizard completed end to end
};

// Pure (unit-tested): text <-> struct. Serialisation is deterministic, one `key=value` per line.
std::string serialize_settings(const Settings& s);
Settings parse_settings(const std::string& text);

std::wstring settings_path();
std::optional<Settings> load_settings();   // nullopt when the file is absent or has no fields
void save_settings(const Settings& s);     // throws std::runtime_error on I/O failure
void delete_settings();

// Credential Manager (per Windows user). `target` is a stable name such as "scshr/screen-sharing".
bool credential_store(const std::string& target, const std::string& user, const std::string& secret);
std::optional<std::string> credential_load(const std::string& target);
void credential_delete(const std::string& target);

inline constexpr const char* kScreenSharingCredential = "scshr/screen-sharing";

}  // namespace scshr::app
