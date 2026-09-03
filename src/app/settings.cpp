#include "app/settings.h"

#include "tunnel/win_tunnel.h"

#include <windows.h>
#include <wincred.h>

#include <cstdlib>
#include <stdexcept>
#include <vector>

namespace scshr::app {
namespace {

using tunnel::narrow;
using tunnel::widen;

std::string trim_ws(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(a, b - a);
}

bool parse_bool(const std::string& v, bool& out) {
    if (v == "1" || v == "true" || v == "yes" || v == "on") { out = true; return true; }
    if (v == "0" || v == "false" || v == "no" || v == "off") { out = false; return true; }
    return false;
}

// Shared by parse_settings() and load_settings(); `recognised` counts the keys we understood so the
// loader can tell "file exists but says nothing" from "file has settings".
Settings parse_into(const std::string& text, int& recognised) {
    Settings s;
    recognised = 0;
    size_t pos = 0;
    while (pos <= text.size()) {
        const size_t nl = text.find('\n', pos);
        const std::string line = trim_ws(text.substr(pos, nl == std::string::npos ? std::string::npos : nl - pos));
        pos = nl == std::string::npos ? text.size() + 1 : nl + 1;
        if (line.empty() || line[0] == '#') continue;
        const size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        const std::string k = trim_ws(line.substr(0, eq));
        const std::string v = trim_ws(line.substr(eq + 1));
        bool hit = true;
        if (k == "mac_label") s.mac_label = v;
        else if (k == "ssh_host") s.ssh_host = v;
        else if (k == "ssh_port") { const long p = std::strtol(v.c_str(), nullptr, 10); if (p > 0 && p < 65536) s.ssh_port = uint16_t(p); else hit = false; }
        else if (k == "ssh_user") s.ssh_user = v;
        else if (k == "ssh_hostkey_sha256") s.ssh_hostkey_sha256 = v;
        else if (k == "screen_user") s.screen_user = v;
        else if (k == "remember_password") hit = parse_bool(v, s.remember_password);
        else if (k == "audio") hit = parse_bool(v, s.audio);
        else if (k == "display") s.display = v;
        else if (k == "paired") hit = parse_bool(v, s.paired);
        else hit = false;   // unknown key: ignored so old builds tolerate new fields
        if (hit) ++recognised;
    }
    return s;
}

}  // namespace

std::string serialize_settings(const Settings& s) {
    std::string t;
    t += "mac_label=" + s.mac_label + "\n";
    t += "ssh_host=" + s.ssh_host + "\n";
    t += "ssh_port=" + std::to_string(unsigned(s.ssh_port)) + "\n";
    t += "ssh_user=" + s.ssh_user + "\n";
    t += "ssh_hostkey_sha256=" + s.ssh_hostkey_sha256 + "\n";
    t += "screen_user=" + s.screen_user + "\n";
    t += std::string("remember_password=") + (s.remember_password ? "1" : "0") + "\n";
    t += std::string("audio=") + (s.audio ? "1" : "0") + "\n";
    t += "display=" + s.display + "\n";
    t += std::string("paired=") + (s.paired ? "1" : "0") + "\n";
    return t;
}

Settings parse_settings(const std::string& text) {
    int n = 0;
    return parse_into(text, n);
}

std::wstring settings_path() { return tunnel::paths().dir + L"\\settings"; }

std::optional<Settings> load_settings() {
    const auto text = tunnel::read_file(settings_path());
    if (!text) return std::nullopt;
    int n = 0;
    Settings s = parse_into(*text, n);
    if (n == 0) return std::nullopt;
    return s;
}

void save_settings(const Settings& s) {
    tunnel::ensure_secure_dir(tunnel::paths().dir);
    tunnel::write_secure_file(settings_path(), serialize_settings(s));
}

void delete_settings() { DeleteFileW(settings_path().c_str()); }

// ── Credential Manager ────────────────────────────────────────────────────────────────────
// The secret is stored as a UTF-16 blob (the spelling every Windows credential UI expects) under
// CRED_TYPE_GENERIC. CRED_PERSIST_LOCAL_MACHINE keeps it out of a roaming profile.

bool credential_store(const std::string& target, const std::string& user, const std::string& secret) {
    const std::wstring wtarget = widen(target), wuser = widen(user), wsecret = widen(secret);
    CREDENTIALW c = {};
    c.Type = CRED_TYPE_GENERIC;
    c.TargetName = const_cast<LPWSTR>(wtarget.c_str());
    c.CredentialBlobSize = DWORD(wsecret.size() * sizeof(wchar_t));
    c.CredentialBlob = reinterpret_cast<LPBYTE>(const_cast<wchar_t*>(wsecret.c_str()));
    c.Persist = CRED_PERSIST_LOCAL_MACHINE;
    if (!wuser.empty()) c.UserName = const_cast<LPWSTR>(wuser.c_str());
    return CredWriteW(&c, 0) != FALSE;
}

std::optional<std::string> credential_load(const std::string& target) {
    PCREDENTIALW c = nullptr;
    if (!CredReadW(widen(target).c_str(), CRED_TYPE_GENERIC, 0, &c)) return std::nullopt;
    std::optional<std::string> out;
    if (c->CredentialBlob && c->CredentialBlobSize >= sizeof(wchar_t))
        out = narrow(std::wstring(reinterpret_cast<const wchar_t*>(c->CredentialBlob),
                                  c->CredentialBlobSize / sizeof(wchar_t)));
    else
        out = std::string();
    SecureZeroMemory(c->CredentialBlob, c->CredentialBlobSize);
    CredFree(c);
    return out;
}

void credential_delete(const std::string& target) {
    CredDeleteW(widen(target).c_str(), CRED_TYPE_GENERIC, 0);
}

}  // namespace scshr::app
