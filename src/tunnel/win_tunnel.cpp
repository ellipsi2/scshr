#include "tunnel/win_tunnel.h"

#include "common/log.h"

#include <winsock2.h>   // must precede iphlpapi.h for the netioapi (route table) declarations
#include <ws2tcpip.h>
#include <windows.h>

#include <aclapi.h>
#include <dpapi.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <sddl.h>
#include <shellapi.h>
#include <shlobj.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

#pragma comment(lib, "iphlpapi.lib")

namespace scshr::tunnel {
namespace {

// SYSTEM and the local Administrators group, full control, inheritable, DACL protected from
// inheritance so nothing an installer left on %ProgramData% widens it.
constexpr const wchar_t* kSecureSddl = L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
constexpr const wchar_t* kServiceName = L"WireGuardTunnel$scshr";
constexpr const wchar_t* kServiceDisplay = L"scshr WireGuard Tunnel";
constexpr const wchar_t* kUapiPipe = L"\\\\.\\pipe\\ProtectedPrefix\\Administrators\\WireGuard\\scshr";

[[noreturn]] void fail(const std::string& what, DWORD err = GetLastError()) {
    char buf[256] = {};
    FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, err,
                   MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buf, sizeof buf - 1, nullptr);
    for (char* p = buf; *p; ++p) if (*p == '\r' || *p == '\n') *p = ' ';
    throw std::runtime_error(what + " (0x" + [&] { char h[16]; snprintf(h, sizeof h, "%08lx", err); return std::string(h); }() + ": " + buf + ")");
}

std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), int(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(size_t(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), int(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), int(s.size()), nullptr, 0);
    std::wstring w(size_t(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), int(s.size()), w.data(), n);
    return w;
}

std::wstring exe_path() {
    std::wstring buf(MAX_PATH, L'\0');
    for (;;) {
        const DWORD n = GetModuleFileNameW(nullptr, buf.data(), DWORD(buf.size()));
        if (n == 0) fail("GetModuleFileName failed");
        if (n < buf.size()) { buf.resize(n); return buf; }
        buf.resize(buf.size() * 2);
    }
}

std::wstring exe_dir() {
    std::wstring p = exe_path();
    const size_t slash = p.find_last_of(L"\\/");
    return slash == std::wstring::npos ? L"." : p.substr(0, slash);
}

struct SecurityAttributes {
    SECURITY_ATTRIBUTES sa{};
    PSECURITY_DESCRIPTOR sd = nullptr;
    SecurityAttributes() {
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(kSecureSddl, SDDL_REVISION_1, &sd, nullptr))
            fail("building the scshr security descriptor failed");
        sa.nLength = sizeof sa;
        sa.lpSecurityDescriptor = sd;
        sa.bInheritHandle = FALSE;
    }
    ~SecurityAttributes() { if (sd) LocalFree(sd); }
    SecurityAttributes(const SecurityAttributes&) = delete;
    SecurityAttributes& operator=(const SecurityAttributes&) = delete;
};

// Re-applies the restrictive DACL to an existing path (first run may have created it differently).
void harden(const std::wstring& path, SE_OBJECT_TYPE type) {
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(kSecureSddl, SDDL_REVISION_1, &sd, nullptr))
        fail("building the scshr security descriptor failed");
    PACL dacl = nullptr;
    BOOL present = FALSE, defaulted = FALSE;
    const bool got = GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) && present;
    const DWORD rc = got ? SetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), type,
                                                 DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                                 nullptr, nullptr, dacl, nullptr)
                         : ERROR_INVALID_PARAMETER;
    LocalFree(sd);
    if (rc != ERROR_SUCCESS) fail("restricting permissions on " + narrow(path) + " failed", rc);
}

void ensure_secure_dir(const std::wstring& dir) {
    SecurityAttributes sa;
    if (!CreateDirectoryW(dir.c_str(), &sa.sa)) {
        const DWORD err = GetLastError();
        if (err != ERROR_ALREADY_EXISTS) fail("creating " + narrow(dir) + " failed", err);
        harden(dir, SE_FILE_OBJECT);
    }
}

void write_secure_file(const std::wstring& path, const std::string& data) {
    SecurityAttributes sa;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, &sa.sa, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) fail("writing " + narrow(path) + " failed");
    DWORD written = 0;
    const BOOL ok = WriteFile(h, data.data(), DWORD(data.size()), &written, nullptr) && written == data.size();
    const DWORD err = GetLastError();
    CloseHandle(h);
    if (!ok) fail("writing " + narrow(path) + " failed", err);
    harden(path, SE_FILE_OBJECT);
}

std::optional<std::string> read_file(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return std::nullopt;
    std::string out;
    char buf[4096];
    DWORD n = 0;
    while (ReadFile(h, buf, sizeof buf, &n, nullptr) && n) out.append(buf, n);
    CloseHandle(h);
    return out;
}

std::string dpapi_protect(const std::string& plain) {
    DATA_BLOB in{DWORD(plain.size()), reinterpret_cast<BYTE*>(const_cast<char*>(plain.data()))}, out{};
    if (!CryptProtectData(&in, L"scshr WireGuard identity", nullptr, nullptr, nullptr, CRYPTPROTECT_LOCAL_MACHINE, &out))
        fail("DPAPI protect failed");
    std::string s(reinterpret_cast<char*>(out.pbData), out.cbData);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return s;
}

std::string dpapi_unprotect(const std::string& blob) {
    DATA_BLOB in{DWORD(blob.size()), reinterpret_cast<BYTE*>(const_cast<char*>(blob.data()))}, out{};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_LOCAL_MACHINE, &out))
        fail("DPAPI unprotect failed (identity unreadable on this machine)");
    std::string s(reinterpret_cast<char*>(out.pbData), out.cbData);
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return s;
}

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\r' || s[a] == '\n' || s[a] == '\t')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\r' || s[b - 1] == '\n' || s[b - 1] == '\t')) --b;
    return s.substr(a, b - a);
}

struct ScHandle {
    SC_HANDLE h = nullptr;
    explicit ScHandle(SC_HANDLE x = nullptr) : h(x) {}
    ~ScHandle() { if (h) CloseServiceHandle(h); }
    ScHandle(const ScHandle&) = delete;
    ScHandle& operator=(const ScHandle&) = delete;
    operator SC_HANDLE() const { return h; }
};

std::wstring service_command() {
    return L"\"" + exe_path() + L"\" /wireguard-service \"" + paths().conf + L"\"";
}

bool luid_for_tunnel(NET_LUID& luid) {
    return ConvertInterfaceAliasToLuid(widen(kTunnelName).c_str(), &luid) == NO_ERROR;
}

bool sockaddr_from_ipv4(const std::string& ip, SOCKADDR_INET& sa) {
    ZeroMemory(&sa, sizeof sa);
    sa.si_family = AF_INET;
    return InetPtonW(AF_INET, widen(ip).c_str(), &sa.Ipv4.sin_addr) == 1;
}

bool best_route_luid(const std::string& ip, NET_LUID& out_luid, uint8_t& out_prefix) {
    SOCKADDR_INET dest{};
    if (!sockaddr_from_ipv4(ip, dest)) return false;
    MIB_IPFORWARD_ROW2 row{};
    SOCKADDR_INET src{};
    if (GetBestRoute2(nullptr, 0, nullptr, &dest, 0, &row, &src) != NO_ERROR) return false;
    out_luid = row.InterfaceLuid;
    out_prefix = row.DestinationPrefix.PrefixLength;
    return true;
}

}  // namespace

Paths paths() {
    static Paths p = [] {
        PWSTR pd = nullptr;
        if (FAILED(SHGetKnownFolderPath(FOLDERID_ProgramData, 0, nullptr, &pd))) fail("locating %ProgramData% failed");
        Paths q;
        q.dir = std::wstring(pd) + L"\\scshr";
        CoTaskMemFree(pd);
        q.conf = q.dir + L"\\" + widen(kTunnelName) + L".conf";
        q.identity = q.dir + L"\\identity.dpapi";
        q.pubkey = q.dir + L"\\identity.pub";
        q.state = q.dir + L"\\tunnel.state";
        return q;
    }();
    return p;
}

bool is_elevated() {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION e{};
    DWORD n = 0;
    const bool ok = GetTokenInformation(tok, TokenElevation, &e, sizeof e, &n) && e.TokenIsElevated;
    CloseHandle(tok);
    return ok;
}

int relaunch_elevated(int argc, char** argv) {
    std::wstring args;
    for (int i = 1; i < argc; ++i) {
        if (i > 1) args += L' ';
        const std::wstring a = widen(argv[i]);
        args += a.find(L' ') == std::wstring::npos ? a : (L"\"" + a + L"\"");
    }
    SHELLEXECUTEINFOW si{};
    si.cbSize = sizeof si;
    si.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    si.lpVerb = L"runas";
    const std::wstring exe = exe_path();
    si.lpFile = exe.c_str();
    si.lpParameters = args.c_str();
    si.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&si)) {
        const DWORD err = GetLastError();
        if (err == ERROR_CANCELLED) throw std::runtime_error("elevation was declined — scshr init needs Administrator to install the tunnel service");
        fail("relaunching elevated failed", err);
    }
    WaitForSingleObject(si.hProcess, INFINITE);
    DWORD code = 1;
    GetExitCodeProcess(si.hProcess, &code);
    CloseHandle(si.hProcess);
    return int(code);
}

Components validate_components() {
    Components c;
    c.tunnel_dll = exe_dir() + L"\\tunnel.dll";
    c.wireguard_dll = exe_dir() + L"\\wireguard.dll";
    for (const std::wstring* p : {&c.tunnel_dll, &c.wireguard_dll}) {
        if (GetFileAttributesW(p->c_str()) == INVALID_FILE_ATTRIBUTES)
            throw std::runtime_error("bundled WireGuard component missing: " + narrow(*p) +
                                     "\n  run tools/fetch_deps.ps1 (pins WireGuardNT 1.1 + wireguard-windows v0.6.1) and rebuild");
    }
    return c;
}

KeyPair generate_keypair(const Components& c) {
    HMODULE lib = LoadLibraryW(c.tunnel_dll.c_str());
    if (!lib) fail("loading tunnel.dll failed");
    using GenFn = void(__cdecl*)(BYTE*, BYTE*);
    auto gen = reinterpret_cast<GenFn>(reinterpret_cast<void*>(GetProcAddress(lib, "WireGuardGenerateKeypair")));
    if (!gen) { FreeLibrary(lib); throw std::runtime_error("tunnel.dll does not export WireGuardGenerateKeypair"); }
    BYTE pub[32] = {}, priv[32] = {};
    gen(pub, priv);
    KeyPair kp{base64_std_encode(std::string(reinterpret_cast<char*>(pub), 32)),
               base64_std_encode(std::string(reinterpret_cast<char*>(priv), 32))};
    SecureZeroMemory(priv, sizeof priv);
    FreeLibrary(lib);
    if (!valid_wg_key(kp.public_key) || !valid_wg_key(kp.private_key)) throw std::runtime_error("tunnel.dll produced an invalid keypair");
    return kp;
}

KeyPair load_or_create_identity(const Components& c, bool& created) {
    ensure_secure_dir(paths().dir);
    const auto blob = read_file(paths().identity);
    const auto pub = read_file(paths().pubkey);
    if (blob && pub) {
        KeyPair kp{trim(*pub), dpapi_unprotect(*blob)};
        if (!valid_wg_key(kp.public_key) || !valid_wg_key(kp.private_key))
            throw std::runtime_error("stored scshr identity is corrupt — run `scshr tunnel uninstall --reset-identity` to start over");
        created = false;
        return kp;
    }
    if (blob || pub) throw std::runtime_error("scshr identity is half-written — run `scshr tunnel uninstall --reset-identity` to start over");
    KeyPair kp = generate_keypair(c);
    write_secure_file(paths().identity, dpapi_protect(kp.private_key));
    write_secure_file(paths().pubkey, kp.public_key + "\n");
    created = true;
    return kp;
}

std::optional<TunnelState> load_state() {
    const auto text = read_file(paths().state);
    if (!text) return std::nullopt;
    TunnelState s;
    size_t pos = 0;
    bool any = false;
    while (pos < text->size()) {
        size_t nl = text->find('\n', pos);
        if (nl == std::string::npos) nl = text->size();
        const std::string line = trim(text->substr(pos, nl - pos));
        pos = nl + 1;
        const size_t eq = line.find('=');
        if (line.empty() || eq == std::string::npos) continue;
        const std::string k = line.substr(0, eq), v = line.substr(eq + 1);
        if (k == "local_public_key") s.local_public_key = v;
        else if (k == "peer_public_key") s.peer_public_key = v;
        else if (k == "endpoint_host") s.endpoint_host = v;
        else if (k == "endpoint_port") s.endpoint_port = uint16_t(std::strtoul(v.c_str(), nullptr, 10));
        else if (k == "win_ip") s.win_ip = v;
        else if (k == "mac_ip") s.mac_ip = v;
        else continue;
        any = true;
    }
    if (!any || s.peer_public_key.empty()) return std::nullopt;
    return s;
}

void save_state(const TunnelState& s) {
    ensure_secure_dir(paths().dir);
    const std::string text = "local_public_key=" + s.local_public_key + "\npeer_public_key=" + s.peer_public_key +
                             "\nendpoint_host=" + s.endpoint_host + "\nendpoint_port=" + std::to_string(s.endpoint_port) +
                             "\nwin_ip=" + s.win_ip + "\nmac_ip=" + s.mac_ip + "\n";
    write_secure_file(paths().state, text);
}

bool write_conf_if_changed(const std::string& rendered) {
    ensure_secure_dir(paths().dir);
    const auto existing = read_file(paths().conf);
    if (existing && *existing == rendered) return false;
    write_secure_file(paths().conf, rendered);
    return true;
}

std::optional<std::string> read_conf() { return read_file(paths().conf); }

void restore_conf(const std::optional<std::string>& previous) {
    if (previous) write_secure_file(paths().conf, *previous);
    else DeleteFileW(paths().conf.c_str());
}

ServiceState service_state() {
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) return ServiceState::Absent;
    ScHandle svc(OpenServiceW(scm, kServiceName, SERVICE_QUERY_STATUS));
    if (!svc) return ServiceState::Absent;
    SERVICE_STATUS st{};
    if (!QueryServiceStatus(svc, &st)) return ServiceState::Other;
    switch (st.dwCurrentState) {
        case SERVICE_STOPPED: return ServiceState::Stopped;
        case SERVICE_START_PENDING: return ServiceState::StartPending;
        case SERVICE_RUNNING: return ServiceState::Running;
        default: return ServiceState::Other;
    }
}

void install_service() {
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT));
    if (!scm) fail("opening the service manager failed");
    const std::wstring cmd = service_command();
    // SERVICE_SID_TYPE_UNRESTRICTED is mandatory for the embeddable tunnel service.
    SERVICE_SID_INFO sid{SERVICE_SID_TYPE_UNRESTRICTED};

    ScHandle existing(OpenServiceW(scm, kServiceName, SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG));
    if (existing) {
        if (!ChangeServiceConfigW(existing, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                  cmd.c_str(), nullptr, nullptr, L"Nsi\0TcpIp\0\0", nullptr, nullptr, kServiceDisplay))
            fail("reconfiguring the scshr tunnel service failed");
        if (!ChangeServiceConfig2W(existing, SERVICE_CONFIG_SERVICE_SID_INFO, &sid))
            fail("setting the service SID type failed");
        return;
    }
    ScHandle svc(CreateServiceW(scm, kServiceName, kServiceDisplay, SERVICE_CHANGE_CONFIG | SERVICE_START,
                                SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                                cmd.c_str(), nullptr, nullptr, L"Nsi\0TcpIp\0\0", nullptr, nullptr));
    if (!svc) fail("creating the scshr tunnel service failed");
    if (!ChangeServiceConfig2W(svc, SERVICE_CONFIG_SERVICE_SID_INFO, &sid))
        fail("setting the service SID type failed");
}

void start_service() {
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) fail("opening the service manager failed");
    ScHandle svc(OpenServiceW(scm, kServiceName, SERVICE_START | SERVICE_QUERY_STATUS));
    if (!svc) fail("opening the scshr tunnel service failed");
    if (!StartServiceW(svc, 0, nullptr)) {
        const DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) fail("starting the scshr tunnel service failed", err);
    }
    for (int i = 0; i < 100; ++i) {
        SERVICE_STATUS st{};
        if (QueryServiceStatus(svc, &st) && st.dwCurrentState == SERVICE_RUNNING) return;
        Sleep(100);
    }
    throw std::runtime_error("the scshr tunnel service did not reach the running state within 10 s");
}

void stop_service() {
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) return;
    ScHandle svc(OpenServiceW(scm, kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS));
    if (!svc) return;
    SERVICE_STATUS st{};
    ControlService(svc, SERVICE_CONTROL_STOP, &st);
    for (int i = 0; i < 100; ++i) {
        if (QueryServiceStatus(svc, &st) && st.dwCurrentState == SERVICE_STOPPED) return;
        Sleep(100);
    }
}

void delete_service() {
    ScHandle scm(OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT));
    if (!scm) return;
    ScHandle svc(OpenServiceW(scm, kServiceName, DELETE));
    if (svc) DeleteService(svc);
}

bool query_status(TunnelStatus& out, std::string& error) {
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 2; ++attempt) {
        pipe = CreateFileW(kUapiPipe, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_PIPE_BUSY) break;
        WaitNamedPipeW(kUapiPipe, 2000);
    }
    if (pipe == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        error = err == ERROR_FILE_NOT_FOUND ? "tunnel is not running" :
                err == ERROR_ACCESS_DENIED  ? "tunnel status needs Administrator" : "cannot reach the tunnel";
        return false;
    }
    static const char kGet[] = "get=1\n\n";
    DWORD written = 0;
    if (!WriteFile(pipe, kGet, DWORD(sizeof kGet - 1), &written, nullptr)) {
        CloseHandle(pipe);
        error = "writing to the WireGuard API pipe failed";
        return false;
    }
    std::string resp;
    char buf[4096];
    DWORD n = 0;
    while (ReadFile(pipe, buf, sizeof buf, &n, nullptr) && n) {
        resp.append(buf, n);
        if (resp.find("\nerrno=") != std::string::npos && resp.size() >= 2 && resp.compare(resp.size() - 2, 2, "\n\n") == 0) break;
    }
    CloseHandle(pipe);
    return parse_uapi_status(resp, out, error);
}

RouteAudit audit_routes(const std::string& peer_ip) {
    RouteAudit a;
    NET_LUID tun{};
    if (!luid_for_tunnel(tun)) {
        a.problems.push_back("the scshr tunnel adapter is not present");
        return a;
    }
    a.tunnel_interface_present = true;

    NET_LUID via{};
    uint8_t prefix = 0;
    if (best_route_luid(peer_ip, via, prefix) && via.Value == tun.Value && prefix == 32) a.peer_route_via_tunnel = true;
    else a.problems.push_back(peer_ip + " does not route through the scshr tunnel as a /32");

    // No default route may be bound to our adapter (that would make it a full VPN).
    a.no_default_route_on_tunnel = true;
    PMIB_IPFORWARD_TABLE2 table = nullptr;
    if (GetIpForwardTable2(AF_UNSPEC, &table) == NO_ERROR && table) {
        for (ULONG i = 0; i < table->NumEntries; ++i) {
            const MIB_IPFORWARD_ROW2& r = table->Table[i];
            if (r.InterfaceLuid.Value == tun.Value && r.DestinationPrefix.PrefixLength == 0) {
                a.no_default_route_on_tunnel = false;
                a.problems.push_back("a default route is bound to the scshr tunnel adapter");
                break;
            }
        }
        FreeMibTable(table);
    } else {
        a.no_default_route_on_tunnel = false;
        a.problems.push_back("could not read the system routing table");
    }

    // Ordinary Internet traffic must still leave over the normal network.
    NET_LUID pub{};
    uint8_t pub_prefix = 0;
    if (best_route_luid("1.1.1.1", pub, pub_prefix) && pub.Value != tun.Value) a.internet_bypasses_tunnel = true;
    else a.problems.push_back("public Internet traffic would be routed into the scshr tunnel");

    // The adapter must publish no DNS servers (we never write a DNS= line).
    ULONG size = 16 * 1024;
    std::vector<char> mem(size);
    ULONG rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_FRIENDLY_NAME,
                                    nullptr, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(mem.data()), &size);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        mem.resize(size);
        rc = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_FRIENDLY_NAME,
                                  nullptr, reinterpret_cast<PIP_ADAPTER_ADDRESSES>(mem.data()), &size);
    }
    if (rc == NO_ERROR) {
        bool found = false;
        for (auto* p = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(mem.data()); p; p = p->Next) {
            if (p->Luid.Value != tun.Value) continue;
            found = true;
            a.no_dns_on_tunnel = p->FirstDnsServerAddress == nullptr;
            break;
        }
        if (!found || !a.no_dns_on_tunnel) a.problems.push_back("the scshr tunnel adapter publishes DNS servers");
    } else {
        a.problems.push_back("could not enumerate network adapters");
    }
    return a;
}

int run_tunnel_service(const wchar_t* conf_path) {
    // Runs inside the service process: hand the configuration straight to upstream's tunnel.dll.
    const std::wstring dll = exe_dir() + L"\\tunnel.dll";
    HMODULE lib = LoadLibraryW(dll.c_str());
    if (!lib) return int(GetLastError());
    using SvcFn = BOOL(__cdecl*)(LPCWSTR);
    auto svc = reinterpret_cast<SvcFn>(reinterpret_cast<void*>(GetProcAddress(lib, "WireGuardTunnelService")));
    if (!svc) return int(ERROR_PROC_NOT_FOUND);
    return svc(conf_path) ? 0 : 1;
}

void uninstall(bool reset_identity, std::vector<std::string>& removed) {
    if (service_state() != ServiceState::Absent) {
        stop_service();
        delete_service();
        removed.push_back("service " + narrow(kServiceName));
    }
    const Paths p = paths();
    std::vector<std::wstring> files{p.conf, p.state};
    if (reset_identity) { files.push_back(p.identity); files.push_back(p.pubkey); }
    for (const std::wstring& f : files) {
        if (DeleteFileW(f.c_str())) removed.push_back(narrow(f));
    }
    RemoveDirectoryW(p.dir.c_str());   // only succeeds if nothing of ours is left
}

}  // namespace scshr::tunnel
