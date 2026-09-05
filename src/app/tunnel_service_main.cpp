// scshr-tunnel.exe — the host process of the WireGuard tunnel service (`WireGuardTunnel$scshr`).
//
// It exists so that the always-on service does not run as `scshr.exe`: with the same image name the
// service looked like a leftover of the application in Task Manager (and was killed as one, taking the
// tunnel down), and it kept the application binary locked. This process only loads upstream's
// tunnel.dll from its own directory and hands it the configuration; everything else stays in scshr.exe.
//
//   scshr-tunnel.exe /wireguard-service "<path to scshr.conf>"
#include <windows.h>

#include <string>

int wmain(int argc, wchar_t** argv) {
    if (argc != 3 || std::wstring(argv[1]) != L"/wireguard-service") return 2;
    std::wstring dir(MAX_PATH, L'\0');
    const DWORD n = GetModuleFileNameW(nullptr, dir.data(), DWORD(dir.size()));
    if (n == 0 || n >= dir.size()) return int(GetLastError());
    dir.resize(n);
    dir.resize(dir.find_last_of(L"\\/") + 1);
    HMODULE lib = LoadLibraryW((dir + L"tunnel.dll").c_str());
    if (!lib) return int(GetLastError());
    using SvcFn = BOOL(__cdecl*)(LPCWSTR);
    auto svc = reinterpret_cast<SvcFn>(reinterpret_cast<void*>(GetProcAddress(lib, "WireGuardTunnelService")));
    if (!svc) return int(ERROR_PROC_NOT_FOUND);
    return svc(argv[2]) ? 0 : 1;
}
