// scshr — native Windows client for Apple Screen Sharing High Performance mode.
//
// The executable is /SUBSYSTEM:WINDOWS (with /ENTRY:mainCRTStartup, so this plain `main` still runs) so a
// double-click never flashes a console. Three entry paths:
//
//   scshr /wireguard-service <name>   the embedded WireGuard tunnel service (no console, no UI)
//   scshr                             the launcher GUI (setup wizard / connect page) — app/gui.h
//   scshr <arguments>                 the CLI: re-attach to the parent console, then tunnel commands + viewer
#include "app/gui.h"
#include "app/tunnel_cli.h"
#include "app/viewer.h"
#include "common/log.h"
#include "tunnel/win_tunnel.h"

#include <shellapi.h>
#include <windows.h>

#include <io.h>

#include <cstdio>
#include <string>

using namespace scshr;

namespace {

// A GUI-subsystem process gets its standard handles from whoever started it, so a shell's redirection
// (`scshr status > log.txt`, `echo $PW | scshr -u me --password-stdin`) already works and must be left
// alone. What it does not get is a console of its own: attach to the parent's so the password prompt and
// SetConsoleMode have one, and point any stream the parent left unset at it. Started from Explorer there
// is no parent console, and the CLI then simply produces no visible output — no console window pops up.
void attach_parent_console() {
    if (_fileno(stdout) >= 0 && _fileno(stderr) >= 0 && _fileno(stdin) >= 0) return;
    if (!AttachConsole(ATTACH_PARENT_PROCESS)) return;
    FILE* f = nullptr;
    if (_fileno(stdout) < 0) freopen_s(&f, "CONOUT$", "w", stdout);
    if (_fileno(stderr) < 0) freopen_s(&f, "CONOUT$", "w", stderr);
    if (_fileno(stdin) < 0) freopen_s(&f, "CONIN$", "r", stdin);
}

}  // namespace

// Once the last window is gone (or the CLI has printed its result) the process must end now. A normal
// return would run every DLL's detach and every static destructor (FFmpeg, D3D11, WASAPI, WinSock,
// OpenSSL) and wait for background threads; any of those can stall and leave scshr.exe alive with no
// window. Everything that matters is already on disk, so flush what was written and stop the process.
[[noreturn]] void exit_now(int rc) {
    std::fflush(stdout);
    std::fflush(stderr);
    log_set_file("");   // closes the log file
    TerminateProcess(GetCurrentProcess(), UINT(rc));
    ExitProcess(UINT(rc));   // not reached
}

int main(int argc, char** argv) {
    // Service entry point kept for installs made before the service got its own host
    // (scshr-tunnel.exe); the next Set up / `scshr init` re-points the service there.
    if (argc == 3 && std::string(argv[1]) == "/wireguard-service") {
        int wargc = 0;
        LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &wargc);
        if (!wargv || wargc != 3) return 2;
        const int rc = tunnel::run_tunnel_service(wargv[2]);
        LocalFree(wargv);
        return rc;
    }

    if (argc == 1) exit_now(app::run_gui(GetModuleHandleW(nullptr)));

    attach_parent_console();

    int tunnel_rc = 0;
    if (app::run_tunnel_command(argc, argv, tunnel_rc)) return tunnel_rc;

    app::ViewerOptions o;
    if (!app::parse_viewer_args(argc, argv, o)) return 2;
    if (o.user.empty() && o.replay_key.empty() && !o.list_adapters) { app::usage(); return 2; }

    const app::ViewerResult r = app::run_viewer(o);
    if (r.exit != app::ViewerExit::Closed && !r.error.empty()) std::fprintf(stderr, "scshr: %s\n", r.error.c_str());
    exit_now(r.exit_code);
}
