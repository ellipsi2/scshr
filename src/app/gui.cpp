// Launcher GUI: pure Win32 + comctl32 v6, dialog templates from scshr.rc.
//
//   run_gui() → (not paired) setup wizard → (paired) connect page → viewer → back to the connect page.
//
// Long-running work (setup over SSH, link checks) runs on a worker thread; the worker never touches a
// window handle, it posts WM_APP messages and the dialog thread does the UI. Threads are always joined
// before a dialog ends, and the wizard refuses to close while setup is still running.
#include "app/gui.h"

#include "app/resource.h"
#include "app/settings.h"
#include "app/setup.h"
#include "app/ssh_client.h"
#include "app/viewer.h"

#include <commctrl.h>
#include <objbase.h>

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace scshr::app {
namespace {

HINSTANCE g_instance = nullptr;

constexpr UINT WM_SETUP_STEP = WM_APP + 1;   // wParam = MAKEWPARAM(step, total), lParam = new std::wstring*
constexpr UINT WM_SETUP_LOG  = WM_APP + 2;   // lParam = new std::wstring*
constexpr UINT WM_SETUP_DONE = WM_APP + 3;
constexpr UINT WM_LINK_DONE  = WM_APP + 4;
constexpr UINT WM_UNPAIR_DONE = WM_APP + 5;

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), int(s.size()), nullptr, 0);
    std::wstring w(size_t(n > 0 ? n : 0), L'\0');
    if (n > 0) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), int(s.size()), w.data(), n);
    return w;
}
std::string narrow(const std::wstring& w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), int(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(size_t(n > 0 ? n : 0), '\0');
    if (n > 0) WideCharToMultiByte(CP_UTF8, 0, w.c_str(), int(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}

std::string dlg_text(HWND dlg, int id) {
    const int n = GetWindowTextLengthW(GetDlgItem(dlg, id));
    std::wstring w(size_t(n) + 1, L'\0');
    GetDlgItemTextW(dlg, id, w.data(), n + 1);
    w.resize(size_t(n));
    return narrow(w);
}
void set_text(HWND dlg, int id, const std::wstring& s) { SetDlgItemTextW(dlg, id, s.c_str()); }
void set_text(HWND dlg, int id, const std::string& s) { set_text(dlg, id, widen(s)); }

void append_log(HWND dlg, const std::wstring& line) {
    HWND e = GetDlgItem(dlg, IDC_SETUP_LOG);
    const int len = GetWindowTextLengthW(e);
    SendMessageW(e, EM_SETSEL, WPARAM(len), LPARAM(len));
    const std::wstring t = line + L"\r\n";
    SendMessageW(e, EM_REPLACESEL, FALSE, LPARAM(t.c_str()));
    SendMessageW(e, EM_SCROLLCARET, 0, 0);
}

void apply_icon(HWND dlg) {
    if (HICON big = LoadIconW(g_instance, MAKEINTRESOURCEW(IDI_APP))) {
        SendMessageW(dlg, WM_SETICON, ICON_BIG, LPARAM(big));
        SendMessageW(dlg, WM_SETICON, ICON_SMALL, LPARAM(big));
    }
}

std::string mac_label_of(const Settings& s) { return s.mac_label.empty() ? s.ssh_host : s.mac_label; }

// ── options ───────────────────────────────────────────────────────────────
struct OptionsCtx { Settings* settings; };

INT_PTR CALLBACK options_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
    auto* ctx = reinterpret_cast<OptionsCtx*>(GetWindowLongPtrW(dlg, DWLP_USER));
    switch (msg) {
    case WM_INITDIALOG: {
        SetWindowLongPtrW(dlg, DWLP_USER, LONG_PTR(lp));
        ctx = reinterpret_cast<OptionsCtx*>(lp);
        apply_icon(dlg);
        CheckDlgButton(dlg, IDC_OPT_AUDIO, ctx->settings->audio ? BST_CHECKED : BST_UNCHECKED);
        CheckRadioButton(dlg, IDC_OPT_SEPARATE, IDC_OPT_SHARED, ctx->settings->separate_session ? IDC_OPT_SEPARATE : IDC_OPT_SHARED);
        HWND cb = GetDlgItem(dlg, IDC_OPT_DISPLAY);
        SendMessageW(cb, CB_ADDSTRING, 0, LPARAM(L"All monitors, one window each"));
        SendMessageW(cb, CB_ADDSTRING, 0, LPARAM(L"Everything in one window"));
        for (int i = 1; i <= 4; ++i) SendMessageW(cb, CB_ADDSTRING, 0, LPARAM((L"Monitor " + std::to_wstring(i)).c_str()));
        int sel = 0;
        if (ctx->settings->display == "combined") sel = 1;
        else if (ctx->settings->display != "all") sel = std::min(5, std::max(1, atoi(ctx->settings->display.c_str()) + 1));
        SendMessageW(cb, CB_SETCURSEL, WPARAM(sel), 0);
        return TRUE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) {
            ctx->settings->audio = IsDlgButtonChecked(dlg, IDC_OPT_AUDIO) == BST_CHECKED;
            ctx->settings->separate_session = IsDlgButtonChecked(dlg, IDC_OPT_SEPARATE) == BST_CHECKED;
            const int sel = int(SendDlgItemMessageW(dlg, IDC_OPT_DISPLAY, CB_GETCURSEL, 0, 0));
            ctx->settings->display = sel <= 0 ? "all" : sel == 1 ? "combined" : std::to_string(sel - 1);
            EndDialog(dlg, IDOK);
            return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) { EndDialog(dlg, IDCANCEL); return TRUE; }
        break;
    default: break;
    }
    return FALSE;
}

// ── password prompt ───────────────────────────────────────────────────────
struct PasswordCtx { std::wstring prompt; std::string password; };

INT_PTR CALLBACK password_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
    auto* ctx = reinterpret_cast<PasswordCtx*>(GetWindowLongPtrW(dlg, DWLP_USER));
    switch (msg) {
    case WM_INITDIALOG:
        SetWindowLongPtrW(dlg, DWLP_USER, LONG_PTR(lp));
        ctx = reinterpret_cast<PasswordCtx*>(lp);
        apply_icon(dlg);
        set_text(dlg, IDC_PWD_TEXT, ctx->prompt);
        SetFocus(GetDlgItem(dlg, IDC_PWD_EDIT));
        return FALSE;
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) { ctx->password = dlg_text(dlg, IDC_PWD_EDIT); EndDialog(dlg, IDOK); return TRUE; }
        if (LOWORD(wp) == IDCANCEL) { EndDialog(dlg, IDCANCEL); return TRUE; }
        break;
    default: break;
    }
    return FALSE;
}

// ── setup wizard ──────────────────────────────────────────────────────────
struct SetupCtx {
    const Settings* previous = nullptr;      // prefill + previously pinned host key (may be null)
    std::thread worker;
    std::atomic<bool> cancel{false};
    bool running = false, done_ok = false, advanced = false;
    bool close_is_ok = false;   // setup failed late, but the pairing is on disk: Close goes to the connect page
    SetupRequest req;
    SetupOutcome outcome;
};

const int kSetupInputs[] = {IDC_SETUP_HOST, IDC_SETUP_USER, IDC_SETUP_PASS, IDC_SETUP_ADVANCED,
                            IDC_SETUP_SSH_PORT, IDC_SETUP_PORT, IDC_SETUP_ENDPOINT};

void setup_show_advanced(HWND dlg, bool on) {
    const int ids[] = {IDC_SETUP_SSH_PORT_LBL, IDC_SETUP_SSH_PORT, IDC_SETUP_PORT_LBL, IDC_SETUP_PORT,
                       IDC_SETUP_ENDPOINT_LBL, IDC_SETUP_ENDPOINT};
    for (int id : ids) ShowWindow(GetDlgItem(dlg, id), on ? SW_SHOW : SW_HIDE);
}

void setup_enable_inputs(HWND dlg, bool on) {
    for (int id : kSetupInputs) EnableWindow(GetDlgItem(dlg, id), on);
}

// Reads a 1..65535 port from an edit control; returns 0 when the field is empty or out of range.
uint16_t dlg_port(HWND dlg, int id) {
    const long v = std::strtol(dlg_text(dlg, id).c_str(), nullptr, 10);
    return v > 0 && v < 65536 ? uint16_t(v) : 0;
}

void setup_start(HWND dlg, SetupCtx& ctx) {
    SetupRequest req;
    req.ssh_host = dlg_text(dlg, IDC_SETUP_HOST);
    req.ssh_user = dlg_text(dlg, IDC_SETUP_USER);
    req.password = dlg_text(dlg, IDC_SETUP_PASS);
    req.endpoint_override = ctx.advanced ? dlg_text(dlg, IDC_SETUP_ENDPOINT) : std::string();
    const uint16_t listen = ctx.advanced ? dlg_port(dlg, IDC_SETUP_PORT) : 0;
    req.listen_port = listen ? listen : 51820;
    if (ctx.previous) req.expected_hostkey = ctx.previous->ssh_hostkey_sha256;
    if (req.ssh_host.empty() || req.ssh_user.empty() || req.password.empty()) {
        gui_message(L"Set up scshr", L"Fill in the Mac's address, a user name and that user's password.", true);
        return;
    }
    // The SSH port lives in the Advanced section, but "host:port" in the address box still works, so
    // the two must agree. run_setup() re-parses req.ssh_host; hand it the composed form.
    if (ctx.advanced) {
        std::string host;
        uint16_t typed_port = 22;
        if (!parse_ssh_host(req.ssh_host, host, typed_port)) {
            gui_message(L"Set up scshr", L"\"" + widen(req.ssh_host) + L"\" is not a valid Mac address.", true);
            return;
        }
        const uint16_t ssh_port = dlg_port(dlg, IDC_SETUP_SSH_PORT);
        if (!ssh_port) {
            gui_message(L"Set up scshr", L"The SSH port must be a number from 1 to 65535 (22 is the usual one).", true);
            return;
        }
        if (typed_port != 22 && ssh_port != 22 && typed_port != ssh_port) {
            gui_message(L"Set up scshr", L"The Mac address says port " + std::to_wstring(typed_port) +
                        L" but the SSH port field says " + std::to_wstring(ssh_port) + L". Use one or the other.", true);
            return;
        }
        req.ssh_host = compose_ssh_host(host, ssh_port != 22 ? ssh_port : typed_port);
    }
    ctx.req = req;
    ctx.cancel = false;
    ctx.running = true;
    ctx.done_ok = false;
    setup_enable_inputs(dlg, false);
    SetDlgItemTextW(dlg, IDOK, L"Set up");
    EnableWindow(GetDlgItem(dlg, IDOK), FALSE);
    SetDlgItemTextW(dlg, IDCANCEL, L"Cancel");
    SetDlgItemTextW(dlg, IDC_SETUP_LOG, L"");
    set_text(dlg, IDC_SETUP_STATUS, std::wstring(L"Connecting to the Mac..."));
    HWND bar = GetDlgItem(dlg, IDC_SETUP_PROGRESS);
    ShowWindow(bar, SW_SHOW);
    SendMessageW(bar, PBM_SETRANGE32, 0, 1);
    SendMessageW(bar, PBM_SETPOS, 0, 0);

    SetupProgress prog;
    prog.on_step = [dlg](int step, int total, const std::string& title) {
        PostMessageW(dlg, WM_SETUP_STEP, MAKEWPARAM(step, total), LPARAM(new std::wstring(widen(title))));
    };
    prog.on_log = [dlg](const std::string& line) {
        PostMessageW(dlg, WM_SETUP_LOG, 0, LPARAM(new std::wstring(widen(line))));
    };
    prog.cancelled = [&ctx] { return ctx.cancel.load(); };
    ctx.worker = std::thread([dlg, &ctx, prog] {
        ctx.outcome = run_setup(ctx.req, prog);
        PostMessageW(dlg, WM_SETUP_DONE, 0, 0);
    });
}

void setup_finish(HWND dlg, SetupCtx& ctx) {
    if (ctx.worker.joinable()) ctx.worker.join();
    ctx.running = false;
    const SetupOutcome& o = ctx.outcome;
    HWND bar = GetDlgItem(dlg, IDC_SETUP_PROGRESS);

    if (o.ok) {
        // run_setup() persists the Settings itself; run_gui() re-reads them on its next pass.
        SendMessageW(bar, PBM_SETRANGE32, 0, 1);
        SendMessageW(bar, PBM_SETPOS, 1, 0);
        set_text(dlg, IDC_SETUP_STATUS, o.headline);
        if (!o.detail.empty()) append_log(dlg, widen(o.detail));
        if (!o.warnings.empty()) {
            append_log(dlg, L"");
            append_log(dlg, L"Worth knowing:");
            for (const auto& w : o.warnings) append_log(dlg, L"  \x2022 " + widen(w));
        }
        ctx.done_ok = true;
        SetDlgItemTextW(dlg, IDOK, L"&Open");
        EnableWindow(GetDlgItem(dlg, IDOK), TRUE);
        SetDlgItemTextW(dlg, IDCANCEL, L"Close");
        SetFocus(GetDlgItem(dlg, IDOK));
        return;
    }

    ShowWindow(bar, SW_HIDE);
    set_text(dlg, IDC_SETUP_STATUS, o.headline.empty() ? std::string("Setup did not finish.") : o.headline);
    if (!o.detail.empty()) { append_log(dlg, L""); append_log(dlg, widen(o.detail)); }
    for (const auto& w : o.warnings) append_log(dlg, L"  \x2022 " + widen(w));
    setup_enable_inputs(dlg, true);
    SetDlgItemTextW(dlg, IDOK, L"&Try again");
    EnableWindow(GetDlgItem(dlg, IDOK), TRUE);
    // run_setup() saves the settings as soon as both halves are paired, so a late failure (port not
    // forwarded yet, Screen Sharing still off) leaves a usable pairing behind. Let the user go to the
    // connect page, whose Check spells out what is still missing.
    const auto saved = load_settings();
    ctx.close_is_ok = saved && saved->paired;
    SetDlgItemTextW(dlg, IDCANCEL, ctx.close_is_ok ? L"Close" : L"Cancel");
    SetFocus(GetDlgItem(dlg, IDC_SETUP_HOST));
}

INT_PTR CALLBACK setup_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
    auto* ctx = reinterpret_cast<SetupCtx*>(GetWindowLongPtrW(dlg, DWLP_USER));
    switch (msg) {
    case WM_INITDIALOG: {
        SetWindowLongPtrW(dlg, DWLP_USER, LONG_PTR(lp));
        ctx = reinterpret_cast<SetupCtx*>(lp);
        apply_icon(dlg);
        setup_show_advanced(dlg, false);
        ShowWindow(GetDlgItem(dlg, IDC_SETUP_PROGRESS), SW_HIDE);   // only meaningful once setup is running
        SetDlgItemTextW(dlg, IDC_SETUP_SSH_PORT, L"22");
        SetDlgItemTextW(dlg, IDC_SETUP_PORT, L"51820");
        if (ctx->previous) {
            set_text(dlg, IDC_SETUP_HOST, ctx->previous->ssh_host);
            set_text(dlg, IDC_SETUP_USER, ctx->previous->ssh_user);
            SetDlgItemTextW(dlg, IDC_SETUP_SSH_PORT, std::to_wstring(ctx->previous->ssh_port).c_str());
            if (ctx->previous->ssh_port != 22) {
                // A non-default port is worth seeing, not just carrying over silently.
                CheckDlgButton(dlg, IDC_SETUP_ADVANCED, BST_CHECKED);
                ctx->advanced = true;
                setup_show_advanced(dlg, true);
            }
        }
        SetFocus(GetDlgItem(dlg, ctx->previous ? IDC_SETUP_PASS : IDC_SETUP_HOST));
        return FALSE;
    }
    case WM_SETUP_STEP: {
        std::unique_ptr<std::wstring> title(reinterpret_cast<std::wstring*>(lp));
        const int step = int(LOWORD(wp)), total = int(HIWORD(wp));
        HWND bar = GetDlgItem(dlg, IDC_SETUP_PROGRESS);
        SendMessageW(bar, PBM_SETRANGE32, 0, LPARAM(total > 0 ? total : 1));
        SendMessageW(bar, PBM_SETPOS, WPARAM(step), 0);
        if (title) {
            set_text(dlg, IDC_SETUP_STATUS, L"Step " + std::to_wstring(step) + L" of " + std::to_wstring(total) + L": " + *title);
            append_log(dlg, L"[" + std::to_wstring(step) + L"/" + std::to_wstring(total) + L"] " + *title);
        }
        return TRUE;
    }
    case WM_SETUP_LOG: {
        std::unique_ptr<std::wstring> line(reinterpret_cast<std::wstring*>(lp));
        if (line) append_log(dlg, *line);
        return TRUE;
    }
    case WM_SETUP_DONE:
        setup_finish(dlg, *ctx);
        return TRUE;
    case WM_CTLCOLORSTATIC:
        if (ctx && GetDlgCtrlID(HWND(lp)) == IDC_SETUP_STATUS && !ctx->running && !ctx->outcome.headline.empty()) {
            SetTextColor(HDC(wp), ctx->outcome.ok ? RGB(0, 100, 0) : RGB(160, 20, 20));
            SetBkMode(HDC(wp), TRANSPARENT);
            return INT_PTR(GetSysColorBrush(COLOR_BTNFACE));
        }
        break;
    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_SETUP_ADVANCED:
            ctx->advanced = IsDlgButtonChecked(dlg, IDC_SETUP_ADVANCED) == BST_CHECKED;
            setup_show_advanced(dlg, ctx->advanced);
            return TRUE;
        case IDOK:
            if (ctx->running) return TRUE;
            if (ctx->done_ok) { EndDialog(dlg, IDOK); return TRUE; }
            setup_start(dlg, *ctx);
            return TRUE;
        case IDCANCEL:
            if (ctx->running) {
                ctx->cancel = true;                      // run_setup() aborts its next wait; clicking again is harmless
                set_text(dlg, IDC_SETUP_STATUS, std::wstring(L"Stopping..."));
                return TRUE;
            }
            EndDialog(dlg, ctx->done_ok || ctx->close_is_ok ? IDOK : IDCANCEL);
            return TRUE;
        default: break;
        }
        break;
    case WM_CLOSE:
        SendMessageW(dlg, WM_COMMAND, IDCANCEL, 0);
        return TRUE;
    default: break;
    }
    return FALSE;
}

// Returns IDOK when the Mac is paired and the user wants to go on, IDCANCEL to quit.
int run_setup_dialog(HWND owner, const Settings* previous) {
    SetupCtx ctx;
    ctx.previous = previous;
    const INT_PTR r = DialogBoxParamW(g_instance, MAKEINTRESOURCEW(IDD_SETUP), owner, setup_proc, LPARAM(&ctx));
    if (ctx.worker.joinable()) ctx.worker.join();     // belt and braces: the dialog never ends while running
    return r == IDOK ? IDOK : IDCANCEL;
}

// ── connect page ──────────────────────────────────────────────────────────
struct ConnectCtx {
    Settings settings;
    std::thread checker;
    bool checking = false, status_ok = false, have_status = false;
    LinkStatus link;
    // Removing the pairing signs in to the Mac over SSH and can take minutes, so it runs on its own
    // thread; `unpair_req` lives here because the worker holds a pointer into it.
    std::thread unpairer;
    bool unpairing = false, unpair_with_mac = false;
    SetupRequest unpair_req;
    std::vector<std::string> unpair_lines;
};

// Everything the user can press on the connect page, disabled while the pairing is being removed.
const int kConnectControls[] = {IDOK, IDC_CONN_CHECK, IDC_CONN_SETUP_AGAIN, IDC_CONN_OPTIONS,
                                IDC_CONN_REMOVE, IDC_CONN_USER, IDC_CONN_PASS, IDC_CONN_REMEMBER};

void connect_start_check(HWND dlg, ConnectCtx& ctx) {
    if (ctx.checking) return;
    if (ctx.checker.joinable()) ctx.checker.join();
    ctx.checking = true;
    ctx.have_status = false;
    EnableWindow(GetDlgItem(dlg, IDC_CONN_CHECK), FALSE);
    set_text(dlg, IDC_CONN_STATUS, std::wstring(L"Checking..."));
    InvalidateRect(GetDlgItem(dlg, IDC_CONN_STATUS), nullptr, TRUE);
    ctx.checker = std::thread([dlg, &ctx] { ctx.link = check_link(); PostMessageW(dlg, WM_LINK_DONE, 0, 0); });
}

void connect_show_status(HWND dlg, ConnectCtx& ctx) {
    if (ctx.checker.joinable()) ctx.checker.join();
    ctx.checking = false;
    ctx.have_status = true;
    ctx.status_ok = ctx.link.screen_sharing_reachable;
    EnableWindow(GetDlgItem(dlg, IDC_CONN_CHECK), TRUE);
    std::wstring text = ctx.status_ok ? L"Ready"
                                      : L"Waiting for the Mac" + (ctx.link.problem.empty() ? std::wstring(L".")
                                                                                           : L" \x2014 " + widen(ctx.link.problem));
    set_text(dlg, IDC_CONN_STATUS, text);
    InvalidateRect(GetDlgItem(dlg, IDC_CONN_STATUS), nullptr, TRUE);
}

void connect_run_viewer(HWND dlg, ConnectCtx& ctx) {
    const std::string user = dlg_text(dlg, IDC_CONN_USER);
    const std::string password = dlg_text(dlg, IDC_CONN_PASS);
    if (user.empty()) { gui_message(L"scshr", L"Type the name of the Mac account you want to sign in to.", true); return; }
    // run_viewer() would fall back to a console password prompt, and this process has no console.
    if (password.empty()) { gui_message(L"scshr", L"Type the password for that Mac account.", true); SetFocus(GetDlgItem(dlg, IDC_CONN_PASS)); return; }

    ctx.settings.screen_user = user;
    ctx.settings.remember_password = IsDlgButtonChecked(dlg, IDC_CONN_REMEMBER) == BST_CHECKED;
    if (ctx.settings.remember_password && !password.empty()) credential_store(kScreenSharingCredential, user, password);
    else if (!ctx.settings.remember_password) credential_delete(kScreenSharingCredential);
    try { save_settings(ctx.settings); } catch (const std::exception&) { /* not fatal for this session */ }

    if (ctx.checker.joinable()) { ctx.checker.join(); ctx.checking = false; }

    const std::string label = mac_label_of(ctx.settings);
    ViewerOptions o;
    o.user = user;
    o.password = password;
    o.audio = ctx.settings.audio;
    o.display = ctx.settings.display;
    o.alt_session = ctx.settings.separate_session;    // own virtual session (default) …
    o.share_console = !o.alt_session;                 // … or the console user's screen after they click Allow
    o.title_label = label;
    o.direct = false;
    o.host.clear();

    ShowWindow(dlg, SW_HIDE);
    for (;;) {
        ViewerOptions run = o;                       // run_viewer rewrites host/password fields
        const ViewerResult r = run_viewer(run);
        if (r.exit == ViewerExit::ConnectionLost) {
            const std::wstring q = L"The connection to " + widen(label) + L" was lost.\r\n\r\nReconnect?";
            if (MessageBoxW(nullptr, q.c_str(), L"scshr", MB_YESNO | MB_ICONWARNING) == IDYES) continue;
            break;
        }
        if (r.exit != ViewerExit::Closed) {
            const std::wstring m = r.error.empty() ? std::wstring(L"The session could not be started.")
                                                   : widen(r.error);
            gui_message(L"scshr", m, true);
        }
        break;
    }
    ShowWindow(dlg, SW_SHOW);
    SetForegroundWindow(dlg);
    connect_start_check(dlg, ctx);
}

void connect_remove(HWND dlg, ConnectCtx& ctx) {
    const std::wstring label = widen(mac_label_of(ctx.settings));
    const std::wstring q = L"Remove the connection to " + label + L"?\r\n\r\n"
                           L"This PC will stop being able to reach that Mac until you set it up again.";
    if (MessageBoxW(dlg, q.c_str(), L"Remove connection", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES) return;

    PasswordCtx pc;
    pc.prompt = L"To clean up the Mac as well, type the password for " + widen(ctx.settings.ssh_user) +
                L" on " + label + L". Choose Skip to remove the connection from this PC only.";
    const INT_PTR pr = DialogBoxParamW(g_instance, MAKEINTRESOURCEW(IDD_PASSWORD), dlg, password_proc, LPARAM(&pc));

    SetupRequest& req = ctx.unpair_req;
    req = SetupRequest{};
    req.ssh_host = compose_ssh_host(ctx.settings.ssh_host, ctx.settings.ssh_port);
    req.ssh_user = ctx.settings.ssh_user;
    req.password = pc.password;
    req.expected_hostkey = ctx.settings.ssh_hostkey_sha256;
    ctx.unpair_with_mac = pr == IDOK && !pc.password.empty();

    ctx.unpairing = true;
    ctx.have_status = false;
    for (int id : kConnectControls) EnableWindow(GetDlgItem(dlg, id), FALSE);
    set_text(dlg, IDC_CONN_STATUS, std::wstring(L"Removing..."));
    InvalidateRect(GetDlgItem(dlg, IDC_CONN_STATUS), nullptr, TRUE);
    ctx.unpairer = std::thread([dlg, &ctx] {
        ctx.unpair_lines = run_unpair(ctx.unpair_with_mac ? &ctx.unpair_req : nullptr, false);
        PostMessageW(dlg, WM_UNPAIR_DONE, 0, 0);
    });
}

void connect_remove_done(HWND dlg, ConnectCtx& ctx) {
    if (ctx.unpairer.joinable()) ctx.unpairer.join();
    ctx.unpairing = false;
    for (int id : kConnectControls) EnableWindow(GetDlgItem(dlg, id), TRUE);
    std::wstring report;
    for (const auto& l : ctx.unpair_lines) report += widen(l) + L"\r\n";
    if (report.empty()) report = L"The connection was removed.";
    gui_message(L"Remove connection", report, false);
    EndDialog(dlg, IDC_CONN_REMOVE);
}

INT_PTR CALLBACK connect_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
    auto* ctx = reinterpret_cast<ConnectCtx*>(GetWindowLongPtrW(dlg, DWLP_USER));
    switch (msg) {
    case WM_INITDIALOG: {
        SetWindowLongPtrW(dlg, DWLP_USER, LONG_PTR(lp));
        ctx = reinterpret_cast<ConnectCtx*>(lp);
        apply_icon(dlg);
        set_text(dlg, IDC_CONN_MAC, "Mac: " + mac_label_of(ctx->settings));
        const std::string user = ctx->settings.screen_user.empty() ? ctx->settings.ssh_user : ctx->settings.screen_user;
        set_text(dlg, IDC_CONN_USER, user);
        CheckDlgButton(dlg, IDC_CONN_REMEMBER, ctx->settings.remember_password ? BST_CHECKED : BST_UNCHECKED);
        if (ctx->settings.remember_password) {
            if (auto pw = credential_load(kScreenSharingCredential)) set_text(dlg, IDC_CONN_PASS, *pw);
        }
        connect_start_check(dlg, *ctx);
        SetFocus(GetDlgItem(dlg, IDC_CONN_PASS));
        return FALSE;
    }
    case WM_LINK_DONE:
        connect_show_status(dlg, *ctx);
        return TRUE;
    case WM_UNPAIR_DONE:
        connect_remove_done(dlg, *ctx);
        return TRUE;
    case WM_CTLCOLORSTATIC:
        if (GetDlgCtrlID(HWND(lp)) == IDC_CONN_STATUS && ctx && ctx->have_status) {
            SetTextColor(HDC(wp), ctx->status_ok ? RGB(0, 110, 0) : RGB(150, 90, 0));
            SetBkMode(HDC(wp), TRANSPARENT);
            return INT_PTR(GetSysColorBrush(COLOR_BTNFACE));
        }
        break;
    case WM_COMMAND:
        if (ctx && ctx->unpairing) return TRUE;      // never end the dialog while the worker is running
        switch (LOWORD(wp)) {
        case IDC_CONN_CHECK: connect_start_check(dlg, *ctx); return TRUE;
        case IDOK: connect_run_viewer(dlg, *ctx); return TRUE;
        case IDC_CONN_SETUP_AGAIN:
            if (ctx->checker.joinable()) { ctx->checker.join(); ctx->checking = false; }
            EndDialog(dlg, IDC_CONN_SETUP_AGAIN);
            return TRUE;
        case IDC_CONN_OPTIONS: {
            OptionsCtx oc{&ctx->settings};
            if (DialogBoxParamW(g_instance, MAKEINTRESOURCEW(IDD_OPTIONS), dlg, options_proc, LPARAM(&oc)) == IDOK) {
                try { save_settings(ctx->settings); }
                catch (const std::exception& e) { gui_message(L"Options", L"The options could not be saved: " + widen(e.what()), true); }
            }
            return TRUE;
        }
        case IDC_CONN_REMOVE:
            if (ctx->checker.joinable()) { ctx->checker.join(); ctx->checking = false; }
            connect_remove(dlg, *ctx);
            return TRUE;
        case IDCANCEL:
            if (ctx->checker.joinable()) { ctx->checker.join(); ctx->checking = false; }
            EndDialog(dlg, IDCANCEL);
            return TRUE;
        default: break;
        }
        break;
    case WM_CLOSE:
        SendMessageW(dlg, WM_COMMAND, IDCANCEL, 0);
        return TRUE;
    default: break;
    }
    return FALSE;
}

int run_connect_dialog(HWND owner, const Settings& s) {
    ConnectCtx ctx;
    ctx.settings = s;
    const INT_PTR r = DialogBoxParamW(g_instance, MAKEINTRESOURCEW(IDD_CONNECT), owner, connect_proc, LPARAM(&ctx));
    if (ctx.checker.joinable()) ctx.checker.join();
    if (ctx.unpairer.joinable()) ctx.unpairer.join();
    return int(r);
}

}  // namespace

void gui_message(const wchar_t* title, const std::wstring& text, bool error) {
    MessageBoxW(GetActiveWindow(), text.c_str(), title, MB_OK | (error ? MB_ICONERROR : MB_ICONINFORMATION));
}

int run_gui(HINSTANCE instance) {
    g_instance = instance;
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);
    INITCOMMONCONTROLSEX icc{sizeof(INITCOMMONCONTROLSEX), ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS | ICC_BAR_CLASSES};
    InitCommonControlsEx(&icc);

    for (;;) {
        auto s = load_settings();
        if (!s || !s->paired) {
            const Settings* prev = s ? &*s : nullptr;
            if (run_setup_dialog(nullptr, prev) != IDOK) break;
            continue;                                   // re-read the settings the wizard just wrote
        }
        const int r = run_connect_dialog(nullptr, *s);
        // IDC_CONN_SETUP_AGAIN → wizard with the current settings; IDC_CONN_REMOVE → the settings are gone,
        // so the next pass lands on the wizard by itself. Anything else (including a dialog failure) quits.
        if (r == IDC_CONN_SETUP_AGAIN) { if (run_setup_dialog(nullptr, &*s) != IDOK) break; continue; }
        if (r != IDC_CONN_REMOVE) break;
    }

    CoUninitialize();
    return 0;
}

}  // namespace scshr::app
