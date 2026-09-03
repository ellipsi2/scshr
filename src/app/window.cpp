#include "app/app.h"
#include "common/log.h"

#include <shellscalingapi.h>
#include <mutex>
#include <windowsx.h>

namespace scshr::app {

namespace {
const wchar_t* CLASS_NAME = L"scshr_viewer";
bool g_class_registered = false;
}

Window::Window(const std::wstring& title, int cw, int ch, WindowEvents ev) : ev_(std::move(ev)) {
    static std::once_flag once;
    std::call_once(once, [] { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2); });
    if (!g_class_registered) {
        WNDCLASSEXW wc{}; wc.cbSize = sizeof wc; wc.style = CS_HREDRAW | CS_VREDRAW | CS_OWNDC; wc.lpfnWndProc = &Window::wndproc; wc.hInstance = GetModuleHandleW(nullptr);
        wc.hCursor = LoadCursorW(nullptr, IDC_ARROW); wc.lpszClassName = CLASS_NAME; wc.hbrBackground = nullptr;
        RegisterClassExW(&wc); g_class_registered = true;
    }
    RECT r{0, 0, cw, ch};
    AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW, FALSE);
    hwnd_ = CreateWindowExW(0, CLASS_NAME, title.c_str(), WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, r.right - r.left, r.bottom - r.top, nullptr, nullptr, GetModuleHandleW(nullptr), this);
    ShowWindow(hwnd_, SW_SHOW);
}

Window::~Window() { if (hwnd_) DestroyWindow(hwnd_); }

LRESULT CALLBACK Window::wndproc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_NCCREATE) { auto* cs = reinterpret_cast<CREATESTRUCTW*>(l); SetWindowLongPtrW(h, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(cs->lpCreateParams)); }
    auto* self = reinterpret_cast<Window*>(GetWindowLongPtrW(h, GWLP_USERDATA));
    if (self && !self->hwnd_) self->hwnd_ = h;   // messages arrive during CreateWindowExW, before the ctor stores the handle
    return self ? self->handle(m, w, l) : DefWindowProcW(h, m, w, l);
}

LRESULT Window::handle(UINT m, WPARAM w, LPARAM l) {
    switch (m) {
    case WM_SIZE: if (ev_.on_resize && w != SIZE_MINIMIZED) ev_.on_resize(LOWORD(l), HIWORD(l)); return 0;
    case WM_SIZING:
        if (aspect_w_ > 0 && aspect_h_ > 0) {
            RECT* r = reinterpret_cast<RECT*>(l);
            RECT frame{0, 0, 0, 0}; AdjustWindowRect(&frame, WS_OVERLAPPEDWINDOW, FALSE);
            const int fw = frame.right - frame.left, fh = frame.bottom - frame.top;
            int cw = r->right - r->left - fw, ch = r->bottom - r->top - fh;
            const double asp = double(aspect_w_) / double(aspect_h_);
            if (w == WMSZ_LEFT || w == WMSZ_RIGHT || w == WMSZ_BOTTOMLEFT || w == WMSZ_BOTTOMRIGHT || w == WMSZ_TOPLEFT || w == WMSZ_TOPRIGHT) ch = int(cw / asp + 0.5); else cw = int(ch * asp + 0.5);
            if (w == WMSZ_TOP || w == WMSZ_TOPLEFT || w == WMSZ_TOPRIGHT) r->top = r->bottom - (ch + fh); else r->bottom = r->top + ch + fh;
            if (w == WMSZ_LEFT || w == WMSZ_TOPLEFT || w == WMSZ_BOTTOMLEFT) r->left = r->right - (cw + fw); else r->right = r->left + cw + fw;
            return TRUE;
        }
        break;
    case WM_MOUSEMOVE: {
        if (!tracking_) { TRACKMOUSEEVENT t{sizeof t, TME_LEAVE, hwnd_, 0}; TrackMouseEvent(&t); tracking_ = true; if (ev_.on_mouse_enter) ev_.on_mouse_enter(true); }
        last_x_ = GET_X_LPARAM(l); last_y_ = GET_Y_LPARAM(l);
        if (ev_.on_mouse_move) ev_.on_mouse_move(last_x_, last_y_);
        return 0;
    }
    case WM_MOUSELEAVE: tracking_ = false; if (ev_.on_mouse_enter) ev_.on_mouse_enter(false); return 0;
    case WM_LBUTTONDOWN: case WM_LBUTTONUP: case WM_RBUTTONDOWN: case WM_RBUTTONUP: case WM_MBUTTONDOWN: case WM_MBUTTONUP: {
        const int bit = (m == WM_LBUTTONDOWN || m == WM_LBUTTONUP) ? 1 : (m == WM_RBUTTONDOWN || m == WM_RBUTTONUP) ? 2 : 4;
        const bool down = m == WM_LBUTTONDOWN || m == WM_RBUTTONDOWN || m == WM_MBUTTONDOWN;
        if (down) SetCapture(hwnd_); else ReleaseCapture();
        if (ev_.on_mouse_button) ev_.on_mouse_button(bit, down, GET_X_LPARAM(l), GET_Y_LPARAM(l));
        return 0;
    }
    case WM_MOUSEWHEEL: {
        POINT pt{GET_X_LPARAM(l), GET_Y_LPARAM(l)}; ScreenToClient(hwnd_, &pt);
        if (ev_.on_wheel) ev_.on_wheel(pt.x, pt.y, double(GET_WHEEL_DELTA_WPARAM(w)) / WHEEL_DELTA);
        return 0;
    }
    case WM_KEYDOWN: case WM_SYSKEYDOWN: case WM_KEYUP: case WM_SYSKEYUP: {
        const bool down = m == WM_KEYDOWN || m == WM_SYSKEYDOWN;
        const bool repeat = down && (l & (1 << 30));
        const bool extended = (l & (1 << 24)) != 0;
        unsigned vk = unsigned(w);
        // Distinguish left/right modifiers like GLFW does.
        if (vk == VK_SHIFT) vk = MapVirtualKeyW((l >> 16) & 0xFF, MAPVK_VSC_TO_VK_EX);
        else if (vk == VK_CONTROL) vk = extended ? VK_RCONTROL : VK_LCONTROL;
        else if (vk == VK_MENU) vk = extended ? VK_RMENU : VK_LMENU;
        if (ev_.on_key) ev_.on_key(down, vk_to_keysym(vk, extended), repeat);
        if (m == WM_SYSKEYDOWN && w == VK_F4) break;   // let Alt+F4 through to close
        return 0;
    }
    case WM_CHAR: case WM_SYSCHAR: {
        const uint32_t c = uint32_t(w);
        if (c >= 0x20 && c != 0x7F && ev_.on_char) {
            // Surrogate pairs arrive as two WM_CHARs; combine.
            static uint32_t hi = 0;
            if (c >= 0xD800 && c <= 0xDBFF) { hi = c; return 0; }
            if (c >= 0xDC00 && c <= 0xDFFF && hi) { ev_.on_char(0x10000 + ((hi - 0xD800) << 10) + (c - 0xDC00)); hi = 0; return 0; }
            ev_.on_char(c);
        }
        return 0;
    }
    case WM_SETFOCUS: if (ev_.on_focus) ev_.on_focus(true); return 0;
    case WM_KILLFOCUS: if (ev_.on_focus) ev_.on_focus(false); return 0;
    case WM_DISPLAYCHANGE: case WM_DPICHANGED: if (ev_.on_display_change) ev_.on_display_change(); if (m == WM_DPICHANGED) { RECT* r = reinterpret_cast<RECT*>(l); SetWindowPos(hwnd_, nullptr, r->left, r->top, r->right - r->left, r->bottom - r->top, SWP_NOZORDER | SWP_NOACTIVATE); return 0; } break;
    case WM_SETCURSOR: if (LOWORD(l) == HTCLIENT) { SetCursor(cursor_hidden_ ? nullptr : LoadCursorW(nullptr, IDC_ARROW)); return TRUE; } break;
    case WM_ERASEBKGND: return 1;
    case WM_CLOSE: closed_ = true; if (ev_.on_close) ev_.on_close(); return 0;
    case WM_DESTROY: closed_ = true; return 0;
    default: break;
    }
    return DefWindowProcW(hwnd_, m, w, l);
}

void Window::pump() { MSG msg; while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) { TranslateMessage(&msg); DispatchMessageW(&msg); } }
void Window::run_message_pump_once() { MSG msg; while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) { TranslateMessage(&msg); DispatchMessageW(&msg); } }
std::pair<int, int> Window::client_size() const { RECT r; GetClientRect(hwnd_, &r); return {r.right - r.left, r.bottom - r.top}; }
float Window::dpi_scale() const { return float(GetDpiForWindow(hwnd_)) / 96.0f; }
void Window::set_title(const std::wstring& t) { SetWindowTextW(hwnd_, t.c_str()); }
void Window::set_client_size(int w, int h) { RECT r{0, 0, w, h}; AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW, FALSE); SetWindowPos(hwnd_, nullptr, 0, 0, r.right - r.left, r.bottom - r.top, SWP_NOMOVE | SWP_NOZORDER | SWP_NOACTIVATE); }
void Window::lock_aspect(int w, int h) { aspect_w_ = w; aspect_h_ = h; }
void Window::show_cursor(bool show) { cursor_hidden_ = !show; }
bool Window::focused() const { return GetForegroundWindow() == hwnd_; }

}  // namespace scshr::app
