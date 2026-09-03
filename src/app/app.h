#pragma once
// Desktop viewer pieces: Win32 window, input mapping, low-level keyboard grab, local clipboard.
#include "common/bytes.h"

#include <functional>
#include <optional>
#include <string>
#include <windows.h>

namespace scshr::app {

struct WindowEvents {
    std::function<void(int w, int h)> on_resize;
    std::function<void(int x, int y)> on_mouse_move;          // client px
    std::function<void(int button_bit, bool down, int x, int y)> on_mouse_button;
    std::function<void(int x, int y, double wheel_notches)> on_wheel;
    std::function<void(bool down, uint32_t keysym, bool repeat)> on_key;
    std::function<void(uint32_t codepoint)> on_char;
    std::function<void(bool entered)> on_mouse_enter;
    std::function<void(bool focused)> on_focus;
    std::function<void()> on_close;
    std::function<void()> on_display_change;
};

class Window {
public:
    Window(const std::wstring& title, int client_w, int client_h, WindowEvents ev);
    ~Window();
    HWND hwnd() const { return hwnd_; }
    void pump();                     // process pending messages (non-blocking)
    bool closed() const { return closed_; }
    std::pair<int, int> client_size() const;
    float dpi_scale() const;
    void set_title(const std::wstring& t);
    void set_client_size(int w, int h);
    void lock_aspect(int w, int h);  // 0,0 = free
    void show_cursor(bool show);
    bool focused() const;
    static void run_message_pump_once();
private:
    static LRESULT CALLBACK wndproc(HWND, UINT, WPARAM, LPARAM);
    LRESULT handle(UINT, WPARAM, LPARAM);
    HWND hwnd_ = nullptr;
    WindowEvents ev_;
    bool closed_ = false, tracking_ = false, cursor_hidden_ = false;
    int aspect_w_ = 0, aspect_h_ = 0;
    int last_x_ = 0, last_y_ = 0;
};

// Win32 VK → X11 keysym for the special keys (port of keymap.py / keyboard_grab.py tables). 0 = printable (use WM_CHAR).
uint32_t vk_to_keysym(unsigned vk, bool extended);
uint32_t vk_to_keysym_letter(unsigned vk);          // A-Z/0-9/space for modifier-held combos

// Low-level keyboard hook: while our window is foreground, intercept modifier combos (Win/Ctrl/Alt) so the
// OS doesn't act on them and deliver them straight to the session (Moonlight/SDL pattern).
class KeyboardHook {
public:
    KeyboardHook(HWND our_hwnd, std::function<void(bool down, uint32_t keysym)> sender);
    ~KeyboardHook();
    void enable();
    void disable();
    void set_window(HWND h) { hwnd_ = h; }
private:
    HWND hwnd_;
    std::function<void(bool, uint32_t)> send_;
    HHOOK hook_ = nullptr;
    unsigned mods_ = 0;
    static LRESULT CALLBACK proc(int code, WPARAM wp, LPARAM lp);
    LRESULT handle(int code, WPARAM wp, LPARAM lp);
    static KeyboardHook* inst_;
};

std::optional<std::string> clipboard_read_text();
bool clipboard_write_text(const std::string& utf8);

}  // namespace scshr::app
