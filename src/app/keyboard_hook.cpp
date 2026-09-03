#include "app/app.h"
#include "common/log.h"

namespace scshr::app {

// Port of keyboard_grab.py's _Win32Grab: intercept ALL keys while our window is foreground, keep our own
// modifier bitmap (Win/Ctrl/left-Alt = "command" modifiers), deliver modifier-held combos and the
// modifier keys themselves directly to the session, let bare character keys flow to WM_CHAR so the
// user's layout / IME still apply. Shift and AltGr (right Alt) are never intercepted.
KeyboardHook* KeyboardHook::inst_ = nullptr;

namespace {
constexpr unsigned M_WIN = 1, M_CTRL = 2, M_ALT = 4;
bool is_command_modifier(unsigned vk) { return vk == VK_LWIN || vk == VK_RWIN || vk == VK_LCONTROL || vk == VK_RCONTROL || vk == VK_CONTROL || vk == VK_LMENU || vk == VK_MENU; }
}

KeyboardHook::KeyboardHook(HWND h, std::function<void(bool, uint32_t)> s) : hwnd_(h), send_(std::move(s)) { inst_ = this; }
KeyboardHook::~KeyboardHook() { disable(); if (inst_ == this) inst_ = nullptr; }

void KeyboardHook::enable() {
    if (hook_) return;
    hook_ = SetWindowsHookExW(WH_KEYBOARD_LL, &KeyboardHook::proc, GetModuleHandleW(nullptr), 0);
    if (!hook_) LOG_WARN("input", "keyboard grab unavailable (SetWindowsHookEx failed %lu)", GetLastError());
    else LOG_INFO("input", "keyboard grab acquired (Win32 LL hook)");
}

void KeyboardHook::disable() {
    if (!hook_) return;
    UnhookWindowsHookEx(hook_); hook_ = nullptr;
    // Release any modifiers we reported as held so the host doesn't see a stuck Cmd/Ctrl.
    if (mods_ & M_WIN) send_(false, 0xffeb);
    if (mods_ & M_CTRL) send_(false, 0xffe3);
    if (mods_ & M_ALT) send_(false, 0xffe9);
    mods_ = 0;
    LOG_INFO("input", "keyboard grab released");
}

LRESULT CALLBACK KeyboardHook::proc(int code, WPARAM wp, LPARAM lp) { return inst_ ? inst_->handle(code, wp, lp) : CallNextHookEx(nullptr, code, wp, lp); }

LRESULT KeyboardHook::handle(int code, WPARAM wp, LPARAM lp) {
    if (code != HC_ACTION || GetForegroundWindow() != hwnd_) return CallNextHookEx(hook_, code, wp, lp);
    const auto* k = reinterpret_cast<const KBDLLHOOKSTRUCT*>(lp);
    const bool down = wp == WM_KEYDOWN || wp == WM_SYSKEYDOWN;
    const unsigned vk = k->vkCode;
    if (k->dwExtraInfo == 0x5C5D) return CallNextHookEx(hook_, code, wp, lp);   // our own injected events (none today)
    if (is_command_modifier(vk)) {
        const unsigned bit = (vk == VK_LWIN || vk == VK_RWIN) ? M_WIN : (vk == VK_LMENU || vk == VK_MENU) ? M_ALT : M_CTRL;
        if (down) mods_ |= bit; else mods_ &= ~bit;
        send_(down, vk_to_keysym(vk, (k->flags & LLKHF_EXTENDED) != 0));
        return 1;   // swallow: Start menu / Alt menu never see it
    }
    if (mods_ == 0) return CallNextHookEx(hook_, code, wp, lp);   // bare key → normal WM_KEYDOWN/WM_CHAR path
    uint32_t ks = vk_to_keysym(vk, (k->flags & LLKHF_EXTENDED) != 0);
    if (!ks) ks = vk_to_keysym_letter(vk);
    if (!ks) return CallNextHookEx(hook_, code, wp, lp);
    send_(down, ks);
    return 1;
}

}  // namespace scshr::app
