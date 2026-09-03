#pragma once
// Launcher GUI (pure Win32 + comctl32 v6; no framework). Entered when scshr.exe starts without
// command-line arguments. Owns the whole non-technical user journey:
//
//   not paired  → Setup wizard (Mac address, Mac user, password → progress → done/failed)
//   paired      → Connect page (Mac name + live link status, Screen Sharing user/password,
//                 [Remember password], [Connect]; menu: Check connection, Set up again, Remove)
//   connected   → the launcher hides, the viewer runs (app/viewer.h); when the viewer returns
//                 with a lost connection the launcher offers Reconnect / Close.
//
// All text is plain language: no mention of keys, WireGuard, routes or ports unless something
// failed and the detail explains what to do (e.g. "forward UDP port 51820 to the Mac").
#include <windows.h>

#include <string>

namespace scshr::app {

int run_gui(HINSTANCE instance);

// Shows a plain-language error/notice box owned by the current foreground window.
void gui_message(const wchar_t* title, const std::wstring& text, bool error);

}  // namespace scshr::app
