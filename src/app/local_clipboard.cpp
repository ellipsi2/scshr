#include "app/app.h"

namespace scshr::app {

namespace {
std::string wide_to_utf8(const wchar_t* w) {
    const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    std::string s(size_t(n > 0 ? n - 1 : 0), 0);
    if (n > 1) WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}
std::wstring utf8_to_wide(const std::string& s) {
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(size_t(n > 0 ? n - 1 : 0), 0);
    if (n > 1) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    return w;
}
}  // namespace

std::optional<std::string> clipboard_read_text() {
    if (!IsClipboardFormatAvailable(CF_UNICODETEXT)) return std::string();
    if (!OpenClipboard(nullptr)) return std::nullopt;
    std::optional<std::string> out;
    if (HANDLE h = GetClipboardData(CF_UNICODETEXT)) { if (auto* w = static_cast<const wchar_t*>(GlobalLock(h))) { out = wide_to_utf8(w); GlobalUnlock(h); } }
    CloseClipboard();
    return out;
}

bool clipboard_write_text(const std::string& utf8) {
    std::wstring w = utf8_to_wide(utf8);
    // CRLF for Windows consumers (the reference relies on pyperclip which does the same on Windows).
    std::wstring crlf; for (size_t i = 0; i < w.size(); ++i) { if (w[i] == L'\n' && (i == 0 || w[i - 1] != L'\r')) crlf.push_back(L'\r'); crlf.push_back(w[i]); }
    if (!OpenClipboard(nullptr)) return false;
    EmptyClipboard();
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, (crlf.size() + 1) * sizeof(wchar_t));
    if (!h) { CloseClipboard(); return false; }
    std::memcpy(GlobalLock(h), crlf.c_str(), (crlf.size() + 1) * sizeof(wchar_t));
    GlobalUnlock(h);
    SetClipboardData(CF_UNICODETEXT, h);
    CloseClipboard();
    return true;
}

}  // namespace scshr::app
