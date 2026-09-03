#include "common/log.h"
#include "common/bytes.h"
#include "common/clock.h"

#include <atomic>
#include <cstdio>
#include <mutex>
#include <windows.h>

namespace scshr {

namespace {
std::atomic<int> g_level{int(LogLevel::Info)};
std::mutex g_mu;
FILE* g_file = nullptr;
const char* level_name(LogLevel l) {
    switch (l) { case LogLevel::Debug: return "DEBUG"; case LogLevel::Info: return "INFO "; case LogLevel::Warn: return "WARN "; default: return "ERROR"; }
}
}  // namespace

void log_set_level(LogLevel lvl) { g_level.store(int(lvl)); }
LogLevel log_level() { return LogLevel(g_level.load(std::memory_order_relaxed)); }

void log_set_file(const std::string& path) {
    std::lock_guard<std::mutex> lk(g_mu);
    if (g_file) { fclose(g_file); g_file = nullptr; }
    if (!path.empty()) g_file = fopen(path.c_str(), "ab");
}

void log_vwrite(LogLevel lvl, const char* tag, const char* fmt, va_list ap) {
    char msg[2048];
    vsnprintf(msg, sizeof msg, fmt, ap);
    SYSTEMTIME st; GetLocalTime(&st);
    char line[2304];
    int n = snprintf(line, sizeof line, "%02d:%02d:%02d.%03d %s %-8s | %s\n", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, level_name(lvl), tag, msg);
    if (n < 0) return;
    std::lock_guard<std::mutex> lk(g_mu);
    fwrite(line, 1, size_t(n), stderr);
    if (g_file) { fwrite(line, 1, size_t(n), g_file); fflush(g_file); }
}

void log_write(LogLevel lvl, const char* tag, const char* fmt, ...) {
    va_list ap; va_start(ap, fmt); log_vwrite(lvl, tag, fmt, ap); va_end(ap);
}

std::string hex(ByteView b) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(b.size() * 2);
    for (uint8_t c : b) { s.push_back(d[c >> 4]); s.push_back(d[c & 15]); }
    return s;
}

Bytes unhex(std::string_view h) {
    Bytes out; out.reserve(h.size() / 2);
    auto nib = [](char c) -> int { if (c >= '0' && c <= '9') return c - '0'; if (c >= 'a' && c <= 'f') return c - 'a' + 10; if (c >= 'A' && c <= 'F') return c - 'A' + 10; return -1; };
    for (size_t i = 0; i + 1 < h.size(); i += 2) {
        int a = nib(h[i]), b = nib(h[i + 1]);
        if (a < 0 || b < 0) break;
        out.push_back(uint8_t(a * 16 + b));
    }
    return out;
}

}  // namespace scshr
