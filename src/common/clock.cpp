#include "common/clock.h"
#include <windows.h>

namespace scshr {

namespace {
struct Qpc {
    LARGE_INTEGER freq;
    Qpc() { QueryPerformanceFrequency(&freq); }
};
const Qpc& qpc() { static Qpc q; return q; }
}  // namespace

int64_t now_ns() {
    LARGE_INTEGER c; QueryPerformanceCounter(&c);
    const int64_t f = qpc().freq.QuadPart;
    // Split to avoid overflow: (c / f) * 1e9 + (c % f) * 1e9 / f
    return (c.QuadPart / f) * 1000000000LL + (c.QuadPart % f) * 1000000000LL / f;
}

double now_s() { return double(now_ns()) / 1e9; }

int64_t wall_time_ns() {
    FILETIME ft; GetSystemTimePreciseAsFileTime(&ft);
    uint64_t t = (uint64_t(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;  // 100ns since 1601
    return int64_t(t - 116444736000000000ULL) * 100;
}

}  // namespace scshr
