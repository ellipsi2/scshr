#pragma once
// Monotonic high-resolution clock (QueryPerformanceCounter), nanoseconds.
#include <cstdint>

namespace scshr {

int64_t now_ns();          // monotonic, QPC-based
double now_s();
int64_t wall_time_ns();    // Unix epoch (for RTCP NTP fields)
inline double ns_to_ms(int64_t ns) { return double(ns) / 1e6; }

}  // namespace scshr
