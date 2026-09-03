#pragma once
// Minimal leveled logger. Never used per-packet on the hot path; rate-limit helper below.
#include <cstdarg>
#include <cstdint>
#include <string>

namespace scshr {

enum class LogLevel { Debug = 0, Info = 1, Warn = 2, Error = 3 };

void log_set_level(LogLevel lvl);
LogLevel log_level();
void log_set_file(const std::string& path);  // tee to file (empty = none)
void log_write(LogLevel lvl, const char* tag, const char* fmt, ...);
void log_vwrite(LogLevel lvl, const char* tag, const char* fmt, va_list ap);

#define SCSHR_LOG(lvl, tag, ...) do { if (::scshr::log_level() <= (lvl)) ::scshr::log_write((lvl), (tag), __VA_ARGS__); } while (0)
#define LOG_DEBUG(tag, ...) SCSHR_LOG(::scshr::LogLevel::Debug, tag, __VA_ARGS__)
#define LOG_INFO(tag, ...)  SCSHR_LOG(::scshr::LogLevel::Info, tag, __VA_ARGS__)
#define LOG_WARN(tag, ...)  SCSHR_LOG(::scshr::LogLevel::Warn, tag, __VA_ARGS__)
#define LOG_ERROR(tag, ...) SCSHR_LOG(::scshr::LogLevel::Error, tag, __VA_ARGS__)

// Rate limiter for event logs that could fire per packet/frame: logs the 1st, 10th, 100th, ... occurrence.
struct LogDecimator {
    uint64_t n = 0;
    bool tick() { ++n; return n == 1 || n == 10 || n == 100 || n == 1000 || (n % 10000) == 0; }
};

}  // namespace scshr
