#pragma once
// Rolling-window latency statistics (median / p95 / p99 / max) over the last N samples.
// Cheap insert; percentiles computed on demand (telemetry tick, ~2 Hz).
#include <algorithm>
#include <cstdint>
#include <mutex>
#include <vector>

namespace scshr {

class RollingStats {
public:
    explicit RollingStats(size_t window = 600) : win_(window) { samples_.reserve(window); }
    void add(double v) {
        std::lock_guard<std::mutex> lk(mu_);
        if (samples_.size() < win_) samples_.push_back(v);
        else samples_[pos_ % win_] = v;
        ++pos_; ++total_;
    }
    struct Summary { double median = 0, p95 = 0, p99 = 0, max = 0, mean = 0; size_t n = 0; uint64_t total = 0; };
    Summary summary() const {
        std::vector<double> s;
        uint64_t total;
        { std::lock_guard<std::mutex> lk(mu_); s = samples_; total = total_; }
        Summary out; out.n = s.size(); out.total = total;
        if (s.empty()) return out;
        std::sort(s.begin(), s.end());
        auto pct = [&](double p) { size_t i = size_t(p * double(s.size() - 1) + 0.5); return s[std::min(i, s.size() - 1)]; };
        out.median = pct(0.5); out.p95 = pct(0.95); out.p99 = pct(0.99); out.max = s.back();
        double sum = 0; for (double v : s) sum += v; out.mean = sum / double(s.size());
        return out;
    }
    void reset() { std::lock_guard<std::mutex> lk(mu_); samples_.clear(); pos_ = 0; }
private:
    mutable std::mutex mu_;
    size_t win_;
    std::vector<double> samples_;
    size_t pos_ = 0;
    uint64_t total_ = 0;
};

}  // namespace scshr
