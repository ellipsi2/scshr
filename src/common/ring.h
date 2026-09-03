#pragma once
// Bounded single-producer / single-consumer ring of T (trivially movable). Lock-free by
// construction: one writer index, one reader index, both atomics with acquire/release.
#include <atomic>
#include <cstddef>
#include <optional>
#include <utility>
#include <vector>

namespace scshr {

template <typename T>
class SpscRing {
public:
    explicit SpscRing(size_t capacity_pow2) : buf_(capacity_pow2), mask_(capacity_pow2 - 1) {
        // capacity must be a power of two
    }
    bool push(T&& v) {
        const size_t w = write_.load(std::memory_order_relaxed);
        const size_t r = read_.load(std::memory_order_acquire);
        if (w - r >= buf_.size()) return false;
        buf_[w & mask_] = std::move(v);
        write_.store(w + 1, std::memory_order_release);
        return true;
    }
    std::optional<T> pop() {
        const size_t r = read_.load(std::memory_order_relaxed);
        const size_t w = write_.load(std::memory_order_acquire);
        if (r == w) return std::nullopt;
        T v = std::move(buf_[r & mask_]);
        read_.store(r + 1, std::memory_order_release);
        return v;
    }
    size_t size() const { return write_.load(std::memory_order_acquire) - read_.load(std::memory_order_acquire); }
    size_t capacity() const { return buf_.size(); }
private:
    std::vector<T> buf_;
    size_t mask_;
    alignas(64) std::atomic<size_t> write_{0};
    alignas(64) std::atomic<size_t> read_{0};
};

}  // namespace scshr
