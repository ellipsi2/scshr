#pragma once
// Per-tile keyframe-required state with libwebrtc-style sticky semantics (media/quality_gate.py).
// Time injected in ns for deterministic tests.
#include <cstdint>
#include <set>
#include <vector>

namespace scshr {

class FrameQualityGate {
public:
    explicit FrameQualityGate(int num_tiles);
    void mark_decode_error(int tile, int64_t now_ns, bool reliable = true);
    void mark_idr_observed(int tile, int64_t now_ns, bool suspicious = false);
    void mark_clean(int tile, int64_t now_ns);
    std::set<int> consume_fir_request(int64_t now_ns);  // at most {0}
    void force_keyframe_all(int64_t now_ns);
    void reset();
    void reset_tile(int tile);

    const std::set<int>& keyframe_required() const { return keyframe_required_; }
    std::set<int> bad_tiles() const { return keyframe_required_; }
    int bad_streak(int tile) const { return states_[size_t(tile)].bad_streak; }
    int fir_attempts_tile0() const { return fir_attempts_[0]; }
    int num_tiles() const { return int(states_.size()); }
    uint64_t flicker_events = 0;

    // Tunables (ns / counts) — reference defaults.
    int64_t re_arm_interval_ns = 1'000'000'000;
    int re_arm_cap = 8;
    int64_t re_arm_slow_interval_ns = 4'000'000'000;
    int64_t post_idr_grace_ns = 500'000'000;
    int64_t recovery_quiet_ns = 1'500'000'000;

private:
    struct TileState { int bad_streak = 0; bool needs_real_frame = false; };
    std::vector<TileState> states_;
    std::set<int> keyframe_required_, idr_observed_;
    std::vector<int64_t> fir_last_;
    std::vector<int> fir_attempts_;
    std::vector<bool> cap_warned_;
    std::vector<int> cycle_count_;
    std::vector<int64_t> idr_observed_at_;
    int64_t last_concealment_ns_ = 0, last_unreliable_concealment_ns_ = 0;
};

}  // namespace scshr
