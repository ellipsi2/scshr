#include "media/quality_gate.h"
#include "common/log.h"

namespace scshr {

FrameQualityGate::FrameQualityGate(int n)
    : states_(size_t(n)), fir_last_(size_t(n), 0), fir_attempts_(size_t(n), 0), cap_warned_(size_t(n), false), cycle_count_(size_t(n), 0), idr_observed_at_(size_t(n), 0) {}

void FrameQualityGate::mark_decode_error(int tile, int64_t now, bool reliable) {
    if (tile < 0 || tile >= num_tiles()) return;
    last_concealment_ns_ = now;
    if (!reliable) last_unreliable_concealment_ns_ = now;
    if (idr_observed_at_[size_t(tile)] > 0 && now - idr_observed_at_[size_t(tile)] < post_idr_grace_ns) {
        LOG_DEBUG("gate", "tile %d post-IDR error suppressed (%.0f ms after IDR)", tile, double(now - idr_observed_at_[size_t(tile)]) / 1e6);
        return;
    }
    TileState& st = states_[size_t(tile)];
    ++st.bad_streak;
    st.needs_real_frame = true;
    if (!keyframe_required_.count(tile)) {
        keyframe_required_.insert(tile);
        idr_observed_.erase(tile);
        fir_attempts_[size_t(tile)] = 0;
        cap_warned_[size_t(tile)] = false;
        ++flicker_events;
        ++cycle_count_[size_t(tile)];
        LOG_DEBUG("gate", "tile %d decode error -> keyframe required (cycle %d)", tile, cycle_count_[size_t(tile)]);
    }
}

void FrameQualityGate::mark_idr_observed(int tile, int64_t now, bool suspicious) {
    if (tile < 0 || tile >= num_tiles()) return;
    idr_observed_at_[size_t(tile)] = now;
    if (suspicious) return;
    if (keyframe_required_.count(tile)) idr_observed_.insert(tile);
}

void FrameQualityGate::mark_clean(int tile, int64_t now) {
    if (tile < 0 || tile >= num_tiles()) return;
    TileState& st = states_[size_t(tile)];
    st.bad_streak = 0; st.needs_real_frame = false;
    if (keyframe_required_.count(tile) && idr_observed_.count(tile) && now - last_unreliable_concealment_ns_ >= recovery_quiet_ns) {
        keyframe_required_.erase(tile); idr_observed_.erase(tile);
        fir_attempts_[size_t(tile)] = 0; cap_warned_[size_t(tile)] = false;
        LOG_DEBUG("gate", "tile %d recovered (IDR + clean decode)", tile);
        if (cycle_count_[size_t(tile)] >= 3) { LOG_WARN("gate", "tile %d cycled %d times — keeps recovering but next P-frame keeps erroring", tile, cycle_count_[size_t(tile)]); cycle_count_[size_t(tile)] = 0; }
    }
}

std::set<int> FrameQualityGate::consume_fir_request(int64_t now) {
    if (keyframe_required_.empty()) return {};
    const bool capped = fir_attempts_[0] >= re_arm_cap;
    const int64_t interval = capped ? re_arm_slow_interval_ns : re_arm_interval_ns;
    if (now - fir_last_[0] < interval) return {};
    fir_last_[0] = now;
    ++fir_attempts_[0];
    if (capped && !cap_warned_[0]) {
        LOG_WARN("gate", "Host slow to respond to FIR after %d attempts (%zu tiles still need recovery); backing off to a %.0fs retry", fir_attempts_[0] - 1, keyframe_required_.size(), double(re_arm_slow_interval_ns) / 1e9);
        cap_warned_[0] = true;
    }
    return {0};
}

void FrameQualityGate::force_keyframe_all(int64_t now) { for (int i = 0; i < num_tiles(); ++i) mark_decode_error(i, now); }

void FrameQualityGate::reset() { for (int i = 0; i < num_tiles(); ++i) reset_tile(i); }

void FrameQualityGate::reset_tile(int t) {
    if (t < 0 || t >= num_tiles()) return;
    states_[size_t(t)] = TileState{};
    keyframe_required_.erase(t); idr_observed_.erase(t);
    fir_attempts_[size_t(t)] = 0; cap_warned_[size_t(t)] = false; cycle_count_[size_t(t)] = 0; idr_observed_at_[size_t(t)] = 0;
}

}  // namespace scshr
