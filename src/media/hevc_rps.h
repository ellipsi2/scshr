#pragma once
// HEVC slice-header RPS tracker (media/hevc_rps.py): pre-decode "will this slice conceal?" detection,
// LTRP-use / far-reference telemetry, and the DONL/POC bookkeeping the LTR ack needs.
#include "common/bytes.h"

#include <optional>
#include <set>
#include <vector>

namespace scshr {

struct HevcShortTermRps { std::vector<std::pair<int, bool>> deltas; };

struct HevcSpsState {
    int log2_max_pic_order_cnt_lsb = 8;
    int num_short_term_ref_pic_sets = 0;
    std::vector<HevcShortTermRps> short_term_rps_sets;
    int num_long_term_ref_pics_sps = 0;
    bool long_term_ref_pics_present_flag = false;
    bool sample_adaptive_offset_enabled_flag = false;
    bool separate_colour_plane_flag = false;
    int pic_width_in_luma_samples = 0, pic_height_in_luma_samples = 0;
    int log2_min_luma_coding_block_size_minus3 = 0, log2_diff_max_min_luma_coding_block_size = 0;
    int chroma_format_idc = 1;
    bool parsed = false;
};

HevcSpsState hevc_parse_sps(ByteView rbsp_no_header_epb_stripped);

struct SliceRps { uint32_t poc_lsb; std::vector<std::pair<int, bool>> deltas; int num_long_term; };
std::optional<SliceRps> hevc_parse_slice_rps(int nal_unit_type, ByteView rbsp_after_nal_header, const HevcSpsState& sps);

class HevcRpsTracker {
public:
    void reset();
    void feed_sps(ByteView sps_nal_payload_after_header);   // EPB not yet stripped
    // Returns POCs the slice references that were never fed (may be empty). Side effect: advances POC state.
    std::set<int> check_slice(ByteView nal);
    void commit_decoded();
    bool has_sps() const { return sps_.parsed; }
    const HevcSpsState& sps() const { return sps_; }
    uint64_t checks = 0, missing_ref_events = 0, ltr_ref_events = 0, far_ref_events = 0;
    int max_ref_distance = 0;
    size_t seen_count() const { return seen_pocs_.size(); }
private:
    HevcSpsState sps_;
    std::set<int> seen_pocs_;
    int prev_poc_msb_ = 0, prev_poc_lsb_ = 0;
    std::optional<int> last_checked_poc_;
};

}  // namespace scshr
