#include "media/hevc_rps.h"
#include "common/log.h"
#include "media/bitstream.h"
#include "media/nalu.h"

#include <cstdlib>

namespace scshr {

namespace {
void skip_profile_tier_level(BitReader& br, int max_sub_layers) {
    br.read(8); br.read(32); br.read(48); br.read(8);
    std::vector<int> spp, slp;
    for (int i = 0; i < max_sub_layers - 1; ++i) { spp.push_back(int(br.read1())); slp.push_back(int(br.read1())); }
    if (max_sub_layers > 1) for (int i = max_sub_layers - 1; i < 8; ++i) br.read(2);
    for (int i = 0; i < max_sub_layers - 1; ++i) { if (spp[size_t(i)]) br.read(8 + 32 + 48); if (slp[size_t(i)]) br.read(8); }
}

HevcShortTermRps parse_st_ref_pic_set(BitReader& br, int idx, int num_in_sps, const std::vector<HevcShortTermRps>& sets) {
    HevcShortTermRps out;
    uint32_t inter = 0;
    if (idx != 0) inter = br.read1();
    if (inter) {
        uint32_t delta_idx_minus1 = 0;
        if (idx == num_in_sps) delta_idx_minus1 = br.read_ue();
        const uint32_t delta_rps_sign = br.read1();
        const uint32_t abs_delta_rps_minus1 = br.read_ue();
        const int delta_rps = (1 - 2 * int(delta_rps_sign)) * (int(abs_delta_rps_minus1) + 1);
        const int ref_idx = idx - (int(delta_idx_minus1) + 1);
        if (ref_idx < 0 || ref_idx >= int(sets.size())) return out;
        const HevcShortTermRps& ref = sets[size_t(ref_idx)];
        const size_t n_ref = ref.deltas.size() + 1;
        std::vector<int> used_by_curr, use_delta;
        for (size_t i = 0; i < n_ref; ++i) { used_by_curr.push_back(int(br.read1())); int udf = 1; if (!used_by_curr.back()) udf = int(br.read1()); use_delta.push_back(udf); }
        // Mirrors the reference derivation (only negative-delta entries are produced; matches the Python port).
        for (size_t i = 0; i < ref.deltas.size(); ++i) {
            const auto& rd = ref.deltas[ref.deltas.size() - 1 - i];
            const int d = rd.first + delta_rps;
            if (d < 0 && use_delta[i]) out.deltas.emplace_back(d, used_by_curr[i] != 0);
        }
        if (delta_rps < 0 && use_delta[n_ref - 1]) out.deltas.emplace_back(delta_rps, used_by_curr[n_ref - 1] != 0);
        return out;
    }
    const uint32_t nneg = br.read_ue(), npos = br.read_ue();
    if (nneg > 64 || npos > 64) return out;
    int last = 0;
    for (uint32_t i = 0; i < nneg; ++i) { const int d = last - (int(br.read_ue()) + 1); const bool used = br.read1(); last = d; out.deltas.emplace_back(d, used); }
    last = 0;
    for (uint32_t i = 0; i < npos; ++i) { const int d = last + (int(br.read_ue()) + 1); const bool used = br.read1(); last = d; out.deltas.emplace_back(d, used); }
    return out;
}
}  // namespace

HevcSpsState hevc_parse_sps(ByteView rbsp) {
    HevcSpsState st;
    BitReader br(rbsp);
    br.read(4);
    const int max_sub_layers_minus1 = int(br.read(3));
    br.read1();
    skip_profile_tier_level(br, max_sub_layers_minus1 + 1);
    br.read_ue();
    st.chroma_format_idc = int(br.read_ue());
    if (st.chroma_format_idc == 3) st.separate_colour_plane_flag = br.read1() != 0;
    st.pic_width_in_luma_samples = int(br.read_ue());
    st.pic_height_in_luma_samples = int(br.read_ue());
    if (br.read1()) { br.read_ue(); br.read_ue(); br.read_ue(); br.read_ue(); }
    br.read_ue(); br.read_ue();
    st.log2_max_pic_order_cnt_lsb = int(br.read_ue()) + 4;
    const uint32_t sub_layer_ordering_info_present = br.read1();
    const int n_sub_lo = sub_layer_ordering_info_present ? max_sub_layers_minus1 + 1 : 1;
    for (int i = 0; i < n_sub_lo; ++i) { br.read_ue(); br.read_ue(); br.read_ue(); }
    st.log2_min_luma_coding_block_size_minus3 = int(br.read_ue());
    st.log2_diff_max_min_luma_coding_block_size = int(br.read_ue());
    br.read_ue(); br.read_ue(); br.read_ue(); br.read_ue();
    if (br.read1()) { if (br.read1()) { LOG_WARN("hevc_rps", "SPS contains scaling_list_data; parser may misalign"); st.parsed = true; return st; } }
    br.read1();
    st.sample_adaptive_offset_enabled_flag = br.read1() != 0;
    if (br.read1()) { br.read(4); br.read(4); br.read_ue(); br.read_ue(); br.read1(); }
    st.num_short_term_ref_pic_sets = int(br.read_ue());
    if (st.num_short_term_ref_pic_sets > 64) st.num_short_term_ref_pic_sets = 0;
    for (int i = 0; i < st.num_short_term_ref_pic_sets; ++i) st.short_term_rps_sets.push_back(parse_st_ref_pic_set(br, i, st.num_short_term_ref_pic_sets, st.short_term_rps_sets));
    st.long_term_ref_pics_present_flag = br.read1() != 0;
    if (st.long_term_ref_pics_present_flag) st.num_long_term_ref_pics_sps = int(br.read_ue());
    st.parsed = !br.overrun();
    return st;
}

std::optional<SliceRps> hevc_parse_slice_rps(int nal_unit_type, ByteView rbsp, const HevcSpsState& sps) {
    BitReader br(rbsp);
    const uint32_t first_slice = br.read1();
    if (hevc_is_irap(nal_unit_type)) br.read1();
    br.read_ue();
    if (!first_slice) {
        const int min_cb_log2 = sps.log2_min_luma_coding_block_size_minus3 + 3;
        const int ctb_log2 = min_cb_log2 + sps.log2_diff_max_min_luma_coding_block_size;
        if (ctb_log2 < 4 || ctb_log2 > 6 || sps.pic_width_in_luma_samples == 0) return std::nullopt;
        const int ctb = 1 << ctb_log2;
        const int cw = (sps.pic_width_in_luma_samples + ctb - 1) / ctb, chh = (sps.pic_height_in_luma_samples + ctb - 1) / ctb;
        const int num = cw * chh;
        if (num <= 1) return std::nullopt;
        int bits = 0; while ((1 << bits) < num) ++bits;  // ceil(log2(num))
        br.read(bits);
    }
    const uint32_t slice_type = br.read_ue();
    if (sps.separate_colour_plane_flag) br.read(2);
    if (nal_unit_type == 19 || nal_unit_type == 20) return SliceRps{0, {}, 0};
    const uint32_t poc_lsb = br.read(sps.log2_max_pic_order_cnt_lsb);
    const uint32_t st_sps_flag = br.read1();
    HevcShortTermRps rps;
    if (!st_sps_flag) rps = parse_st_ref_pic_set(br, sps.num_short_term_ref_pic_sets, sps.num_short_term_ref_pic_sets, sps.short_term_rps_sets);
    else if (sps.num_short_term_ref_pic_sets > 1) {
        int bits = 0; while ((1 << bits) < sps.num_short_term_ref_pic_sets) ++bits;
        const uint32_t idx = br.read(bits);
        if (idx >= sps.short_term_rps_sets.size()) return std::nullopt;
        rps = sps.short_term_rps_sets[idx];
    } else {
        if (sps.short_term_rps_sets.empty()) return SliceRps{poc_lsb, {}, 0};
        rps = sps.short_term_rps_sets[0];
    }
    int num_lt = 0;
    if (sps.long_term_ref_pics_present_flag) {
        const uint32_t num_lt_sps = sps.num_long_term_ref_pics_sps > 0 ? br.read_ue() : 0;
        const uint32_t num_lt_pics = br.read_ue();
        num_lt = int(num_lt_sps + num_lt_pics);
    }
    if (br.overrun()) return std::nullopt;
    if (slice_type == 2) return SliceRps{poc_lsb, {}, num_lt};
    return SliceRps{poc_lsb, rps.deltas, num_lt};
}

void HevcRpsTracker::reset() { seen_pocs_.clear(); prev_poc_msb_ = 0; prev_poc_lsb_ = 0; last_checked_poc_.reset(); }

void HevcRpsTracker::feed_sps(ByteView sps_payload) {
    sps_ = hevc_parse_sps(view(remove_emulation_prevention(sps_payload)));
    if (sps_.parsed)
        LOG_INFO("hevc_rps", "SPS log2_max_poc_lsb=%d pic=%dx%d chroma_format=%d num_st_rps=%d long_term_present=%d", sps_.log2_max_pic_order_cnt_lsb,
                 sps_.pic_width_in_luma_samples, sps_.pic_height_in_luma_samples, sps_.chroma_format_idc, sps_.num_short_term_ref_pic_sets, int(sps_.long_term_ref_pics_present_flag));
    else LOG_WARN("hevc_rps", "SPS parse failed");
}

std::set<int> HevcRpsTracker::check_slice(ByteView nal) {
    last_checked_poc_.reset();
    std::set<int> missing;
    if (!sps_.parsed || nal.size() < 3) return missing;
    const int nt = hevc_nal_type(nal[0]);
    Bytes rbsp = remove_emulation_prevention(nal.subspan(2, std::min<size_t>(nal.size() - 2, 256)));
    auto res = hevc_parse_slice_rps(nt, view(rbsp), sps_);
    if (!res) return missing;
    if (res->num_long_term > 0) {
        ++ltr_ref_events;
        if (ltr_ref_events == 1 || ltr_ref_events == 10 || ltr_ref_events == 50 || ltr_ref_events == 200 || ltr_ref_events == 1000)
            LOG_INFO("hevc_rps", "server is using LTRP: %llu slices referenced a long-term picture", (unsigned long long)ltr_ref_events);
    }
    const int max_poc_lsb = 1 << sps_.log2_max_pic_order_cnt_lsb;
    int poc;
    if (nt == 19 || nt == 20) { poc = 0; prev_poc_msb_ = 0; prev_poc_lsb_ = 0; }
    else {
        const int lsb = int(res->poc_lsb);
        int cur_msb;
        if (lsb < prev_poc_lsb_ && (prev_poc_lsb_ - lsb) >= max_poc_lsb / 2) cur_msb = prev_poc_msb_ + max_poc_lsb;
        else if (lsb > prev_poc_lsb_ && (lsb - prev_poc_lsb_) > max_poc_lsb / 2) cur_msb = prev_poc_msb_ - max_poc_lsb;
        else cur_msb = prev_poc_msb_;
        poc = cur_msb + lsb;
        prev_poc_msb_ = cur_msb; prev_poc_lsb_ = lsb;
    }
    ++checks;
    last_checked_poc_ = poc;
    int far = 0;
    for (auto& [delta, used] : res->deltas) {
        if (!used) continue;
        if (!seen_pocs_.count(poc + delta)) missing.insert(poc + delta);
        far = std::max(far, std::abs(delta));
    }
    if (!missing.empty()) ++missing_ref_events;
    if (far > max_ref_distance) max_ref_distance = far;
    if (far >= 16) ++far_ref_events;
    return missing;
}

void HevcRpsTracker::commit_decoded() {
    if (!last_checked_poc_) return;
    seen_pocs_.insert(*last_checked_poc_);
    last_checked_poc_.reset();
    // Bound the shadow-DPB set on very long sessions (the reference never evicts; keep the last 4096 POCs).
    if (seen_pocs_.size() > 8192) { auto it = seen_pocs_.begin(); std::advance(it, 4096); seen_pocs_.erase(seen_pocs_.begin(), it); }
}

}  // namespace scshr
