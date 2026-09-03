#pragma once
// RTCP feedback builders / SR parser (proxy/protocol/rtcp.py).
#include "common/bytes.h"

#include <map>
#include <set>
#include <tuple>
#include <vector>

namespace scshr::rtcp {

Bytes build_fir(uint32_t sender_ssrc, uint32_t target_ssrc, uint8_t seq_nr);
Bytes build_fir_legacy(uint32_t target_ssrc);                              // PT=192 (RFC 2032)
Bytes build_pli(uint32_t sender_ssrc, uint32_t media_ssrc);
Bytes build_nack(uint32_t sender_ssrc, uint32_t media_ssrc, const std::set<uint16_t>& lost);
Bytes build_rtcp_app_ltrp(uint32_t sender_ssrc, uint32_t ltr_id);         // PT=204 subtype 5
Bytes build_empty_sr(uint32_t sender_ssrc);

struct SsrcStat { uint16_t max_seq = 0; uint32_t roc = 0; };
struct SrArrival { uint32_t ntp_mid32 = 0; double arrival_s = 0; };
Bytes build_rr(uint32_t sender_ssrc, const std::vector<uint32_t>& sources = {},
               const std::map<uint32_t, SsrcStat>& stats = {}, const std::map<uint32_t, SrArrival>& sr = {});
Bytes compound_with_rr(uint32_t sender_ssrc, ByteView payload);
// (ssrc, ntp_mid32) for every SR in a compound buffer.
std::vector<std::pair<uint32_t, uint32_t>> parse_sr(ByteView data);

}  // namespace scshr::rtcp
