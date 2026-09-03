#pragma once
// RTP payload → NAL unit reassembly for Apple's HEVC (RFC 7798 variant with DONL everywhere) and
// H.264 (RFC 6184, DON-less) screen streams. Ports of media/nalu.py and media/avc_nalu.py.
#include "common/bytes.h"

#include <optional>
#include <vector>

namespace scshr {

// HEVC NAL types
constexpr int HEVC_NAL_VPS = 32, HEVC_NAL_SPS = 33, HEVC_NAL_PPS = 34, HEVC_NAL_AP = 48, HEVC_NAL_FU = 49;
inline bool hevc_is_irap(int nt) { return nt >= 16 && nt <= 21; }   // BLA_W_LP .. CRA_NUT
inline int hevc_nal_type(uint8_t b0) { return (b0 >> 1) & 0x3F; }
// H.264 NAL types
constexpr int AVC_NAL_SLICE = 1, AVC_NAL_IDR = 5, AVC_NAL_SPS = 7, AVC_NAL_PPS = 8, AVC_NAL_STAP_A = 24, AVC_NAL_FU_A = 28, AVC_NAL_FU_B = 29;
constexpr uint8_t APPLE_AVC_CONFIG_MARKER = 0x92;
inline int avc_nal_type(uint8_t b0) { return b0 & 0x1F; }

// A reassembled NAL is appended to `out` as [4-byte start code][nal bytes]; `ranges` records (offset,len) of each nal (excl. start code).
struct NalRange { size_t off, len; };

// Turn ordered RTP payloads of one timestamp group into NALs (Annex-B into `out`). Malformed entries dropped silently.
void reassemble_hevc(const std::vector<ByteView>& payloads, Bytes& out, std::vector<NalRange>& ranges);
void reassemble_h264(const std::vector<ByteView>& payloads, Bytes& out, std::vector<NalRange>& ranges);

// DONL of the first usable packet in a group (HEVC), for the LTRP ack.
std::optional<uint16_t> first_donl(const std::vector<ByteView>& payloads);

// Apple's 0x92 config packet: avc1 sample entry with avcC → (sps, pps) raw NALs.
struct AvcConfig { Bytes sps, pps; };
std::optional<AvcConfig> parse_avc_config(ByteView payload);

}  // namespace scshr
