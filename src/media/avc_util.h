#pragma once
// H.264 helpers: intra-slice keyframe detection (Apple sends no type-5 IDR; keyframes are I slices in
// type-1 NALs) and the SPS DPB patch (max_num_ref_frames→16, level→6.0) from media/avc.py.
#include "common/bytes.h"

namespace scshr {

bool avc_nal_is_keyframe(ByteView nal);          // raw NAL (no start code)
Bytes avc_patch_sps_dpb(ByteView sps);           // returns input unchanged on any parse surprise

}  // namespace scshr
