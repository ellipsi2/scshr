"""Python-reference replay of a .scshr recording → JSONL of packet-path decisions (same schema as scshr_replay).

Drives the REAL reference code (SRTPDecryptor, gather_initial_burst, Session._track_seq /
_queue_video_group_packet / _evict_stale_groups / _flush_group / _drop_incomplete_group) with the recorded
packet timestamps as the monotonic clock, so decisions are deterministic and comparable byte-for-byte.
"""
from __future__ import annotations

import json
import os
import struct
import sys
import types
import zlib

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read_scshr(path):
    with open(path, "rb") as f:
        hdr = f.read(106)
        assert hdr[:8] == b"SCSHRPKT"
        codec = "hevc" if hdr[12] == 1 else "avc"
        tiles = hdr[13]
        vkey = hdr[14:60]
        recs = []
        while True:
            rh = f.read(12)
            if len(rh) < 12:
                break
            t_ns, kind, n = struct.unpack(">QHH", rh)
            recs.append((t_ns, kind, f.read(n)))
    return codec, tiles, vkey, recs


def main():
    path = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) > 2 else None
    codec, tiles, vkey, recs = read_scshr(path)
    os.environ["ISS_VIDEO_CODEC"] = codec
    os.environ["ISS_TILES_PER_FRAME"] = str(tiles)
    os.environ["ISS_LTRP"] = "1" if codec == "hevc" else "0"

    from isharescreen.proxy import session as S
    from isharescreen.proxy.protocol import burst as B
    from isharescreen.proxy.protocol.srtp import SRTPDecryptor
    from isharescreen.proxy.media.nalu import reassemble_group, first_donl
    from isharescreen.proxy.media.avc_nalu import reassemble_h264
    from isharescreen.proxy.media.quality_gate import FrameQualityGate

    clock = {"t": 0.0}
    S.time.monotonic = lambda: clock["t"]          # session.py uses `time.monotonic()` via its imported module
    B.time.sleep = lambda s: None
    B.time.time = lambda: clock["t"]

    lines = []
    J = lambda d: lines.append(json.dumps(d, separators=(",", ":")))

    dec = SRTPDecryptor.from_blob(vkey)
    video = [(t, d) for t, k, d in recs if k == 0]
    min_packets = 400 if codec == "avc" else 100
    # Burst window = same rule as scshr_replay: first min_packets, then everything within 300 ms.
    burst_pkts = video[:min_packets]
    settle_end = burst_pkts[-1][0] + 300_000_000 if burst_pkts else 0
    i = len(burst_pkts)
    while i < len(video) and video[i][0] <= settle_end:
        burst_pkts.append(video[i]); i += 1
    try:
        burst = B.gather_initial_burst([d for _, d in burst_pkts], dec, codec=codec, min_packets=min_packets, deadline_seconds=0.0, settle_seconds=0.0)
    except B.BurstStarved as e:
        J({"ev": "burst_starved", "reason": str(e)})
        print("\n".join(lines))
        return 3
    J({"ev": "burst", "packets": len(burst_pkts), "ssrc_to_tile": {str(k): v for k, v in burst.ssrc_to_tile.items()}, "vps": len(burst.vps), "sps": len(burst.sps),
       "pps": len(burst.all_pps), "idr_tiles": len(burst.last_idr), "tile_nalus": {str(k): len(v) for k, v in burst.tile_nalus.items()}, "pending": sum(len(g) for g in burst.burst_pending.values()),
       "codec": "H.264/AVC" if codec == "avc" else "HEVC"})

    # Bare session wired with the fields the packet path touches.
    s = S.Session.__new__(S.Session)
    s._video_codec = codec
    s._pending_groups = {}
    s._group_arrival = {}
    s._recently_flushed = {}
    s._group_repair_deadline = {}
    s._last_group_marker_seq = {}
    s._last_group_evict_t = 0.0
    s._max_seq = {}
    s._roc = {}
    s._nack_pending = __import__("collections").defaultdict(set)
    s._received_pkts = 0
    s._lost_pkts = 0
    s._lost_pkts_per_tile = [0] * max(1, len(burst.ssrc_to_tile))
    s._last_video_pkt_t = 0.0
    s._tx_wakeup = __import__("threading").Event()
    s._ssrc_to_tile = dict(burst.ssrc_to_tile)
    s._tile_bytes = {}
    s._ltr_enabled = codec == "hevc"
    s._avc_needs_reconfig = False
    s._needs_param_harvest = False
    s._video_au_callback = None

    class _Dec:
        def __init__(self):
            self._gate = FrameQualityGate(max(1, len(burst.ssrc_to_tile)))
            self.fed = []
        def feed_nalu(self, nalu, ti, donl=None):
            self.fed.append((ti, bytes(nalu)))
        def mark_reference_chain_broken(self, trigger=""):
            pass
    s._decoder = _Dec()

    orig_flush = S.Session._flush_group
    orig_drop = S.Session._drop_incomplete_group
    reasm = reassemble_h264 if codec == "avc" else reassemble_group

    def flush_wrapper(self, key):
        grp = self._pending_groups.get(key)
        if grp is not None:
            packets = S.Session._sorted_group_packets(grp)
            oseq = [p[0] for p in packets]
            incomplete = any(((oseq[i + 1] - oseq[i]) & 0xFFFF) > 1 for i in range(len(oseq) - 1))
            ordered = [p for _, _, p in packets]
            nals = [[(n[0] & 0x1F) if codec == "avc" else ((n[0] >> 1) & 0x3F), len(n), zlib.crc32(n) & 0xFFFFFFFF] for n in reasm(ordered)]
            d = first_donl(ordered)
            J({"ev": "flush", "ssrc": key[0], "ts": key[1], "seqs": [f"{q}m" if m else f"{q}" for q, m, _ in packets], "incomplete": incomplete, "nals": nals, "donl": -1 if d is None else d})
        return orig_flush(self, key)

    def drop_wrapper(self, key, *, reason, now):
        grp = self._pending_groups.get(key)
        if grp is not None:
            packets = S.Session._sorted_group_packets(grp)
            J({"ev": "drop", "ssrc": key[0], "ts": key[1], "had_marker": any(m for _, m, _ in packets), "reason": reason, "packets": len(grp)})
        return orig_drop(self, key, reason=reason, now=now)

    S.Session._flush_group = flush_wrapper
    S.Session._drop_incomplete_group = drop_wrapper

    # Seed the leftover burst groups exactly like Session.connect (arrival = "now" at connect).
    clock["t"] = burst_pkts[-1][0] / 1e9 if burst_pkts else 0.0
    s._pending_groups = burst.burst_pending
    s._group_arrival = {key: clock["t"] for key in burst.burst_pending}

    last_evict = 0
    n = auth_fail = 0
    for t_ns, d in video[i:]:
        clock["t"] = t_ns / 1e9
        n += 1
        res = dec.decrypt(d)
        if res is None:
            auth_fail += 1
            J({"ev": "auth_fail", "i": n})
            continue
        hdr, payload = res
        ssrc = struct.unpack(">I", hdr[8:12])[0]
        seq = struct.unpack(">H", hdr[2:4])[0]
        ts = struct.unpack(">I", hdr[4:8])[0]
        marker = bool(hdr[1] & 0x80)
        prev = s._max_seq.get(ssrc)
        lost_before = s._lost_pkts
        s._track_seq(ssrc, seq)
        if prev is not None:
            diff = (seq - prev) & 0xFFFF
            lost = s._lost_pkts - lost_before
            if diff == 0 or diff > 0x8000 or lost:
                J({"ev": "seq", "ssrc": ssrc, "seq": seq, "lost": lost, "late": diff > 0x8000, "dup": diff == 0})
        s._queue_video_group_packet(ssrc, ts, seq, marker, payload)
        if t_ns - last_evict >= 20_000_000:   # integer ns like the native loop (avoids float boundary skew)
            last_evict = t_ns
            s._evict_stale_groups()
    clock["t"] = (video[-1][0] if video else 0) / 1e9 + 5.0
    s._evict_stale_groups()
    J({"ev": "summary", "packets": n, "auth_fail": auth_fail, "received": s._received_pkts, "lost": s._lost_pkts})
    text = "\n".join(lines) + "\n"
    if out:
        open(out, "w", encoding="utf-8").write(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
