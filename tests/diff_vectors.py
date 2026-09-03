"""Byte-exact differential tests: native scshr_vectors vs the Python reference implementation.

Run with the oracle venv (which has the Python package installed):
    G:/Dev/scshr/.venv-oracle/Scripts/python tests/diff_vectors.py [path/to/scshr_vectors.exe]
"""
from __future__ import annotations

import os
import struct
import subprocess
import sys
import zlib
import plistlib
import hashlib

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(REPO, "build", "Release", "scshr_vectors.exe")
os.environ.setdefault("ISS_VIDEO_CODEC", "")

from isharescreen.proxy.protocol import srtp as psrtp, rfb as prfb, rtcp as prtcp, clipboard as pclip, offers as poffers
from isharescreen.proxy.protocol import negotiation as pneg, enc1103 as penc, auth as pauth
from isharescreen.proxy.media import nalu as pnalu, avc_nalu as pavc, hevc_rps as prps, avc as pavcdec
from isharescreen.proxy import input as pinput

fails = 0
passes = 0


def run(*args) -> str:
    r = subprocess.run([EXE, *map(str, args)], capture_output=True, text=True)
    return r.stdout.strip()


def check(name, got, exp):
    global fails, passes
    if got != exp:
        fails += 1
        print(f"FAIL {name}\n  native: {got[:200]}\n  python: {exp[:200]}")
    else:
        passes += 1


def H(b: bytes) -> str:
    return b.hex()


rng = __import__("random").Random(1234)
def rb(n): return bytes(rng.getrandbits(8) for _ in range(n))

# ── SRTP ──────────────────────────────────────────────────────────────────
mk, ms = rb(32), rb(14)
for label in range(6):
    check(f"srtp_kdf label{label}", run("srtp_kdf", H(mk), H(ms), label, 32), H(psrtp._srtp_kdf(mk, ms, label, 32)))
blob = mk + ms
enc_py = psrtp.SRTPEncryptor.from_blob(blob, 0x11223344)
pkts = []
payloads = [rb(1200), rb(40), b"", rb(700)]
for p in payloads:
    pkts.append(enc_py.encrypt(p, pt=100, marker=True))
# Also a packet with CSRC + extension header
hdr = bytearray(struct.pack(">BBHII", 0x90 | 1, 100, 5, 999, 0x11223344)) + struct.pack(">I", 0xCAFEBABE) + struct.pack(">HH", 0xBEDE, 1) + b"\x00\x00\x00\x00"
dec_py = psrtp.SRTPDecryptor.from_blob(blob)
native = run("srtp_decrypt", H(blob), *[H(p) for p in pkts]).splitlines()
for i, p in enumerate(pkts):
    r = dec_py.decrypt(p)
    exp = f"ok {len(r[0])} {H(r[1])}" if r else "fail"
    check(f"srtp_decrypt {i}", native[i], exp)
# Encrypt parity (deterministic: seq/roc/ts start at 0)
native = run("srtp_encrypt", H(blob), "0x11223344", *[H(p) for p in payloads[:2]]).splitlines()
enc_py2 = psrtp.SRTPEncryptor.from_blob(blob, 0x11223344)
for i, p in enumerate(payloads[:2]):
    check(f"srtp_encrypt {i}", native[i], H(enc_py2.encrypt(p, pt=101)))
# ROC wrap: seq 65535 -> 0 sequence with per-SSRC state
enc_roc = psrtp.SRTPEncryptor.from_blob(blob, 0x55)
enc_roc._seq = 65534
roc_pkts = [enc_roc.encrypt(rb(100), pt=100) for _ in range(4)]
native = run("srtp_decrypt", H(blob), *[H(p) for p in roc_pkts]).splitlines()
dec_roc = psrtp.SRTPDecryptor.from_blob(blob)
for i, p in enumerate(roc_pkts):
    r = dec_roc.decrypt(p)
    check(f"srtp_roc_wrap {i}", native[i], f"ok {len(r[0])} {H(r[1])}" if r else "fail")
# Tampered packet must fail
bad = bytearray(pkts[0]); bad[20] ^= 1
check("srtp_tamper", run("srtp_decrypt", H(blob), H(bytes(bad))), "fail")
# SRTCP
rtcp_pkt = prtcp.build_rr(0xAABBCCDD) + prtcp.build_pli(0xAABBCCDD, 0x1000)
sen = psrtp.SRTCPEncryptor.from_blob(blob)
check("srtcp_protect", run("srtcp_protect", H(blob), H(rtcp_pkt)), H(psrtp.SRTCPEncryptor.from_blob(blob).protect(rtcp_pkt)))
prot = sen.protect(rtcp_pkt)
check("srtcp_unprotect", run("srtcp_unprotect", H(blob), H(prot)), H(psrtp.SRTCPDecryptor.from_blob(blob).unprotect(prot)))

# ── record layer (enc1103) ────────────────────────────────────────────────
wrap = rb(16)
from Crypto.Cipher import AES
inner_key, inner_iv = rb(16), rb(16)
ecb = AES.new(wrap, AES.MODE_ECB)
blob36 = b"\x00\x00\x00\x01" + ecb.encrypt(inner_key) + ecb.encrypt(inner_iv)
check("record_cbc_key", run("record_cbc_key", H(blob36), H(wrap)), H(inner_key))
msgs = [b"\x03\x00" + rb(10), rb(1), rb(300), rb(14), rb(15), rb(16)]
native = run("record_encrypt", H(blob36), H(wrap), *[H(m) for m in msgs]).splitlines()
cip = penc.StreamCipher(blob36, ecb_key=wrap)
for i, m in enumerate(msgs):
    check(f"record_encrypt {i}", native[i], H(cip.encrypt_message(m)))
# decrypt a python-encrypted stream (with a coalesced buffer + a trailing partial)
cip2 = penc.StreamCipher(blob36, ecb_key=wrap)
stream = b"".join(cip2.encrypt_message(m) for m in msgs)
partial = stream + b"\x00\x40" + b"\x11" * 10
native = run("record_decrypt", H(blob36), H(wrap), H(partial)).splitlines()
cip3 = penc.StreamCipher(blob36, ecb_key=wrap)
dm, consumed = cip3.decrypt_stream(partial)
check("record_decrypt stream", native[0], " ".join([str(consumed)] + [H(m) for m in dm]))

# ── RFB builders ──────────────────────────────────────────────────────────
check("rfb_set_encodings", run("rfb_set_encodings"), H(prfb.build_set_encodings(prfb.HP_ENCODINGS_FULL)))
from isharescreen.proxy.protocol.apple import APPLE_0X12_FOLLOWUP, APPLE_VIEWER_COMMAND_MASK, APPLE_VIEWER_OS_VER
vi = prfb.build_viewer_info(app_id=2, app_ver=(6, 1, 0), os_ver=APPLE_VIEWER_OS_VER, command_mask=APPLE_VIEWER_COMMAND_MASK, extra=b"") + APPLE_0X12_FOLLOWUP
check("rfb_viewer_info", run("rfb_viewer_info"), H(vi))
check("rfb_post_toggle", run("rfb_post_toggle"), H(prfb.build_post_encryption_toggle()))
check("rfb_key", run("rfb_key", 1, 0xff08), H(prfb.build_key_event(down=True, keysym=0xff08)))
check("rfb_pointer", run("rfb_pointer", 3, 100, 70000), H(prfb.build_pointer_event(buttons=3, x=100, y=70000)))
check("rfb_fbu", run("rfb_fbu", 0, 0, 0, 65535, 65535), H(pneg.build_fbu_request(incremental=False)))
check("rfb_fbu_1x1", run("rfb_fbu", 1, 0, 0, 1, 1), H(pneg.build_fbu_request(incremental=True, w=1, h=1)))
for w, h, sc, hdr_ in [(1920, 1080, 2.0, 0), (1366, 768, 1.0, 0), (2560, 1440, 2.5, 1), (1280, 800, 1.0, 0)]:
    check(f"rfb_vdisplay {w}x{h}@{sc}", run("rfb_vdisplay", w, h, sc, hdr_), H(prfb.build_virtual_display(width=w, height=h, hidpi_scale=sc, hdr=bool(hdr_))))
check("rfb_autofbu", run("rfb_autofbu", 3840, 2160), H(pneg.build_auto_framebuffer_update(3840, 2160)))
check("rfb_msg10", run("rfb_msg10", H(inner_key), 1, 1234, 777), H(pinput._build_msg10_pointer(inner_key, 1, 1234, 777)))
# AppleDisplayLayout parse: build a synthetic payload
payload = struct.pack(">HHHHHIIH", 5, 1920, 1080, 3840, 2160, 0xffffffff, 0, 2)
for did, (y0, x0, y1, x1) in [(1, (0, 0, 1080, 1920)), (2, (1080, 0, 2160, 3840))]:
    payload += b"\x00" * 16 + struct.pack(">I", did) + b"\x00" * 8 + struct.pack(">HHHH", y0, x0, y1, x1) + b"\x00" * 20
bw, bh, rects = prfb.parse_apple_display_layout(payload)
check("rfb_layout", run("rfb_layout", H(payload)), " ".join(["1920", "1080", str(bw), str(bh)] + [f"{r.display_id},{r.x},{r.y},{r.w},{r.h}" for r in rects]))

# ── RTCP ──────────────────────────────────────────────────────────────────
check("rtcp_fir", run("rtcp_fir", 0x1234, 0x5678, 200), H(prtcp.build_fir(0x1234, 0x5678, 200)))
check("rtcp_fir_legacy", run("rtcp_fir_legacy", 0x5678), H(prtcp.build_fir_legacy(0x5678)))
check("rtcp_pli", run("rtcp_pli", 0x1234, 0x5678), H(prtcp.build_pli(0x1234, 0x5678)))
lost = [10, 11, 12, 30, 5, 65535, 0, 1, 100]
check("rtcp_nack", run("rtcp_nack", 0x1234, 0x5678, *lost), H(prtcp.build_nack(0x1234, 0x5678, lost)))
check("rtcp_ltrp", run("rtcp_ltrp", 0x1234, 4242), H(prtcp.build_rtcp_app_ltrp(0x1234, 4242)))
check("rtcp_rr_empty", run("rtcp_rr_empty", 0x1234), H(prtcp.build_rr(0x1234)))
stats = {0x10: {"max_seq": 500, "roc": 2}, 0x11: {"max_seq": 65000, "roc": 0}}
check("rtcp_rr", run("rtcp_rr", 0x1234, 0x10, 500, 2, 0x11, 65000, 0), H(prtcp.build_rr(0x1234, source_ssrcs=[0x10, 0x11], ssrc_stats=stats)))

# ── clipboard ─────────────────────────────────────────────────────────────
text = "hello ❤ clipboard\nline2"
pm = pclip.build_clipboard_send(text)
hdrp = pclip.parse_clipboard_send_header(pm)
inner_py = pclip.decompress_clipboard_payload(pm[16:16 + hdrp[3]])
check("clip_send_inner", run("clip_send_inner", text), f"{hdrp[0]} {hdrp[2]} {H(inner_py)}")
check("clip_parse", run("clip_parse", H(pm[16:16 + hdrp[3]])), f"1 {H(text.encode())}")
check("clip_auto", run("clip_auto", 1), H(pclip.build_auto_pasteboard_msg(1)))
check("clip_req", run("clip_req", 0), H(pclip.build_clipboard_request(False)))

# ── offers / bplist / 0x1c ────────────────────────────────────────────────
for mode, codec, tiles, ltrp, audio in [(7, "both", 4, 1, 1), (7, "avc", 1, 0, 1), (7, "hevc", 4, 1, 1), (7, "hevc", 4, 0, 1), (8, "both", 4, 1, 1), (8, "both", 4, 1, 0)]:
    os.environ["ISS_VIDEO_CODEC"] = "" if codec == "both" else codec
    os.environ["ISS_TILES_PER_FRAME"] = str(tiles)
    os.environ["ISS_LTRP"] = "1" if ltrp else "0"
    exp = poffers._build_mediablob(mode, 123456789, 1700000000123456789, audio_enabled=bool(audio))
    got = run("mediablob", mode, 123456789, 1700000000123456789, codec, tiles, ltrp, audio)
    # The reference embeds the Python package version string + host info; mask both UA (field 6) and endpoint (not in blob).
    check(f"mediablob mode{mode} {codec} t{tiles} l{ltrp} a{audio}", got, H(exp))
for k in ("ISS_VIDEO_CODEC", "ISS_TILES_PER_FRAME", "ISS_LTRP"):
    os.environ.pop(k, None)
# bplist writer parity with plistlib
d = {"avcMediaStreamOptionRemoteEndpointInfo": rb(40), "avcMediaStreamNegotiatorMode": 7, "avcMediaStreamNegotiatorMediaBlob": rb(700), "avcMediaStreamOptionCallID": "0A1B2C3D-0000-4000-8000-ABCDEF012345"}
args = [f"{k}={'b:' + v.hex() if isinstance(v, bytes) else 'i:' + str(v) if isinstance(v, int) else 's:' + v}" for k, v in d.items()]
check("bplist_dump", run("bplist_dump", *args), H(plistlib.dumps(d, fmt=plistlib.FMT_BINARY)))
got = run("bplist_load", H(plistlib.dumps(d, fmt=plistlib.FMT_BINARY))).splitlines()
exp = [f"{k}={'b:' + v.hex() if isinstance(v, bytes) else 'i:' + str(v) if isinstance(v, int) else 's:' + v}" for k, v in sorted(d.items())]
check("bplist_load", got, exp)
# SSRC extraction from a python-built offer
vo, ao = poffers.create_offers()
check("offer_ssrc video", run("offer_ssrc", H(vo), "video"), str(poffers.extract_offer_ssrc(vo, is_video=True)))
check("offer_ssrc audio", run("offer_ssrc", H(ao), "audio"), str(poffers.extract_offer_ssrc(ao, is_video=False)))
# Synthetic 0x1c answer: FBU with an embedded bplist carrying canvas dims in F5
def varint(v):
    out = b""
    while v > 0x7F:
        out += bytes([(v & 0x7F) | 0x80]); v >>= 7
    return out + bytes([v])
sub = varint(4 << 3) + varint(1920) + varint(5 << 3) + varint(1088) + varint(6 << 3) + varint(4) + varint(7 << 3) + varint(1)
ans_blob = varint(1 << 3) + varint(1) + varint((5 << 3) | 2) + varint(len(sub)) + sub
ans_plist = plistlib.dumps({"avcMediaStreamNegotiatorMediaBlob": zlib.compress(ans_blob), "x": 1}, fmt=plistlib.FMT_BINARY)
ans_msg = b"\x00\x00\x00\x01" + b"\x00" * 12 + b"\x00\x10" + ans_plist + b"\xaa\xbb"
check("canvas_dims", run("canvas_dims", H(ans_msg)), " ".join(map(str, poffers.extract_canvas_dims(ans_msg))))
# 0x1c (uuid masked to zero on both sides)
keys = pneg.NegotiationKeys(rb(46), rb(46), rb(46), rb(46))
for alt, legacy in [(0, 0), (1, 0), (0, 1)]:
    if legacy: os.environ["ISS_LEGACY_CURSOR"] = "1"
    else: os.environ.pop("ISS_LEGACY_CURSOR", None)
    m = bytearray(pneg.build_0x1c(ao, vo, keys, alt_session=bool(alt))); m[0x14:0x24] = b"\x00" * 16
    check(f"msg1c alt{alt} legacy{legacy}", run("msg1c", H(ao), H(vo), H(keys.audio_key_v), H(keys.audio_key_s), H(keys.video_key_v), H(keys.video_key_s), alt, legacy), H(bytes(m)))
os.environ.pop("ISS_LEGACY_CURSOR", None)

# ── SRP (fixed ephemeral a) ───────────────────────────────────────────────
# Any odd 4096-bit modulus exercises the same bignum/hash math byte-for-byte (no real prime needed for parity).
N_rfc = (1 << 4096) - 12345
Nb = N_rfc.to_bytes(512, "big")
salt = rb(32)
B = pow(5, 12345678901234567890, N_rfc).to_bytes(512, "big")
cap = b"mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305,kdf=SALTED-SHA512-PBKDF2"
s2c1 = b"\x00" * 12 + b"\x00" + Nb + struct.pack(">H", 1) + b"\x05" + bytes([32]) + salt + struct.pack(">H", 512) + B + struct.pack(">Q", 1000) + struct.pack(">H", len(cap)) + cap
ch = pauth._parse_apple_srp_challenge(s2c1)
# Reproduce _solve_srp with a fixed `a` (copy of the reference math with a injected)
a_fixed = rb(64)
def solve_fixed(challenge, password, a_bytes):
    KL = 512
    g_padded = challenge.g.to_bytes(KL, "big")
    k = int.from_bytes(hashlib.sha512(challenge.Nb + g_padded).digest(), "big")
    a = int.from_bytes(a_bytes, "big")
    A = pow(challenge.g, a, challenge.N); Ab = A.to_bytes(KL, "big")
    u = int.from_bytes(hashlib.sha512(Ab + challenge.Bb).digest(), "big")
    x = pauth._derive_x(challenge.salt, challenge.iterations, password) % challenge.N
    S = pow((challenge.B - k * pow(challenge.g, x, challenge.N)) % challenge.N, a + u * x, challenge.N)
    K = hashlib.sha512(S.to_bytes(KL, "big")).digest()
    h_n = hashlib.sha512(challenge.Nb).digest(); h_g = hashlib.sha512(g_padded).digest()
    M1 = hashlib.sha512(bytes(p ^ q for p, q in zip(h_n, h_g)) + hashlib.sha512(b"").digest() + challenge.salt + Ab + challenge.Bb + K).digest()
    return Ab, M1, K
Ab, M1, K = solve_fixed(ch, "s3cret-pässword", a_fixed)
check("srp", run("srp", H(s2c1), "s3cret-pässword", H(a_fixed)), f"{H(Ab)} {H(M1)} {H(K)} {H(hashlib.sha256(K).digest()[:16])}")
check("srp_x", run("srp_x", H(salt), 1000, "s3cret-pässword"), H(pauth._derive_x(salt, 1000, "s3cret-pässword").to_bytes(64, "big")))

# ── AVC helpers ───────────────────────────────────────────────────────────
# A real-ish SPS: profile 100, level 4.0, chroma 1, poc type 0 ... (from libx264 defaults) + level/DPB patch
sps_x264 = bytes.fromhex("6764001facd94050045b016a02020280000003008000001e478c18cb")
check("avc_sps_patch", run("avc_sps_patch", H(sps_x264)), H(pavcdec._patch_avc_sps_dpb(sps_x264)))
for nal in [bytes.fromhex("65888040"), bytes.fromhex("419a"), bytes.fromhex("41e2"), bytes.fromhex("4188"), bytes.fromhex("01")]:
    check(f"avc_keyframe {nal.hex()}", run("avc_keyframe", H(nal)), "1" if pavcdec._nal_is_keyframe(nal) else "0")
avcc = b"\x92" + b"junk" + b"avc1" + b"\x00" * 10 + b"avcC" + bytes([1, 100, 0, 31, 0xff, 0xe1]) + struct.pack(">H", len(sps_x264)) + sps_x264 + b"\x01" + struct.pack(">H", 4) + bytes.fromhex("68ebe3cb")
sp = pavc.parse_avc_config(avcc)
check("avc_config", run("avc_config", H(avcc)), f"{H(sp[0])} {H(sp[1])}")

# ── NAL reassembly (Apple quirks) ─────────────────────────────────────────
# HEVC: AP with 2 sub-NALs, FU start/mid/end with DONL, single NAL with DONL, a malformed short packet
ap = bytes([0x60, 0x01]) + b"\x00\x07" + struct.pack(">H", 3) + b"\x40\x01\xaa" + struct.pack(">H", 4) + b"\x42\x01\xbb\xcc"
fu_s = bytes([0x62, 0x01, 0x80 | 19]) + b"\x00\x08" + b"\x11\x22"
fu_m = bytes([0x62, 0x01, 19]) + b"\x00\x08" + b"\x33"
fu_e = bytes([0x62, 0x01, 0x40 | 19]) + b"\x00\x08" + b"\x44"
single = bytes([0x02, 0x01]) + b"\x00\x09" + b"\x55\x66\x77"
pays = [ap, fu_s, fu_m, fu_e, single, b"\x62", b"\x01"]
exp = [H(n) for n in pnalu.reassemble_group(pays)] + [f"donl {pnalu.first_donl(pays)}"]
check("reassemble_hevc", run("reassemble_hevc", *[H(p) for p in pays]).splitlines(), exp)
# orphan FU (no end) must not emit anything
pays2 = [fu_s, fu_m]
check("reassemble_hevc_orphan", run("reassemble_hevc", *[H(p) for p in pays2]).splitlines(), [H(n) for n in pnalu.reassemble_group(pays2)] + [f"donl {pnalu.first_donl(pays2)}"])
# H.264: FU-A start/end, single NAL, STAP-A, FU-B, config marker skipped
fua_s = bytes([0x7c, 0x85]) + b"\xaa\xbb"
fua_e = bytes([0x7c, 0x45]) + b"\xcc"
sing = bytes([0x41, 0x9a, 0x11])
stap = bytes([0x78]) + b"\x00\x01" + struct.pack(">H", 2) + b"\x67\x01" + struct.pack(">H", 3) + b"\x68\x02\x03"
fub_s = bytes([0x7d, 0x85]) + b"\x00\x05" + b"\xde"
fub_e = bytes([0x7d, 0x45]) + b"\x00\x06" + b"\xad"
pays3 = [b"\x92abc", fua_s, fua_e, sing, stap, fub_s, fub_e, b"\x41"]
exp = [H(n) for n in pavc.reassemble_h264(pays3)] + [f"donl {pnalu.first_donl(pays3)}"]
check("reassemble_h264", run("reassemble_h264", *[H(p) for p in pays3]).splitlines(), exp)

# ── HEVC SPS / RPS parse ──────────────────────────────────────────────────
_SAMPLE = bytes.fromhex("0000000140010c01ffff0408000003009e280000030000baba0240000000014201010408000003009e280000030000ba90041020b2dd25261734040000030004003d090020000000014401c070306011200000012801ade0d117ffd39173238b80")
_nals = [n for n in _SAMPLE.split(bytes([0,0,0,1])) if n]
hevc_sps = _nals[1]
st = prps.parse_sps(prps.remove_emulation_prevention(hevc_sps[2:]))
exp = f"{st.log2_max_pic_order_cnt_lsb} {st.pic_width_in_luma_samples} {st.pic_height_in_luma_samples} {st.num_short_term_ref_pic_sets} {int(st.long_term_ref_pics_present_flag)} {st.num_long_term_ref_pics_sps} {st.log2_min_luma_coding_block_size_minus3} {st.log2_diff_max_min_luma_coding_block_size}"
exp += "".join(" [" + "".join(f"{d}{'u' if u else 'n'}," for d, u in s.deltas) + "]" for s in st.short_term_rps_sets)
check("hevc_sps", run("hevc_sps", H(hevc_sps[2:])), exp)

print(f"vectors: {passes} passed, {fails} failed")
sys.exit(1 if fails else 0)
