#!/usr/bin/env bash
# Regenerates the synthetic .scshr recordings in testdata/ from the Annex-B streams (deterministic seeds).
set -e; cd "$(dirname "$0")/.."
S=./build/Release/scshr_synth.exe
$S --in testdata/avc_1080p60_6s.h264 --codec avc --out testdata/avc_clean.scshr
$S --in testdata/avc_1080p60_6s.h264 --codec avc --out testdata/avc_loss.scshr --loss 1.0 --seed 3
$S --in testdata/avc_1080p60_6s.h264 --codec avc --out testdata/avc_reorder.scshr --reorder 5 --dup 2 --seed 5
$S --in testdata/avc_1080p60_6s.h264 --codec avc --out testdata/avc_wrap.scshr --seq-start 65400
$S --in testdata/avc_1080p60_6s.h264 --codec avc --out testdata/avc_ssrcswitch.scshr --ssrc-switch-at 200
$S --in testdata/avc_1080p60_6s.h264 --codec avc --out testdata/avc_restart.scshr --restart-at 180
$S --in testdata/avc_1080p60_6s.h264 --codec avc --out testdata/avc_corrupt.scshr --corrupt 0.5 --seed 9
$S --in testdata/avc_1080p60_30s.h264 --codec avc --out testdata/avc_30s.scshr
$S --in testdata/hevc444_1080p60_10s.h265 --codec hevc --out testdata/hevc_clean.scshr
$S --in testdata/hevc444_1080p60_10s.h265 --codec hevc --out testdata/hevc_loss.scshr --loss 0.5 --reorder 3 --seed 4
