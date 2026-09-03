#!/usr/bin/env bash
# End-to-end run: native viewer in replay mode + real-time sender on loopback (optionally with emulated WAN impairment).
#   tools/e2e.sh <recording.scshr> <seconds> <log-name> [viewer args...] -- [sender args...]
set -u
cd "$(dirname "$0")/.."
REC=$1; SECS=$2; NAME=$3; shift 3
VARGS=(); SARGS=()
while [ $# -gt 0 ]; do if [ "$1" = "--" ]; then shift; SARGS=("$@"); break; fi; VARGS+=("$1"); shift; done
KEY=$(python -c "d=open('$REC','rb').read(106);print(d[14:60].hex())")
CODEC=$(python -c "d=open('$REC','rb').read(106);print('hevc' if d[12]==1 else 'avc')")
TILES=$(python -c "d=open('$REC','rb').read(106);print(d[13])")
taskkill //F //IM scshr_sender.exe > /dev/null 2>&1; taskkill //F //IM scshr.exe > /dev/null 2>&1
sleep 0.5
LOG=build/e2e_$NAME.log; rm -f "$LOG"
./build/Release/scshr.exe --replay-key "$KEY" --codec "$CODEC" --tiles "$TILES" --auto-quit-secs "$SECS" --log-file "$LOG" --no-grab "${VARGS[@]}" > /dev/null 2>&1 &
VPID=$!
sleep 1.5
./build/Release/scshr_sender.exe --in "$REC" --to 127.0.0.1 --video-port 5901 --loop 100 "${SARGS[@]}" > build/e2e_${NAME}_sender.log 2>&1 &
SPID=$!
wait $VPID
kill $SPID > /dev/null 2>&1; taskkill //F //IM scshr_sender.exe > /dev/null 2>&1
echo "== $NAME (${VARGS[*]} | ${SARGS[*]})"
rg "D3D11VA bound|hardware decode NOT|did not bind|software" "$LOG" | head -2 | cut -c1-200
rg "present:" "$LOG" | tail -1 | cut -c1-400
rg "stats    \| video" "$LOG" | tail -1 | cut -c1-600
rg -c "WARN|ERROR" "$LOG" | sed 's/^/warn+error lines: /'
