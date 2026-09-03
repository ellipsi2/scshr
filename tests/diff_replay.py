"""Differential replay: native scshr_replay vs Python reference over every testdata/*.scshr recording.

Compares, event by event: burst harvest (SSRC→tile map, parameter sets, per-tile NAL counts, leftover groups),
sequence decisions (loss / late / duplicate), every flushed group (SSRC, timestamp, ordered seqs + marker,
incomplete flag, reassembled NAL types/lengths/CRCs, DONL), every dropped group (reason, marker state),
and the final counters.

    G:/Dev/scshr/.venv-oracle/Scripts/python tests/diff_replay.py [testdata/*.scshr ...]
"""
from __future__ import annotations

import glob
import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.path.join(REPO, "build", "Release", "scshr_replay.exe")
ORACLE = os.path.join(REPO, "tests", "replay_oracle.py")
TMP = os.path.join(REPO, "build", "replay_tmp")
os.makedirs(TMP, exist_ok=True)

files = sys.argv[1:] or sorted(glob.glob(os.path.join(REPO, "testdata", "*.scshr")))
total_fail = 0
for f in files:
    name = os.path.basename(f)
    nat = os.path.join(TMP, name + ".native.jsonl")
    pyo = os.path.join(TMP, name + ".python.jsonl")
    r1 = subprocess.run([EXE, "--in", f, "--jsonl", nat], capture_output=True, text=True)
    r2 = subprocess.run([sys.executable, ORACLE, f, pyo], capture_output=True, text=True)
    if r1.returncode not in (0, 3) or r2.returncode not in (0, 3):
        print(f"{name}: RUN ERROR native rc={r1.returncode} python rc={r2.returncode}\n{r1.stderr[-500:]}\n{r2.stderr[-800:]}")
        total_fail += 1
        continue
    a = [json.loads(l) for l in open(nat, encoding="utf-8") if l.strip()]
    b = [json.loads(l) for l in open(pyo, encoding="utf-8") if l.strip()]
    # Sequence-event lines and flush/drop lines must match in order; compare the interleaved stream directly.
    def norm(ev):
        if ev.get("ev") == "summary":
            return {k: ev[k] for k in ("ev", "packets", "auth_fail", "received", "lost")}
        if ev.get("ev") == "burst":
            ev = dict(ev); ev.pop("codec", None)   # diagnostic label only (both sides compute it identically anyway)
        return ev
    an = [norm(e) for e in a]
    bn = [norm(e) for e in b]
    mism = 0
    first = None
    for i, (x, y) in enumerate(zip(an, bn)):
        if x != y:
            mism += 1
            if first is None:
                first = (i, x, y)
    if len(an) != len(bn):
        mism += abs(len(an) - len(bn))
    counts = {}
    for e in an:
        counts[e["ev"]] = counts.get(e["ev"], 0) + 1
    status = "OK " if mism == 0 else "FAIL"
    print(f"{status} {name}: {len(an)} events (native) vs {len(bn)} (python) — {counts}")
    if first:
        print(f"   first mismatch at event {first[0]}:\n     native: {json.dumps(first[1])[:300]}\n     python: {json.dumps(first[2])[:300]}")
    total_fail += 1 if mism else 0
print("replay differential:", "ALL MATCH" if total_fail == 0 else f"{total_fail} file(s) differ")
sys.exit(1 if total_fail else 0)
