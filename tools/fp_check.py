#!/usr/bin/env python3
"""False-positive check: run the BFI-storm detector over the WHOLE real-normal
capture (no attack) and report how many 2s windows would trip the thresholds.
This answers 'does it work on normal conditions' with a real number."""
import sys, statistics as st
from pathlib import Path
sys.path.insert(0, "/home/lutfil/fyp/tools")
from rig import RIG  # rig.conf creds, not hardcoded
from bfi_features import extract

PCAP = sys.argv[1] if len(sys.argv) > 1 else "/home/lutfil/fyp/data/realuse_20261031_071927.pcap"
VICTIM = RIG["VICTIM_MAC"]
WIN = 2.0
# thresholds distilled from the attack capture (normal max ~20 / ratio ~0; attack ~34 / ~0.5)
TH_RATE = 24     # bfi_count per 2s window
TH_RATIO = 0.25  # retry1_ratio

bfi = extract(PCAP, VICTIM)
if not bfi:
    print("NO victim BFI frames in capture — wrong MAC or empty."); sys.exit(1)
t0 = min(t for t, _ in bfi); t1 = max(t for t, _ in bfi)
counts, ratios, trips = [], [], 0
t = t0
while t < t1:
    w = [(bt, r) for bt, r in bfi if t <= bt < t + WIN]
    c = len(w); ret = sum(r for _, r in w)
    ratio = ret / c if c else 0.0
    counts.append(c); ratios.append(ratio)
    if c > TH_RATE or ratio > TH_RATIO:
        trips += 1
    t += WIN
n = len(counts)
print(f"capture span: {t1-t0:.0f}s   victim BFI frames: {len(bfi)}   windows: {n}")
print(f"bfi_count/window : min {min(counts)}  mean {st.mean(counts):.1f}  max {max(counts)}  (attack band >=28)")
print(f"retry1_ratio     : max {max(ratios):.3f}  (attack ~0.5)")
print(f"windows tripping detector (count>{TH_RATE} OR ratio>{TH_RATIO}): {trips}/{n} = {100*trips/n:.2f}%")
print(f"==> normal-conditions false-positive rate: {100*trips/n:.2f}%")
