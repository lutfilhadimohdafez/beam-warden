#!/usr/bin/env python3
"""OBJ3 false-positive validation: does the NORMAL (no-attack) on-air BFI rate
stay below the attack band under HEAVY and BURSTY traffic?

The attack is detected by a BFI-rate spike (normal ~16/2s-window, attack ~35,
threshold 24). But the normal rate rises with downlink volume (more traffic ->
AP sounds more -> more BFI). If heavy real usage pushes normal into the attack
band, we'd get false positives. This measures exactly that.

Rather than fight app UIs over ADB, it reproduces the PHY driver of the BFI rate
directly over the REAL link: a HEAVY sustained downlink (big-download proxy) then
a BURSTY downlink (stream/browse proxy) to the phone, capturing the victim's BFI
the whole time. NO attack, NO injection — Alfa only listens.

Run: pkexec /home/lutfil/fyp/.venv/bin/python /home/lutfil/fyp/tools/real_usage_probe.py
(phone iperf3 server must be up on :5201)
"""
import os
os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin:" + os.environ.get("PATH", "")
import collections
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rig import RIG  # rig.conf creds, not hardcoded
from aba_mt76 import monitor_up, teardown, sh, say

FYP = Path(__file__).resolve().parent.parent
MON, CH, VICTIM, VIP = "mon0", "36", RIG["VICTIM_MAC"], RIG["VICTIM_IP"]
WIN, ATTACK_THRESH = 2.0, 24     # from bfi_features: attack band ~16-35/window, split at 24

if os.geteuid() != 0:
    sys.exit("run under pkexec (monitor needs root).")

ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
pcap = FYP / "data" / f"realuse_{ts}.pcap"
pcap.parent.mkdir(parents=True, exist_ok=True)

stop = threading.Event()
phases = []   # (label, t0, t1)


def heavy(dur):
    """Sustained max downlink to the phone (big-download proxy)."""
    end = time.time() + dur
    while time.time() < end and not stop.is_set():
        subprocess.run(f"iperf3 -c {VIP} -p 5201 -t 5 >/dev/null 2>&1", shell=True)


def bursty(dur):
    """Short bursts + idle gaps (stream/browse proxy)."""
    end = time.time() + dur
    while time.time() < end and not stop.is_set():
        subprocess.run(f"iperf3 -c {VIP} -p 5201 -t 2 >/dev/null 2>&1", shell=True)
        stop.wait(1.5)


phy = monitor_up(MON, CH)
try:
    sniff = subprocess.Popen(f"tcpdump -i {MON} -w {pcap} 2>/dev/null", shell=True)
    time.sleep(1)
    for label, fn, dur in [("heavy", heavy, 30), ("bursty", bursty, 30)]:
        say(f"generating {label} downlink for {dur}s (NO attack)…")
        t0 = time.time()
        th = threading.Thread(target=fn, args=(dur,), daemon=True)
        th.start()
        th.join()
        phases.append((label, t0, time.time()))
    stop.set()
    try:
        sniff.terminate()
    except Exception:
        pass
    time.sleep(1)
finally:
    teardown(phy, None, "true")

# per-window victim BFI counts, split by traffic phase
raw = subprocess.run(
    f"tshark -r {pcap} -Y 'wlan.fixed.category_code==21 && wlan.sa=={VICTIM}' "
    f"-T fields -e frame.time_epoch 2>/dev/null", shell=True, text=True,
    capture_output=True).stdout
times = [float(x) for x in raw.split() if x.strip()]
print("\n" + "=" * 64)
print(f"pcap: {pcap}   victim BFI frames: {len(times)}")
worst = 0
for label, t0, t1 in phases:
    ph = [t for t in times if t0 <= t < t1]
    nwin = max(1, int((t1 - t0) // WIN))
    buckets = collections.Counter(int((t - t0) // WIN) for t in ph)
    counts = [buckets.get(i, 0) for i in range(nwin)]
    peak = max(counts) if counts else 0
    med = sorted(counts)[len(counts) // 2] if counts else 0
    over = sum(1 for c in counts if c >= ATTACK_THRESH)
    worst = max(worst, peak)
    print(f"  {label:7} traffic: BFI/window median={med:2d} peak={peak:2d}  "
          f"windows>=attack-band({ATTACK_THRESH}): {over}/{len(counts)}")
print("-" * 64)
if worst < ATTACK_THRESH:
    print(f"VERDICT: normal peak {worst} < attack band {ATTACK_THRESH} -> real heavy/bursty")
    print("usage does NOT reach the attack band -> detector is robust (no false positive).")
else:
    print(f"VERDICT: normal peak {worst} >= {ATTACK_THRESH} -> heavy traffic can look like")
    print("attack -> use per-environment calibration (learn THIS link's normal rate first).")
print("=" * 64)
