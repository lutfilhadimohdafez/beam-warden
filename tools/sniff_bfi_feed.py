#!/usr/bin/env python3
"""Continuous RX-only BFI sniffer that feeds the dashboard's live detector.

NO injection — the Alfa only LISTENS, so this is NOT the crash window (the wedge
comes from injection TX load, not monitor RX). Reloads the Alfa firmware (so VHT
capture works), brings up mon0 at 20MHz, and streams each victim VHT compressed-BF
frame (epoch + RETRY bit) line-buffered to the feed file the dashboard tails
(`--bfi-feed`). With no attack the detector sits at NORMAL; during an attack the
BFI rate spikes and it flips to ATTACK. Ctrl-C to stop (restores the Alfa).

Run: pkexec /home/lutfil/fyp/.venv/bin/python /home/lutfil/fyp/tools/sniff_bfi_feed.py [feed_path]
"""
import os
os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin:" + os.environ.get("PATH", "")
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aba_mt76 import monitor_up, teardown, sh, say

MON, CH, VICTIM = "mon0", "36", "16:0f:02:1d:91:42"
feed = sys.argv[1] if len(sys.argv) > 1 else "/tmp/bfi_feed.tsv"

if os.geteuid() != 0:
    sys.exit("run under pkexec (monitor needs root).")

phy = monitor_up(MON, CH)          # FW reload + mon0 @ 20MHz (reliable VHT capture)
say(f"feeding {feed}  (RX-only, NO injection — safe; Ctrl-C to stop)")
try:
    # line-buffered tshark -> feed file; the dashboard --bfi-feed tails it live
    subprocess.run(
        f"stdbuf -oL tshark -l -i {MON} "
        f"-Y 'wlan.fixed.category_code==21 && wlan.sa=={VICTIM}' "
        f"-T fields -e frame.time_epoch -e wlan.fc.retry > {feed}",
        shell=True)
except KeyboardInterrupt:
    pass
finally:
    teardown(phy, None, "true")
    say("sniffer stopped, Alfa restored")
