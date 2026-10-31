#!/usr/bin/env python3
"""Continuous RX-only BFI sniffer feeding the dashboard live detector — WITH a
USB-wedge watchdog.

HONEST SAFETY NOTE: the DOCUMENTED Alfa crash is injection TX load (the mt7921u
`-110` vendor-request storm that resets/stalls the shared xHCI USB controller and
can take the whole laptop down). This tool is RX-ONLY (no main_su, no injection),
so it avoids that specific failure mode. BUT a *continuous* monitor capture on
this USB2 card is NOT something we've run for long, so we do NOT assume it is
wedge-proof. Mitigations:
  * WATCHDOG: every few seconds it checks the kernel log for the mt7921u / -110 /
    xHCI-reset signature AND that mon0 is still a live monitor interface. The
    instant a wedge starts it kills the capture and tears the Alfa down, so it
    never gets to stall the whole USB bus.
  * BOUNDED: stops after --max-seconds (default 900s). Re-run to keep going.
  * If it ever aborts with a WEDGE reason, reseat/recover the Alfa before re-running,
    and make sure the laptop uplink is on the onboard RJ45 (PCIe), not a USB NIC on
    the Alfa's controller (see the crash failsafe memory).

Run: pkexec /home/lutfil/fyp/.venv/bin/python /home/lutfil/fyp/tools/sniff_bfi_feed.py [feed] [--max-seconds N]
"""
import argparse
import os
os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin:" + os.environ.get("PATH", "")
import re
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rig import RIG  # rig.conf creds, not hardcoded
from aba_mt76 import monitor_up, teardown, sh, say
from aba_measure import check_mon_hearing

MON, CH, VICTIM = "mon0", "36", RIG["VICTIM_MAC"]
WEDGE_RE = re.compile(r"mt7921|xhci_hcd.*(?i:reset)|-110|vendor request", re.I)


def wedge_count():
    """How many wedge-signature lines are in the recent kernel log."""
    return sum(1 for l in sh("dmesg | tail -n 50").stdout.splitlines()
               if WEDGE_RE.search(l))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("feed", nargs="?", default="/tmp/bfi_feed.tsv")
    ap.add_argument("--max-seconds", type=int, default=900)
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("run under pkexec (monitor needs root).")

    phy = monitor_up(MON, CH)                 # FW reload + mon0 @ 20MHz
    hearing = check_mon_hearing(MON)
    if hearing == 0:
        teardown(phy, None, "true")
        sys.exit("mon0 RX-deaf after setup — reseat/recover the Alfa and re-run.")
    base = wedge_count()
    say(f"{MON} hearing OK ({hearing} rx/2s). Feeding {a.feed} RX-only. "
        f"Watchdog armed, max {a.max_seconds}s. Ctrl-C to stop.")

    proc = subprocess.Popen(
        f"stdbuf -oL tshark -l -i {MON} "
        f"-Y 'wlan.fixed.category_code==21 && wlan.sa=={VICTIM}' "
        f"-T fields -e frame.time_epoch -e wlan.fc.retry > {a.feed}", shell=True)

    t0 = time.time()
    reason = f"reached max-seconds ({a.max_seconds}s)"
    try:
        while True:
            if proc.poll() is not None:
                reason = "tshark exited (check the Alfa)"
                break
            if time.time() - t0 > a.max_seconds:
                break
            if wedge_count() > base:
                reason = "WEDGE SIGNATURE in kernel log (mt7921u/-110/xhci) — aborting to protect the box"
                break
            if "type monitor" not in sh(f"iw dev {MON} info").stdout:
                reason = "mon0 vanished — card wedged, aborting"
                break
            time.sleep(3)
    except KeyboardInterrupt:
        reason = "stopped (Ctrl-C)"
    finally:
        try:
            proc.terminate()
        except Exception:
            pass
        teardown(phy, None, "true")
        say(f"sniffer stopped: {reason}. Alfa restored to managed mode.")


if __name__ == "__main__":
    main()
