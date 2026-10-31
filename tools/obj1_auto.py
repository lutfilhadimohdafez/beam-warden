#!/usr/bin/env python3
"""Automated OBJ1 — hands-off after ONE pkexec password.

Sweeps the AP's 5GHz TX power DOWN through a few levels and re-runs the proven
tools/obj1_run.py at each, stopping as soon as the lag-aware throughput drop
clears 51%. Then restores power to auto. Why a sweep: the attack only bites once
the link is near the beamforming-dependent MCS cliff; the right power depends on
the phone's distance, so we search instead of guessing.

SAFE by construction:
  * each level calls obj1_run.py fresh -> monitor_up reloads the Alfa firmware
    every level (no wedge accumulation across the sweep).
  * obj1_run.py hard-caps every injection burst at 40s (<60s Alfa-wedge margin).
  * stops at the FIRST level that clears 51% (usually level 1-2), so exposure is
    minimal; power is always restored to auto in the finally.

Run (one pkexec): pkexec /home/lutfil/fyp/.venv/bin/python /home/lutfil/fyp/tools/obj1_auto.py
Optional levels:  ... tools/obj1_auto.py 400,300,200   (mBm; default 400,300,200)
"""
import os
os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin:" + os.environ.get("PATH", "")
import re
import subprocess
import sys
import time
from pathlib import Path

FYP = Path(__file__).resolve().parent.parent
PY = FYP / ".venv" / "bin" / "python"
OBJ1 = FYP / "tools" / "obj1_run.py"
LOG = Path("/tmp/beam-warden/obj1_auto_last.log")
ROUTER = "sshpass -p admin ssh -o StrictHostKeyChecking=no -o ConnectTimeout=8 root@192.168.1.1"


def say(m):
    print(f"\n########## {m} ##########", flush=True)


def txpower(val):
    """val = 'fixed <mBm>' or 'auto'. Router 5GHz radio = phy1."""
    subprocess.run(f"{ROUTER} 'iw phy phy1 set txpower {val}'", shell=True)


def run_level(mbm):
    """Set power, run obj1_run.py live (tee'd), return (drop_pct, injections)."""
    say(f"LEVEL {mbm} mBm ({mbm/100:g} dBm)")
    txpower(f"fixed {mbm}")
    time.sleep(2)
    LOG.parent.mkdir(parents=True, exist_ok=True)
    # tee: user sees it live AND we parse the verdict afterwards
    subprocess.run(f"{PY} {OBJ1} 2>&1 | tee {LOG}", shell=True)
    txt = LOG.read_text(errors="ignore") if LOG.exists() else ""
    m = re.search(r"throughput drop:\s*([\-\d.]+)%", txt)
    inj = re.search(r"injections total:\s*(\d+)", txt)
    return (float(m.group(1)) if m else None,
            int(inj.group(1)) if inj else 0)


def main():
    if os.geteuid() != 0:
        sys.exit("run under pkexec (obj1_run needs root for monitor + attack).")
    levels = [int(x) for x in (sys.argv[1].split(",") if len(sys.argv) > 1
                               else ["400", "300", "200"])]
    results, cleared = [], None
    try:
        for mbm in levels:
            drop, inj = run_level(mbm)
            results.append((mbm, drop, inj))
            if inj == 0:
                say(f"LEVEL {mbm}: INJECT=0 (Alfa capture failed) — trying next level")
                continue
            if drop is not None and drop >= 51:
                cleared = (mbm, drop)
                break
            say(f"LEVEL {mbm}: drop {drop}% < 51% — stepping power down")
    finally:
        txpower("auto")
        say("AP TX power restored to AUTO")

    print("\n" + "=" * 64)
    print("OBJ1 AUTO-SWEEP SUMMARY")
    for mbm, drop, inj in results:
        d = f"{drop:.1f}%" if drop is not None else "n/a"
        print(f"  {mbm:>4} mBm ({mbm/100:>4.1f} dBm): drop={d:>7}  inject={inj}")
    if cleared:
        print(f"\n  ✅ OBJ1 CLEARED: {cleared[1]:.1f}% drop at {cleared[0]/100:g} dBm (>=51%)")
    else:
        print("\n  ⚠️  51% not reached in sweep — widen levels "
              "(e.g. 150,100) or check RSSI drift / INJECT counts above.")
    print("=" * 64)


if __name__ == "__main__":
    main()
