#!/usr/bin/env python3
"""OBJ3 capture: record the on-air BFI storm during an A/B/A attack.

tcpdump sniffs mon0 for the whole run while we cycle normal -> attack -> normal.
Normal phases carry only GENUINE BFI (the AP sounding the victim); the attack
phase adds ~195 INJECTED forged BFI with the RETRY=1 bit. bfi_features.py then
slices the pcap into labelled windows where BFI-rate + RETRY-count spike during
attack -> the detectable anomaly, independent of link quality.

Injection runs in 20s bursts only (Alfa-safe, memory 2026-10-31).
Run: pkexec /home/lutfil/fyp/.venv/bin/python /home/lutfil/fyp/tools/bfi_run.py
"""
import os
os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin:" + os.environ.get("PATH", "")
import json
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aba_mt76 import monitor_up, teardown, sh, say
from aba_measure import (check_mon_hearing, count_injections, ensure_attack_dead,
                         spawn_attack)

FYP = Path(__file__).resolve().parent.parent
MON, CH = "mon0", "36"
AP, VICTIM, VICTIM_IP = "5c:02:14:0e:e1:c5", "16:0f:02:1d:91:42", "192.168.1.105"
PH = ("sshpass -p prime1208 ssh -p 8022 -o StrictHostKeyChecking=no "
      "-o ConnectTimeout=8 u0_a349@192.168.1.105")


def load_loop(stop):
    """Bursty downlink so the AP keeps RE-SOUNDING the victim (genuine BFI flows)."""
    while not stop.is_set():
        subprocess.run(f"iperf3 -c {VICTIM_IP} -p 5201 -t 3 >/dev/null 2>&1", shell=True)
        stop.wait(0.6)


def main():
    if os.geteuid() != 0:
        sys.exit("run under pkexec (needs root for monitor + attack).")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    pcap = FYP / "data" / f"bfi_{ts}.pcap"
    phasesf = FYP / "data" / f"bfi_{ts}.phases.json"
    pcap.parent.mkdir(parents=True, exist_ok=True)

    phy = monitor_up(MON, CH)                      # FW reload + mon0 @ 20MHz
    sh(f"{PH} 'pkill iperf3 2>/dev/null; termux-wake-lock; "
       f"nohup iperf3 -s -p 5201 >/dev/null 2>&1 &'")
    time.sleep(2)
    say(f"{MON} hearing {check_mon_hearing(MON)} rx/2s")

    sniff = subprocess.Popen(f"tcpdump -i {MON} -w {pcap} 2>/dev/null", shell=True)
    time.sleep(1)
    stop = threading.Event()
    threading.Thread(target=load_loop, args=(stop,), daemon=True).start()

    phases = []

    def phase(label, cond, secs, attack=False):
        say(f"phase {cond} ({label}) {secs:g}s…")
        t0 = time.time()
        proc = lines = reader = None
        if attack:
            proc, lines, reader = spawn_attack(MON, AP, VICTIM, alpha=1.0)
        time.sleep(secs)
        inj = 0
        if attack:
            ensure_attack_dead(proc)
            reader.join(timeout=2)
            inj = count_injections(lines)
        phases.append({"label": label, "condition": cond,
                       "t0": t0, "t1": time.time(), "inj": inj})
        say(f"  {cond}: injections={inj}")

    try:
        for c in (1, 2):
            phase("normal", f"off1_c{c}", 20)
            phase("attack", f"on_c{c}", 20, attack=True)
            phase("normal", f"off2_c{c}", 20)
    finally:
        stop.set()
        try:
            sniff.terminate()
        except Exception:
            pass
        time.sleep(1)
        teardown(phy, None, PH)

    phasesf.write_text(json.dumps(phases, indent=2))
    tot = sh(f"tcpdump -r {pcap} 2>/dev/null | wc -l").stdout.strip()
    print("\n" + "=" * 60)
    print(f"pcap   : {pcap}  ({tot} frames)")
    print(f"phases : {phasesf}")
    print(f"total injections: {sum(p['inj'] for p in phases)}")
    print(f"next: .venv/bin/python tools/bfi_features.py --pcap {pcap} --phases {phasesf}")
    print("=" * 60)


if __name__ == "__main__":
    main()
