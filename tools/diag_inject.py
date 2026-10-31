#!/usr/bin/env python3
"""Diagnose why main_su injected 0 forged BFI on the AC2100 (mt76) rig.

SAFE: ~12s monitor + one short LIVE main_su burst (Alfa-safe, well under the
~60s wedge wall) + an OFFLINE --pcap decode (no injection at all). Saves
main_su's own stdout (the thing aba_mt76 discarded) so we can read the reason.

Answers three questions:
  (B1) is the victim's BFI even on air?      -> tcpdump frame count on mon0
  (B2) does main_su catch + DECODE it?       -> offline  main_su --pcap <cap>
  (A)  does pcap_inject FAIL (TX not perm.)? -> live main_su stdout "FAIL"/"OK"

Run: pkexec /home/lutfil/fyp/.venv/bin/python /home/lutfil/fyp/tools/diag_inject.py
"""
import os
os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin:" + os.environ.get("PATH", "")
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rig import RIG  # rig.conf creds, not hardcoded
from aba_measure import abort

FYP = Path("/home/lutfil/fyp")
MON, CH = "mon0", RIG["ROUTER_CHANNEL"]
AP, VICTIM = RIG["ROUTER_AP_BSSID"], RIG["VICTIM_MAC"]
BIN = str(FYP / "BeamCraft_AE" / "main_su")
SCR = Path("/tmp/beam-warden")
PHONE = (f"sshpass -p {RIG['PHONE_PASS']} ssh -p {RIG['PHONE_PORT']} -o StrictHostKeyChecking=no "
         f"-o ConnectTimeout=8 {RIG['PHONE_USER']}@{RIG['VICTIM_IP']}")
VICTIM_IP = RIG["VICTIM_IP"]


def sh(c): return subprocess.run(c, shell=True, text=True, capture_output=True)
def say(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


def main():
    if os.geteuid() != 0:
        abort("run under pkexec/sudo (needs root for monitor + inject).")
    phy = sh("for p in /sys/class/ieee80211/phy*; do d=$(basename "
             "$(readlink -f $p/device/driver) 2>/dev/null); "
             "[ \"$d\" = mt7921u ] && basename $p; done").stdout.strip()
    if not phy:
        abort("no mt7921u (Alfa) phy found.")
    say(f"monitor up {phy}/{MON} ch{CH}")
    # 80MHz monitor: VHT BFI is UNREADABLE at 20MHz (memory 2026-10-01). mt7921u
    # rejects `set channel N 80MHz`; must use `set freq <primary> 80 <center>`
    # (ch36 -> 5180 80 5210, memory 2026-10-10). reg MY unlocks clean TX on ch36.
    sh(f"iw reg set MY 2>/dev/null; nmcli device set wlan1 managed no 2>/dev/null; "
       f"iw dev {MON} del 2>/dev/null; iw dev wlan1 del 2>/dev/null; "
       f"iw phy {phy} interface add {MON} type monitor; ip link set {MON} up; "
       f"iw dev {MON} set freq 5180 80 5210")
    say("reg: " + (sh("iw reg get | grep -m1 country").stdout.strip() or "?"))
    say("mon0: " + " ".join(l.strip() for l in
                            sh(f"iw dev {MON} info").stdout.splitlines()
                            if "type" in l or "channel" in l))

    # phone iperf server + bursty load (forces the AP to re-sound -> BFI on air)
    sh(f"{PHONE} 'pkill iperf3 2>/dev/null; termux-wake-lock; "
       f"nohup iperf3 -s -p 5201 >/dev/null 2>&1 &'")
    time.sleep(2)
    stop = threading.Event()

    def load():
        while not stop.is_set():
            subprocess.run(f"iperf3 -c {VICTIM_IP} -p 5201 -t 2 >/dev/null 2>&1",
                           shell=True)
            stop.wait(0.6)
    threading.Thread(target=load, daemon=True).start()

    pcap = str(SCR / "bfi_diag.pcap")
    log = str(SCR / "main_su_diag.log")
    say("sniffing mon0 + running main_su LIVE for 12s…")
    sniff = subprocess.Popen(f"timeout 13 tcpdump -i {MON} -w {pcap} 2>/dev/null",
                             shell=True)
    with open(log, "w") as f:
        proc = subprocess.Popen(
            [BIN, "--iface", MON, "--ap", AP, "--victim", VICTIM,
             "--alpha", "1.0", "--type", "0xe0", "--offset", "33"],
            stdout=f, stderr=subprocess.STDOUT)
        time.sleep(12)
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=6)
        except subprocess.TimeoutExpired:
            proc.kill()
    sniff.wait()
    stop.set()

    sh(f"{PHONE} 'pkill iperf3' 2>/dev/null")
    sh(f"iw dev {MON} del 2>/dev/null; "
       f"iw phy {phy} interface add wlan1 type managed 2>/dev/null; "
       f"nmcli device set wlan1 managed yes 2>/dev/null")
    say("teardown done")

    print("\n============ (A) main_su LIVE stdout ============")
    live = Path(log).read_text(errors="ignore") if Path(log).exists() else ""
    print(live[-2500:] or "(empty — caught/printed nothing)")

    print("\n============ (B1) frames captured on air ============")
    total = sh(f"tcpdump -r {pcap} 2>/dev/null | wc -l").stdout.strip()
    print(f"total frames on mon0: {total}  (pcap: {pcap})")

    print("\n============ (B2) main_su OFFLINE decode (no inject) ============")
    r = sh(f"{BIN} --pcap {pcap} --victim {VICTIM} --type 0xe0 --offset 33 2>&1")
    print((r.stdout or r.stderr)[-2500:] or "(no output)")

    print("\n============ READ ============")
    print("• live shows 'inject FAIL' / 'TX not permitted'  -> (A) can't inject on ch36")
    print("• live/offline found 0 BFI frames                -> (B) AP not sounding victim / MAC/type mismatch")
    print("• offline decodes BFI but live FAILed inject     -> injection-only fix (reg/driver)")


if __name__ == "__main__":
    main()
