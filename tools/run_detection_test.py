#!/usr/bin/env python3
"""BeamCraft WiFi-5 detection validation — ONE password, fully hands-off.

Run (one sudo prompt, then walk away):

    sudo /home/lutfil/fyp/.venv/bin/python /home/lutfil/fyp/tools/run_detection_test.py

What it does, in one controlled session (no drift confound — normal and attack
captured back-to-back under identical saturated load):

  1. preflight: phone associated? Alfa (mt7921u) present? main_su there?
  2. bring up the Alfa in monitor mode (mon0) on the AP's channel        [root]
  3. saturate the victim's downlink (laptop iperf3 -> phone, reverse)
  4. capture NORMAL telemetry under load            (auto-label normal)
  5. fire the BeamCraft forged-BFI attack            (main_su)            [root]
  6. capture ATTACK telemetry under same load        (auto-label attack)
  7. stop the attack; capture RECOVERY               (auto-label normal)
  8. tear down (mon0 removed, wlan1 restored, iperf killed)
  9. print the verdict: normal-vs-attack throughput drop + rows per class

Writes data/real_test_<ts>.csv (real hardware only — NO synthesis). Then:
    .venv/bin/python tools/train_supervised.py --csv data/real_test_*.csv

ponytail: thin orchestrator — reuses the tested mt76_capture.py for every
capture phase instead of re-implementing the poll loop; stdlib only.
"""
import csv
import os
# ensure sbin tools (iw, ip, nmcli) resolve under a minimal root PATH (pkexec/sudo)
os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin:" + os.environ.get("PATH", "")
import signal
import statistics as st
import subprocess
import sys
sys.path.insert(0, __import__("os").path.dirname(__file__) or ".")
from rig import RIG  # rig.conf creds, not hardcoded
import time
from pathlib import Path

FYP = Path("/home/lutfil/fyp")
PY = sys.executable  # we're run under sudo venv python; reuse it for subprocs
CAPTURE = FYP / "tools" / "mt76_capture.py"
MAIN_SU = FYP / "BeamCraft_AE" / "main_su"

# ── rig (AC2100 ImmortalWrt, WiFi-5 VHT) ─────────────────────────────────
AP = RIG["ROUTER_AP_BSSID"]     # phy1-ap0 5GHz BSSID
VICTIM = RIG["VICTIM_MAC"]      # victim station
CH = RIG["ROUTER_CHANNEL"]      # AP channel — fixed non-DFS (reliable inject + demo)
IFACE = "mon0"
ALPHA = "1.0"
FTYPE = "0xe0"
OFFSET = "33"

ROUTER_SSH = ["sshpass", "-p", RIG["ROUTER_PASS"], "ssh", "-o", "StrictHostKeyChecking=no",
              "-o", "ConnectTimeout=8", f"{RIG['ROUTER_USER']}@{RIG['ROUTER_HOST']}"]
AP_IFACE = RIG["ROUTER_AP_IFACE"]
PHONE = ["sshpass", "-p", RIG["PHONE_PASS"], "ssh", "-p", RIG["PHONE_PORT"],
         "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=8",
         f"{RIG['PHONE_USER']}@{RIG['VICTIM_IP']}"]

# ── phase durations (seconds) — override with argv: normal attack recovery
NORMAL_S, ATTACK_S, RECOVERY_S = 90, 90, 30
if len(sys.argv) == 4:
    NORMAL_S, ATTACK_S, RECOVERY_S = (int(x) for x in sys.argv[1:4])

TS = time.strftime("%Y%m%d_%H%M%S")
OUT = FYP / "data" / f"real_test_{TS}.csv"
LOGDIR = Path("/tmp/beam-warden")
LOGDIR.mkdir(parents=True, exist_ok=True)


def sh(cmd: str, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, text=True, capture_output=True, **kw)


def say(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def laptop_lan_ip() -> str:
    """The laptop's address on the AC2100 LAN (192.168.1.0/24) — iperf server."""
    out = sh("ip -4 -o addr show | awk '{print $4}'").stdout
    for cidr in out.split():
        if cidr.startswith("192.168.1."):
            return cidr.split("/")[0]
    sys.exit("FAIL: laptop has no 192.168.1.x address — is USB-ether up?")


# ── preflight ────────────────────────────────────────────────────────────
def preflight() -> str:
    say("preflight…")
    if os.geteuid() != 0:
        sys.exit("FAIL: must run under sudo (need root for monitor + attack).")
    if not MAIN_SU.exists():
        sys.exit(f"FAIL: {MAIN_SU} missing.")
    # phone associated to the AP?
    dump = sh(f"{' '.join(ROUTER_SSH)} 'iw dev {AP_IFACE} station dump'").stdout
    if VICTIM.lower() not in dump.lower():
        sys.exit(f"FAIL: victim {VICTIM} not associated to {AP_IFACE}. "
                 f"Put the phone on the ImmortalWrt Wi-Fi first.")
    # Alfa present?
    phys = sh("for p in /sys/class/ieee80211/phy*; do "
              "d=$(basename $(readlink -f $p/device/driver) 2>/dev/null); "
              "[ \"$d\" = mt7921u ] && basename $p; done").stdout.strip()
    if not phys:
        sys.exit("FAIL: no mt7921u (Alfa) phy found — is the Alfa plugged in?")
    ip = laptop_lan_ip()
    say(f"preflight OK — victim assoc, Alfa={phys}, laptop={ip}")
    return phys


# ── monitor mode (root) ───────────────────────────────────────────────────
def monitor_up(phy: str) -> None:
    say(f"bringing up {IFACE} (monitor) on channel {CH}…")
    cmd = (f"nmcli device set wlan1 managed no 2>/dev/null; "
           f"iw dev {IFACE} del 2>/dev/null; iw dev wlan1 del 2>/dev/null; "
           f"iw phy {phy} interface add {IFACE} type monitor; "
           f"ip link set {IFACE} up; "
           f"iw dev {IFACE} set channel {CH}")
    r = sh(cmd)
    info = sh(f"iw dev {IFACE} info").stdout
    if "type monitor" not in info:
        sys.exit(f"FAIL: monitor setup failed.\n{r.stderr}\n{info}")
    say("monitor up: " + " ".join(l.strip() for l in info.splitlines()
                                  if "type" in l or "channel" in l))


# ── load generation (saturate victim downlink) ─────────────────────────────
def start_load(ip: str, total_s: int):
    sh("pkill -f 'iperf3 -s' 2>/dev/null")
    srv = subprocess.Popen(["iperf3", "-s", "-B", ip],
                           stdout=open(LOGDIR / "iperf_srv.log", "w"),
                           stderr=subprocess.STDOUT)
    time.sleep(2)
    # phone pulls a reverse (downlink) stream = the beamformed path under test
    cli = subprocess.Popen(
        PHONE + [f"termux-wake-lock; iperf3 -c {ip} -R -t {total_s}"],
        stdout=open(LOGDIR / "phone_iperf.log", "w"), stderr=subprocess.STDOUT)
    time.sleep(3)
    say("load started (iperf3 reverse downlink to phone)")
    return srv, cli


# ── capture one phase via the tested mt76_capture.py ───────────────────────
def capture(label: str, condition: str, duration: int) -> None:
    say(f"capture {label}/{condition} for {duration}s…")
    subprocess.run([PY, str(CAPTURE), "--label", label, "--condition", condition,
                    "--duration", str(duration), "--out", str(OUT)], check=False)


# ── attack (root) ──────────────────────────────────────────────────────────
def fire_attack():
    say("FIRING attack (main_su)…")
    log = open(LOGDIR / "main_su.log", "w")
    proc = subprocess.Popen(
        [str(MAIN_SU), "--iface", IFACE, "--ap", AP, "--victim", VICTIM,
         "--alpha", ALPHA, "--type", FTYPE, "--offset", OFFSET],
        stdout=log, stderr=subprocess.STDOUT)
    time.sleep(3)  # let injection ramp before we start measuring
    if proc.poll() is not None:
        say("WARN: main_su exited immediately — check scratchpad/main_su.log")
    return proc


def stop_attack(proc) -> int:
    if proc and proc.poll() is None:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
    sh("pkill -INT -f main_su 2>/dev/null")
    # count injected frames from the attack log (success signal)
    txt = (LOGDIR / "main_su.log").read_text(errors="ignore") if \
        (LOGDIR / "main_su.log").exists() else ""
    frames = sum(1 for ln in txt.splitlines() if "inject" in ln.lower()
                 or "forged" in ln.lower() or "tx" in ln.lower())
    return frames


def teardown(srv, cli, phy: str):
    say("teardown…")
    for p in (srv, cli):
        try:
            p and p.terminate()
        except Exception:
            pass
    sh("pkill -f 'iperf3 -s' 2>/dev/null")
    sh(f"{' '.join(PHONE)} 'pkill iperf3' 2>/dev/null")
    sh(f"iw dev {IFACE} del 2>/dev/null; "
       f"iw phy {phy} interface add wlan1 type managed 2>/dev/null; "
       f"nmcli device set wlan1 managed yes 2>/dev/null")


# ── verdict ────────────────────────────────────────────────────────────────
def verdict(frames: int):
    if not OUT.exists():
        say("no CSV written — capture failed.")
        return
    rows = list(csv.DictReader(OUT.open()))
    by = {}
    for r in rows:
        by.setdefault(r["label"], []).append(float(r["throughput_tx_mbps"]))
    print("\n" + "=" * 60)
    print(f"RESULT  ->  {OUT}")
    print(f"frames injected (approx, from main_su log): {frames}")
    for lbl in ("normal", "attack"):
        v = by.get(lbl, [])
        if v:
            print(f"  {lbl:7} n={len(v):3}  tx_tput mean={st.mean(v):7.2f} "
                  f"max={max(v):7.2f} Mbps")
    if by.get("normal") and by.get("attack"):
        n, a = st.mean(by["normal"]), st.mean(by["attack"])
        drop = (n - a) / n * 100 if n else 0
        print(f"\n  NORMAL->ATTACK downlink change: {drop:+.1f}%  "
              f"({'detectable' if abs(drop) >= 15 else 'WEAK — may need ch36 / higher load'})")
    print("=" * 60)
    print("next:  .venv/bin/python tools/train_supervised.py "
          f"--csv {OUT}  (will report detection accuracy)")


def main():
    phy = preflight()
    ip = laptop_lan_ip()
    srv = cli = None
    attack = None
    frames = 0
    try:
        monitor_up(phy)
        total = NORMAL_S + ATTACK_S + RECOVERY_S + 20
        srv, cli = start_load(ip, total)
        capture("normal", "saturated", NORMAL_S)
        attack = fire_attack()
        capture("attack", "saturated", ATTACK_S)
        frames = stop_attack(attack)
        capture("normal", "recovery", RECOVERY_S)
    finally:
        if attack:
            stop_attack(attack)
        teardown(srv, cli, phy)
    verdict(frames)


if __name__ == "__main__":
    main()
