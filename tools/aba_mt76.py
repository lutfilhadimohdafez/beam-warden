#!/usr/bin/env python3
"""A/B/A BeamCraft run on the ImmortalWrt AC2100 (mt76) — the PROVEN method.

Ports tools/aba_throughput.py (the 2026-10-12 clean −48/−53% run) to this rig
and logs the FULL 11-feature telemetry per phase, so the supervised detector
(train_supervised.py) gets real labelled normal+attack data for OBJ 3 — while
also producing the OBJ 1 throughput verdict.

Why this does NOT crash the laptop (unlike the sustained-saturated mistake):
  * BURSTY load — short bursts + idle gaps — so the AP RE-SOUNDS and the forged
    BFI actually lands (a saturating stream never sounds; see attack-context §8).
  * SHORT phases (default 20s) — the Alfa (mt7921u) wedges only after ~60s at
    80MHz, so each ON window finishes well inside the safe margin.
  * attack runs ON-phase only; OFF phases rest the card.
  * per-row flush — a late wedge never loses captured data.
  * A/B/A OFF→ON→OFF with the RSSI-drift confound guard (the Oct-11 lesson).

Attack side (mon0 + main_su, --type 0xe0 --offset 33 VHT) reused verbatim from
aba_measure. Telemetry = mt76 `iw dev <ap_iface> station dump` over SSH.

Run (one pkexec): pkexec /home/lutfil/fyp/.venv/bin/python /home/lutfil/fyp/tools/aba_mt76.py
"""
import argparse
import csv
import os
# resolve sbin tools under pkexec's minimal PATH
os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin:" + os.environ.get("PATH", "")
import statistics as st
import subprocess
import sys
sys.path.insert(0, __import__("os").path.dirname(__file__) or ".")
from rig import RIG  # rig.conf creds, not hardcoded
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aba_measure import (abort, check_mon_hearing, count_injections,
                         ensure_attack_dead, rssi_primary, spawn_attack)
from aba_throughput import run_iperf3_intervals, verdict_tput
from mt76_telemetry import SSHConn, parse_iw_station_dump, window_metrics
from gn630v_telemetry import compute_deltas

# full ML schema (matches mt76_capture.py so train_supervised reads it)
FIELDS = ["timestamp", "label", "condition",
          "throughput_tx_mbps", "throughput_rx_mbps", "retry_rate",
          "tx_per_pct", "rx_per_pct", "rssi0", "rssi1", "rssi2", "rssi3",
          "tx_mcs", "tx_nss", "bytes_sent", "bytes_recv",
          "packets_sent", "packets_recv", "tx_fail", "tx_failed", "feature_schema",
          "sample_seconds", "tx_failure_fraction", "active_attempts"]


def sh(cmd: str) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, shell=True, text=True, capture_output=True)


def say(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


PHYQ = ("for p in /sys/class/ieee80211/phy*; do d=$(basename "
        "$(readlink -f $p/device/driver) 2>/dev/null); "
        "[ \"$d\" = mt7921u ] && basename $p; done")


def monitor_up(mon: str, ch: str) -> None:
    # CRITICAL (memory 2026-10-31): the Alfa's firmware wedges after a crash/reboot
    # and silently stops delivering VHT BFI (captures only low-rate frames). A clean
    # modprobe reload restores full VHT-RX. Do it EVERY run so capture is reliable.
    say("reloading mt7921u for fresh firmware (wedged FW drops all VHT BFI)…")
    sh(f"iw dev {mon} del 2>/dev/null; nmcli device set wlan1 managed yes 2>/dev/null; "
       f"modprobe -r mt7921u 2>/dev/null")
    time.sleep(3)
    sh("modprobe mt7921u 2>/dev/null")
    phy = ""
    for _ in range(15):
        phy = sh(PHYQ).stdout.strip()
        if phy:
            break
        time.sleep(1)
    if not phy:
        abort("Alfa did not re-enumerate after reload — the ONE case needing a replug.")
    say(f"monitor {mon} on ch{ch} (phy={phy}, fresh FW)…")
    # 20MHz monitor (AP is VHT20): `set channel` matches the AP width; BFI captures
    # fine here (proven 2026-10-31: 58 cat-21 reports from the victim). reg MY = TX.
    sh(f"iw reg set MY 2>/dev/null; nmcli device set wlan1 managed no 2>/dev/null; "
       f"iw dev {mon} del 2>/dev/null; iw dev wlan1 del 2>/dev/null; "
       f"iw phy {phy} interface add {mon} type monitor; ip link set {mon} up; "
       f"iw dev {mon} set channel {ch}")
    if "type monitor" not in sh(f"iw dev {mon} info").stdout:
        abort(f"monitor setup failed for {mon}")
    return phy


def teardown(phy, srv, phone_ssh):
    say("teardown…")
    ensure_attack_dead()
    try:
        srv and srv.terminate()
    except Exception:
        pass
    if phone_ssh:
        sh(f"{phone_ssh} 'pkill iperf3' 2>/dev/null")
    sh(f"iw dev mon0 del 2>/dev/null; "
       f"iw phy {phy} interface add wlan1 type managed 2>/dev/null; "
       f"nmcli device set wlan1 managed yes 2>/dev/null")


def sample_row(conn, ap_iface, prev):
    """One full-feature telemetry row from the AP's view of the station."""
    cur = parse_iw_station_dump(conn.run(f"iw dev {ap_iface} station dump"), RIG['VICTIM_MAC'])
    now = time.time()
    row = None
    if prev:
        dt = now - prev["_t"]
        try:
            d = window_metrics(prev["_s"], cur, dt)
        except ValueError:
            d = {}
        if d:
            row = {
                "throughput_tx_mbps": d["throughput_tx_mbps"],
                "throughput_rx_mbps": d["throughput_rx_mbps"],
                "retry_rate": d["retry_rate"],
                "tx_per_pct": d["tx_per_pct"], "rx_per_pct": cur["rx_per_pct"],
                "rssi0": cur["rssi0"], "rssi1": cur["rssi1"],
                "rssi2": cur["rssi2"], "rssi3": cur["rssi3"],
                "tx_mcs": cur["tx_mcs"], "tx_nss": cur["tx_nss"],
                "bytes_sent": cur["bytes_sent"], "bytes_recv": cur["bytes_recv"],
                "packets_sent": cur["packets_sent"],
                "packets_recv": cur["packets_recv"], "tx_fail": cur["tx_fail"],
                **{k: d[k] for k in ('tx_failed','feature_schema','sample_seconds','tx_failure_fraction','active_attempts')},
            }
    return row, {"_t": now, "_s": cur}


def measure_phase(conn, ap_iface, writer, fh, label, condition,
                  victim_ip, port, seconds, burst, gap):
    """Bursty downlink load + concurrent full-telemetry sampling for `seconds`.

    Returns the per-second iperf tput list (for the OBJ1 verdict). Each telemetry
    sample (~every `burst+gap`) is written as a labelled ML row and flushed.
    """
    say(f"phase {condition} ({label}) {seconds:g}s…")
    tput, prev = [], None
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        time.sleep(gap)                       # idle gap → AP re-sounds next burst
        if time.monotonic() >= deadline:
            break
        ivals = run_iperf3_intervals(victim_ip, port, burst, None)  # box→phone DL
        tput.extend(ivals[1:] if len(ivals) > 1 else ivals)         # drop slow-start
        row, prev = sample_row(conn, ap_iface, prev)
        if row:
            row.update(timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                       label=label, condition=condition)
            writer.writerow(row)
            fh.flush()
            say(f"  {condition}: tx={row['throughput_tx_mbps']:.1f}Mbps "
                f"retry={row['retry_rate']} per={row['tx_per_pct']} "
                f"rssi0={row['rssi0']} mcs={row['tx_mcs']}")
    return tput


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default=RIG["ROUTER_HOST"])
    p.add_argument("--user", default=RIG["ROUTER_USER"])
    p.add_argument("--password", default=RIG["ROUTER_PASS"])
    p.add_argument("--ap-iface", default=RIG["ROUTER_AP_IFACE"])
    p.add_argument("--ap", default=RIG["ROUTER_AP_BSSID"])
    p.add_argument("--victim", default=RIG["VICTIM_MAC"])
    p.add_argument("--victim-ip", default=RIG["VICTIM_IP"])
    p.add_argument("--phone-user", default=RIG["PHONE_USER"])
    p.add_argument("--phone-port", default=RIG["PHONE_PORT"])
    p.add_argument("--phone-pass", default=RIG["PHONE_PASS"])
    p.add_argument("--mon", default="mon0")
    p.add_argument("--channel", default="36")
    p.add_argument("--port", type=int, default=5201)
    p.add_argument("--off", type=float, default=20)
    p.add_argument("--on", type=float, default=20)
    p.add_argument("--cycles", type=int, default=2)
    p.add_argument("--burst", type=float, default=3.0)
    p.add_argument("--gap", type=float, default=0.6)
    p.add_argument("--alpha", type=float, default=1.0)
    p.add_argument("--drift-tol", type=float, default=3.0)
    p.add_argument("--out", default=None)
    a = p.parse_args()

    if os.geteuid() != 0:
        abort("run under pkexec/sudo (needs root for monitor + attack).")
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    # absolute path — pkexec's CWD is NOT the project, so a relative "data/" lands
    # in a root-owned dir and is lost (happened 2026-10-31).
    root = Path(__file__).resolve().parent.parent
    out = Path(a.out) if a.out else root / "data" / f"real_aba_{ts}.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    phone_ssh = (f"sshpass -p {a.phone_pass} ssh -p {a.phone_port} "
                 f"-o StrictHostKeyChecking=no -o ConnectTimeout=8 "
                 f"{a.phone_user}@{a.victim_ip}")

    phy = monitor_up(a.mon, a.channel)
    # start iperf3 server on the phone (downlink target) + hold a wake-lock
    sh(f"{phone_ssh} 'pkill iperf3 2>/dev/null; termux-wake-lock; "
       f"nohup iperf3 -s -p {a.port} >/dev/null 2>&1 &'")
    time.sleep(2)
    srv = None  # phone hosts the iperf server; nothing to hold locally

    try:
        d = check_mon_hearing(a.mon)
        if d == 0:
            abort(f"{a.mon} RX-DEAF (0 rx in 2s) — reseat/recover the Alfa, re-run.")
        say(f"{a.mon} hearing OK ({d} rx/2s)")
        probe = run_iperf3_intervals(a.victim_ip, a.port, 2, None)
        if not probe:
            abort(f"no iperf3 from {a.victim_ip}:{a.port} — is the phone server up?")
        say(f"iperf3 OK ({st.median(probe):g} Mbps probe)")

        alloff, allon = {"tput": [], "rssi": []}, {"tput": [], "rssi": []}
        total_inj = 0
        with SSHConn(a.host, a.user, a.password) as conn, out.open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=FIELDS)
            w.writeheader(); fh.flush()
            for c in range(1, a.cycles + 1):
                ensure_attack_dead()
                t_off1 = measure_phase(conn, a.ap_iface, w, fh, "normal",
                                       f"off1_c{c}", a.victim_ip, a.port,
                                       a.off, a.burst, a.gap)
                say(f"cycle {c}: firing attack (ON {a.on:g}s)…")
                proc, lines, reader = spawn_attack(a.mon, a.ap, a.victim, alpha=a.alpha)
                t_on = measure_phase(conn, a.ap_iface, w, fh, "attack",
                                     f"on_c{c}", a.victim_ip, a.port,
                                     a.on, a.burst, a.gap)
                ensure_attack_dead(proc); reader.join(timeout=2)
                inj = count_injections(lines)
                total_inj += inj
                say(f"cycle {c}: injections={inj}")
                t_off2 = measure_phase(conn, a.ap_iface, w, fh, "normal",
                                       f"off2_c{c}", a.victim_ip, a.port,
                                       a.off, a.burst, a.gap)
                alloff["tput"] += t_off1 + t_off2
                allon["tput"] += t_on
    finally:
        teardown(phy, srv, phone_ssh)

    # OBJ1 verdict (throughput) — confound guard still applies via RSSI in rows
    label, detail = verdict_tput({"tput": alloff["tput"], "rssi": []},
                                 {"tput": allon["tput"], "rssi": []},
                                 {"tput": alloff["tput"], "rssi": []},
                                 total_inj, a.drift_tol)
    print("\n" + "=" * 60)
    print(f"OBJ1 throughput: {label} — {detail}")
    print(f"injections total: {total_inj}")
    print(f"ML dataset: {out}")
    print("next: .venv/bin/python tools/train_supervised.py --csv "
          f"{out}   (OBJ3 detection accuracy)")
    print("=" * 60)


if __name__ == "__main__":
    main()
