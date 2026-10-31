#!/usr/bin/env python3
"""OBJ1 lag-aware throughput-drop measurement — does NOT assume recovery.

WHY THIS EXISTS (the bug it works around):
  tools/aba_throughput.verdict_tput (reused by aba_mt76) is an A/B/A verdict that
  only fires ATTACK CONFIRMED when ON throughput is below BOTH bracketing OFF
  medians (`to < t1 and to < t2`). The real attack has a LAG: during the 20s
  injection throughput is still ~53 Mbps, then it craters to ~30 in the FOLLOWING
  phase and does NOT recover within 40s. So OFF-2 is already degraded, `to < t2`
  is false, and a genuinely persistent attack reads as NO EFFECT. The A/B/A model
  is wrong for an effect that outlives the stimulus.

WHAT THIS DOES INSTEAD (A -> B, no recovery assumed):
  (a) clean BASELINE (~30s), downlink iperf3 + station-dump retry.
  (b) SUSTAINED attack fired in bursts each <= --burst-secs (<=40s; the Alfa
      wedges ~60s at this rig, so NEVER one >60s injection — re-fire for longer).
  (c) the first --ramp-bursts attack bursts are DISCARDED as the lag ramp; the
      remaining --settle-bursts measure the SETTLED/persistent degraded state.
  (d) honest verdict = (baseline_median - attack_settled_median)/baseline_median
      *100, plus the station-dump retry_rate delta. No recovery phase, no A/B/A
      gate that a persistent attack trips over.

Reuses the PROVEN harness verbatim: monitor_up/measure_phase/teardown/FIELDS from
aba_mt76 (incl. the mt7921u FW reload + per-row flush), spawn_attack/
count_injections/ensure_attack_dead/check_mon_hearing from aba_measure,
run_iperf3_intervals from aba_throughput, SSHConn from mt76_telemetry.

Run (one pkexec, as root):
  pkexec /home/lutfil/fyp/.venv/bin/python /home/lutfil/fyp/tools/obj1_run.py
Pure-logic self-check (no hardware):  python tools/obj1_run.py --selftest
"""
import argparse
import csv
import os
os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin:" + os.environ.get("PATH", "")
import statistics as st
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aba_mt76 import FIELDS, measure_phase, monitor_up, say, sh, teardown
from aba_measure import (abort, check_mon_hearing, count_injections,
                         ensure_attack_dead, spawn_attack)
from aba_throughput import run_iperf3_intervals
from mt76_telemetry import SSHConn


# ---------------------------------------------------------------- pure logic

def obj1_verdict(base_tput, atk_settled_tput, base_retry, atk_retry):
    """Lag-aware drop. Returns (base_med, atk_med, drop_pct, retry_delta).

    drop_pct is the settled throughput loss vs the clean baseline; no A/B/A,
    no recovery assumption. retry_delta is None when either retry median is
    missing. Raises ValueError on an empty throughput series (caller aborts).
    """
    if not base_tput or not atk_settled_tput:
        raise ValueError("empty throughput series")
    base_med = st.median(base_tput)
    atk_med = st.median(atk_settled_tput)
    drop_pct = (base_med - atk_med) / base_med * 100.0 if base_med > 0 else 0.0
    retry_delta = (atk_retry - base_retry) if (
        atk_retry is not None and base_retry is not None) else None
    return base_med, atk_med, drop_pct, retry_delta


def _csv_median(csv_path, field, keep, cast=float):
    """Median of `field` over CSV rows where keep(row) is true (missing/unparsable skipped)."""
    vals = []
    with open(csv_path, newline="") as fh:
        for row in csv.DictReader(fh):
            if not keep(row):
                continue
            v = row.get(field)
            if v in (None, ""):
                continue
            try:
                vals.append(cast(v))
            except (ValueError, TypeError):
                pass
    return st.median(vals) if vals else None


def _rssi_primary_median(csv_path, keep):
    """Median of per-row max(rssi0..3) — a drift eyeball, not a gate."""
    vals = []
    with open(csv_path, newline="") as fh:
        for row in csv.DictReader(fh):
            if not keep(row):
                continue
            chains = []
            for k in ("rssi0", "rssi1", "rssi2", "rssi3"):
                try:
                    r = int(float(row.get(k, 0)))
                except (ValueError, TypeError):
                    r = 0
                if r != 0:
                    chains.append(r)
            if chains:
                vals.append(max(chains))
    return st.median(vals) if vals else None


def demo():
    # lag case: baseline ~55, settled ~30 -> ~45% drop; retry climbs
    b, a, drop, dr = obj1_verdict([54, 56, 55], [31, 29, 30], 0.05, 0.27)
    assert b == 55 and a == 30 and abs(drop - 45.4545) < 1e-2, (b, a, drop)
    assert abs(dr - 0.22) < 1e-9, dr
    # no-effect case
    _, _, drop2, _ = obj1_verdict([50, 50], [50, 50], None, None)
    assert drop2 == 0.0
    try:
        obj1_verdict([], [1], 0, 0)
    except ValueError:
        pass
    else:
        raise AssertionError("empty series should raise")
    print("obj1_verdict self-check OK")


# --------------------------------------------------------------------- main

def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", default="192.168.1.1")
    p.add_argument("--user", default="root")
    p.add_argument("--password", default="admin")
    p.add_argument("--ap-iface", default="phy1-ap0")
    p.add_argument("--ap", default="5c:02:14:0e:e1:c5")
    p.add_argument("--victim", default="16:0f:02:1d:91:42")
    p.add_argument("--victim-ip", default="192.168.1.105")
    p.add_argument("--phone-user", default="u0_a349")
    p.add_argument("--phone-port", default="8022")
    p.add_argument("--phone-pass", default="prime1208")
    p.add_argument("--mon", default="mon0")
    p.add_argument("--channel", default="36")
    p.add_argument("--port", type=int, default=5201)
    p.add_argument("--baseline", type=float, default=30, metavar="sec",
                   help="clean baseline length")
    p.add_argument("--burst-secs", type=float, default=35, metavar="sec",
                   help="one injection window; HARD-capped at 40 (Alfa wedges ~60s)")
    p.add_argument("--ramp-bursts", type=int, default=1,
                   help="initial attack bursts DISCARDED as the lag ramp")
    p.add_argument("--settle-bursts", type=int, default=2,
                   help="attack bursts measured as the settled/persistent state")
    p.add_argument("--burst", type=float, default=3.0, help="iperf burst length")
    p.add_argument("--gap", type=float, default=0.6, help="idle gap (forces AP re-sound)")
    p.add_argument("--alpha", type=float, default=1.0)
    p.add_argument("--out", default=None)
    p.add_argument("--selftest", action="store_true",
                   help="run the pure-logic self-check and exit (no hardware)")
    a = p.parse_args()

    if a.selftest:
        demo()
        return

    if os.geteuid() != 0:
        abort("run under pkexec/sudo (needs root for monitor + attack).")
    # never let one injection run past the ~60s Alfa-wedge margin
    burst_secs = min(a.burst_secs, 40.0)
    if burst_secs != a.burst_secs:
        say(f"clamped --burst-secs {a.burst_secs:g} -> {burst_secs:g} (Alfa 60s wedge margin)")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    root = Path(__file__).resolve().parent.parent          # /home/lutfil/fyp
    out = Path(a.out) if a.out else root / "data" / f"obj1_{ts}.csv"
    out.parent.mkdir(parents=True, exist_ok=True)
    phone_ssh = (f"sshpass -p {a.phone_pass} ssh -p {a.phone_port} "
                 f"-o StrictHostKeyChecking=no -o ConnectTimeout=8 "
                 f"{a.phone_user}@{a.victim_ip}")

    phy = monitor_up(a.mon, a.channel)
    sh(f"{phone_ssh} 'pkill iperf3 2>/dev/null; termux-wake-lock; "
       f"nohup iperf3 -s -p {a.port} >/dev/null 2>&1 &'")
    time.sleep(2)

    base_tput = []
    ramp_tput, settled_tput = [], []
    total_inj = 0
    try:
        d = check_mon_hearing(a.mon)
        if d == 0:
            abort(f"{a.mon} RX-DEAF (0 rx in 2s) — reseat/recover the Alfa, re-run.")
        say(f"{a.mon} hearing OK ({d} rx/2s)")
        probe = run_iperf3_intervals(a.victim_ip, a.port, 2, None)
        if not probe:
            abort(f"no iperf3 from {a.victim_ip}:{a.port} — is the phone server up?")
        say(f"iperf3 OK ({st.median(probe):g} Mbps probe)")

        with SSHConn(a.host, a.user, a.password) as conn, out.open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=FIELDS)
            w.writeheader(); fh.flush()

            # (a) clean baseline — attack guaranteed dead
            ensure_attack_dead()
            base_tput = measure_phase(conn, a.ap_iface, w, fh, "normal", "baseline",
                                      a.victim_ip, a.port, a.baseline, a.burst, a.gap)

            # (b)+(c) sustained attack in <=40s bursts; discard ramp, keep settled
            nburst = a.ramp_bursts + a.settle_bursts
            for k in range(1, nburst + 1):
                settled = k > a.ramp_bursts
                cond = f"attack_settled_b{k}" if settled else f"attack_ramp_b{k}"
                ensure_attack_dead()
                say(f"burst {k}/{nburst} ({'SETTLED' if settled else 'ramp'}) "
                    f"firing attack {burst_secs:g}s…")
                proc, lines, reader = spawn_attack(a.mon, a.ap, a.victim, alpha=a.alpha)
                ptput = measure_phase(conn, a.ap_iface, w, fh, "attack", cond,
                                      a.victim_ip, a.port, burst_secs, a.burst, a.gap)
                ensure_attack_dead(proc); reader.join(timeout=2)
                inj = count_injections(lines); total_inj += inj
                say(f"burst {k}: injections={inj}, {len(ptput)} tput samples")
                (settled_tput if settled else ramp_tput).extend(ptput)
    finally:
        teardown(phy, None, phone_ssh)

    # (d) honest verdict — baseline vs settled, retry delta from the logged rows
    base_retry = _csv_median(out, "retry_rate", lambda r: r["label"] == "normal")
    settled_retry = _csv_median(
        out, "retry_rate", lambda r: r["condition"].startswith("attack_settled"))
    base_rssi = _rssi_primary_median(out, lambda r: r["label"] == "normal")
    settled_rssi = _rssi_primary_median(
        out, lambda r: r["condition"].startswith("attack_settled"))

    print("\n" + "=" * 64)
    if not base_tput or not settled_tput:
        print("OBJ1: INCONCLUSIVE — empty baseline or settled throughput series.")
        print(f"  baseline samples={len(base_tput)} settled samples={len(settled_tput)} "
              f"ramp(discarded)={len(ramp_tput)} injections={total_inj}")
        print(f"CSV: {out}")
        print("=" * 64)
        return
    if total_inj == 0:
        print("OBJ1: INCONCLUSIVE — INJECT=0, attack never fired; cannot attribute.")

    b_med, a_med, drop, dretry = obj1_verdict(
        base_tput, settled_tput, base_retry, settled_retry)
    obj1 = "CLEARS >=51%" if drop >= 51 else "below 51%"
    print(f"OBJ1 lag-aware throughput drop: {drop:.1f}%  [{obj1}]")
    print(f"  baseline median : {b_med:.1f} Mbps  (n={len(base_tput)})")
    print(f"  settled  median : {a_med:.1f} Mbps  (n={len(settled_tput)}, "
          f"ramp discarded n={len(ramp_tput)})")
    if dretry is not None:
        print(f"  retry_rate      : {base_retry:.3f} -> {settled_retry:.3f} "
              f"(delta {dretry:+.3f})")
    else:
        print("  retry_rate      : n/a (missing samples)")
    if base_rssi is not None and settled_rssi is not None:
        drift = abs(base_rssi - settled_rssi)
        flag = "  <-- CONFOUND RISK (RSSI moved >3 dB)" if drift > 3 else ""
        print(f"  rssi_primary    : {base_rssi:g} -> {settled_rssi:g} dB "
              f"(drift {drift:g} dB){flag}")
    print(f"  injections total: {total_inj}")
    print(f"CSV (labelled, OBJ3-ready): {out}")
    print("=" * 64)


if __name__ == "__main__":
    main()
