#!/usr/bin/env python3
"""Confound-aware A/B/A throughput measurement (OFF -> ON -> OFF).

Objective 1 metric: victim DOWNLINK throughput (Mbps) under normal working
conditions, while toggling the BeamCraft attack binary. Same RSSI-drift
confound control as aba_measure.

DIRECTION: the AP is the beamformer; the forged BFI steers the AP's DOWNLINK
(AP->victim). So we measure AP->phone, i.e. the phone RECEIVING. iperf3 runs
box(client) -> phone(server) with NO -R (default: client sends to server), so
bytes flow box -> AP -> phone = the beamformed downlink. (-R would reverse it to
phone->box = the phone's UPLINK, which this attack cannot touch — an early
version used -R and correctly saw NO EFFECT for that reason.)

SOUNDING: a *saturating* flow keeps the AP's TX queue backlogged so it rides a
stale steering matrix and never re-sounds (diary: "idle gap forces re-sounding;
steady saturation does NOT sound") -> forged BFI lands on nothing. So the load
is BURSTY: short downlink transfers separated by idle gaps, so the AP re-sounds
at the start of each burst and the forged BFI poisons a FRESH matrix. Also
closer to real app traffic (video buffer-fills, page loads) than a flood. The
first (slow-start) second of each burst is dropped; the steady seconds are the
phase's throughput samples.

Run under sudo (spawns root main_su). Pure logic (parse_iperf3_json /
phase_stats_tput / verdict_tput) is hardware free; all I/O lives in thin
helpers orchestrated by main().
"""

import argparse
import csv
import json
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from aba_measure import (
    abort,
    check_mon_hearing,
    count_injections,
    ensure_attack_dead,
    rssi_primary,
    spawn_attack,
)
from gn630v_telnet import GN630V
from gn630v_telemetry import parse_iwpriv_stat

CSV_FIELDS = [
    "timestamp", "cycle", "phase", "attack_on",
    "tput_mbps", "rssi_primary_median",
]


# ---------------------------------------------------------------- pure logic

def parse_iperf3_json(data: dict) -> list:
    """Extract per-interval Mbps from an iperf3 -J report.

    intervals[].sum.bits_per_second is the interval's goodput in bps; divide
    by 1e6 for the Mbps series (one point per iperf3 second).
    """
    out = []
    for interval in (data.get("intervals") or []):
        bps = ((interval or {}).get("sum") or {}).get("bits_per_second")
        if bps is None:
            continue
        out.append(float(bps) / 1e6)
    return out


def phase_stats_tput(phase: dict) -> dict:
    """Aggregate one phase's tput series + RSSI samples.

    Skips rssi==0 samples (parse-miss sentinel, same as aba_measure).
    Returns keys: median_tput, tput_min, tput_max, median_rssi, rssi_range,
    n_tput, n_rssi. Medians/min/max are None when a series is empty.
    """
    tput = [float(v) for v in (phase.get("tput") or []) if v is not None]
    rssi = [r for r in (phase.get("rssi") or []) if r is not None and r != 0]
    return {
        "median_tput": statistics.median(tput) if tput else None,
        "tput_min": min(tput) if tput else None,
        "tput_max": max(tput) if tput else None,
        "median_rssi": statistics.median(rssi) if rssi else None,
        "rssi_range": (max(rssi) - min(rssi)) if rssi else 0,
        "n_tput": len(tput),
        "n_rssi": len(rssi),
    }


def _as_tput_stats(d: dict) -> dict:
    """Accept a raw phase ({tput, rssi}) or a phase_stats_tput dict."""
    if d is None:
        return phase_stats_tput({})
    if "median_tput" in d or "n_tput" in d or "median_rssi" in d:
        return d
    return phase_stats_tput(d)


def verdict_tput(off1: dict, on: dict, off2: dict, inject_count: int, drift_tol: float):
    """Confound-aware A/B/A verdict on throughput. Returns (label, detail).

    label is one of CONFOUNDED / ATTACK CONFIRMED / NO EFFECT / INCONCLUSIVE.
    Medians only for RSSI — within-phase jitter is fine; what invalidates the
    cycle is the signal MEAN drifting between phases (copied from
    aba_measure.verdict). OBJ1 51% / OBJ2 15% drop thresholds are annotated
    only, never a gate.
    """
    confounded = "result INVALID, re-measure on a steadier signal."
    s1, son, s2 = _as_tput_stats(off1), _as_tput_stats(on), _as_tput_stats(off2)

    r1, ron, r2 = s1.get("median_rssi"), son.get("median_rssi"), s2.get("median_rssi")
    if r1 is not None and r2 is not None:
        baseline_drift = abs(r1 - r2)
        if baseline_drift > drift_tol:
            return (
                "CONFOUNDED",
                f"OFF baseline RSSI drifted {baseline_drift:g} dB across the cycle "
                f"({r1:g} -> {r2:g} dB) — the signal mean moved, not just jittered; "
                f"{confounded}",
            )
    if None not in (r1, ron, r2):
        off_base_rssi = statistics.median([r1, r2])
        level_gap = abs(ron - off_base_rssi)
        if level_gap > drift_tol:
            return (
                "CONFOUNDED",
                f"ON-phase RSSI ({ron:g} dB) sits {level_gap:g} dB off the OFF "
                f"baseline ({off_base_rssi:g} dB) — throughput gap not "
                f"attributable; {confounded}",
            )

    t1, to, t2 = s1.get("median_tput"), son.get("median_tput"), s2.get("median_tput")
    if inject_count == 0:
        return (
            "INCONCLUSIVE",
            "INJECT=0 — attack never fired; cannot attribute any throughput change.",
        )
    if t1 is None or to is None or t2 is None:
        return (
            "INCONCLUSIVE",
            "no valid throughput samples in one or more phases.",
        )

    off_base = statistics.median([t1, t2])
    if off_base <= 0:
        return (
            "INCONCLUSIVE",
            f"OFF baseline throughput is {off_base:g} Mbps — cannot compute a drop.",
        )
    drop_pct = (off_base - to) / off_base * 100.0
    obj1 = "CLEARS" if drop_pct >= 51 else "below"
    obj2 = "CLEARS" if drop_pct >= 15 else "below"
    if to < t1 and to < t2 and drop_pct >= 5:
        return (
            "ATTACK CONFIRMED",
            f"throughput dropped {drop_pct:.1f}% on ON ({off_base:g} -> {to:g} Mbps), "
            f"recovered on OFF ({t1:g}/{t2:g} Mbps), INJECT={inject_count}; "
            f"OBJ1 51%: {obj1}, OBJ2 15%: {obj2}",
        )
    return (
        "NO EFFECT",
        f"throughput flat (OFF medians {t1:g}/{t2:g} Mbps, ON {to:g} Mbps, "
        f"drop {drop_pct:.1f}%) despite INJECT={inject_count}; "
        f"no attributable drop.",
    )


# ------------------------------------------------------------------ thin I/O

# ponytail: NO -R. box(client) -> phone(server) = box -> AP -> phone = the AP's
# beamformed DOWNLINK (what the forged BFI steers). -R would measure the phone's
# uplink, which this attack can't touch.
def run_iperf3_intervals(victim_ip: str, port: int, seconds: float,
                         bitrate: float | None = None) -> list:
    """One iperf3 downlink run (box->phone); returns per-second Mbps.

    bitrate (Mbps) caps the offered load with iperf3 -b so the burst does NOT
    saturate the channel (realistic sub-saturation normal usage); None = flat out.
    """
    cmd = [
        "iperf3", "-c", str(victim_ip), "-p", str(port),
        "-t", str(seconds), "-i", "1", "-J",
    ]
    if bitrate:
        cmd += ["-b", f"{bitrate}M"]
    hint = f"is `iperf3 -s` running on the phone at {victim_ip}:{port}?"
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=seconds + 10,
        )
    except FileNotFoundError:
        print(f"iperf3 binary not found on this host. {hint}", file=sys.stderr)
        return []
    except subprocess.TimeoutExpired:
        print(f"iperf3 timed out after {seconds + 10:g}s. {hint}", file=sys.stderr)
        return []
    if proc.returncode != 0 or not proc.stdout.strip():
        err = (proc.stderr or "").strip().splitlines()
        tail = err[-1] if err else f"exit {proc.returncode}"
        print(f"iperf3 failed: {tail}. {hint}", file=sys.stderr)
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        print(f"iperf3 returned non-JSON output ({e}). {hint}", file=sys.stderr)
        return []
    return parse_iperf3_json(data)


def measure_phase(ont, iface: str, victim_ip: str, port: int,
                  seconds: float, rssi_interval: float,
                  burst: float, gap: float, bitrate: float | None = None) -> dict:
    """Run one phase: BURSTY downlink load+metric with concurrent RSSI sampling.

    The phase repeats {idle gap -> short downlink burst} for `seconds`. The idle
    gap lets the AP mark the steering matrix stale so it RE-SOUNDS at the start
    of each burst (where the forged BFI gets ingested); the burst measures the
    resulting downlink throughput. The first (slow-start) second of each burst
    is dropped so the ramp doesn't deflate the samples.

    A daemon thread samples rssi_primary every rssi_interval via
    `iwpriv <iface> stat` (skipping rssi==0 parse-misses) throughout.
    Returns {"tput": [mbps...], "rssi": [primary...]}.
    """
    stop = threading.Event()
    rssi = []
    lock = threading.Lock()

    def sample_rssi():
        while not stop.is_set():
            try:
                st = parse_iwpriv_stat(ont.run(f"iwpriv {iface} stat"))
                if st.get("rssi0") is not None:
                    r = rssi_primary(st)
                    if r != 0:
                        with lock:
                            rssi.append(r)
            except Exception as e:
                print(f"  [rssi skip] {e}", file=sys.stderr)
            stop.wait(rssi_interval)

    sampler = threading.Thread(target=sample_rssi, daemon=True)
    sampler.start()
    tput = []
    try:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            time.sleep(gap)  # idle gap -> AP re-sounds at next burst
            if time.monotonic() >= deadline:
                break
            ivals = run_iperf3_intervals(victim_ip, port, burst, bitrate)
            # drop the slow-start second of each burst; keep the steady seconds
            tput.extend(ivals[1:] if len(ivals) > 1 else ivals)
    finally:
        stop.set()
        sampler.join(timeout=rssi_interval + 2)
    with lock:
        return {"tput": tput, "rssi": list(rssi)}


def log_phase(writer, cycle: int, phase: str, attack_on: bool,
              tput: list, rssi: list):
    """One CSV row per iperf3 second: tput + the running rssi median so far."""
    for i, mbps in enumerate(tput):
        seen = rssi[:i + 1]
        writer.writerow({
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "cycle": cycle,
            "phase": phase,
            "attack_on": int(attack_on),
            "tput_mbps": f"{mbps:.3f}",
            "rssi_primary_median": f"{statistics.median(seen):g}" if seen else "",
        })


def print_table(rows):
    hdr = (
        f"{'cycle':>5} | {'phase':<6} | {'median_tput_mbps':>16} | "
        f"{'median_rssi':>11} | {'n':>4} | {'inject':>6}"
    )
    print(hdr)
    print("-" * len(hdr))
    for cycle, phase, st, inj in rows:
        mt = "None" if st["median_tput"] is None else f"{st['median_tput']:g}"
        mr = "None" if st["median_rssi"] is None else f"{st['median_rssi']:g}"
        inj_s = "-" if inj is None else str(inj)
        print(
            f"{cycle:>5} | {phase:<6} | {mt:>16} | {mr:>11} | "
            f"{st['n_tput']:>4} | {inj_s:>6}"
        )


# ---------------------------------------------------------------------- main

def main(argv=None):
    p = argparse.ArgumentParser(
        description="Confound-aware A/B/A throughput measurement (normal-usage load)",
    )
    p.add_argument("--host", default="192.168.31.1")
    p.add_argument("--user", default="root")
    p.add_argument("--password", default="REDACTED")
    p.add_argument("--iface", default="wl0")
    p.add_argument("--ap", default="5c:02:14:b0:34:13")
    p.add_argument("--victim", default="fe:40:39:4d:6d:da")
    p.add_argument("--mon", default="mon0")
    p.add_argument("--victim-ip", default="192.168.31.158",
                   help="iperf3 server on the phone (downlink source is the AP)")
    p.add_argument("--port", type=int, default=5201)
    p.add_argument("--off", type=float, default=15, metavar="sec")
    p.add_argument("--on", type=float, default=15, metavar="sec")
    p.add_argument("--cycles", type=int, default=1)
    p.add_argument("--drift-tol", type=float, default=3.0, metavar="dB",
                   help="median RSSI drift across OFF phases (or ON-vs-OFF gap) above this = CONFOUNDED")
    p.add_argument("--rssi-interval", type=float, default=1.5, metavar="sec")
    p.add_argument("--burst", type=float, default=3.0, metavar="sec",
                   help="length of each downlink burst")
    p.add_argument("--gap", type=float, default=0.6, metavar="sec",
                   help="idle gap before each burst (forces AP re-sounding)")
    p.add_argument("--bitrate", type=float, default=None, metavar="Mbps",
                   help="cap each burst's offered load (iperf3 -b) so it does NOT "
                        "saturate the channel; omit = flat out (full channel)")
    p.add_argument("--out", default=None, metavar="csvpath")
    args = p.parse_args(argv)

    out_path = Path(args.out) if args.out else (
        Path("results/sessions")
        / f"tput_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.csv"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # -- pre-flight a: telnet
    try:
        ont_cm = GN630V(args.host, args.user, args.password)
        ont = ont_cm.__enter__()
    except Exception as e:
        abort(f"cannot reach AP ({args.host}): {e}")

    try:
        # -- pre-flight b: mon hearing
        try:
            delta = check_mon_hearing(args.mon)
        except Exception as e:
            abort(f"cannot read rx_packets for {args.mon}: {e}")
        if delta == 0:
            abort(
                f"{args.mon} is RX-DEAF — click Recover Alfa in the GUI, then re-run."
            )
        print(f"[preflight] {args.mon} hearing OK ({delta} rx_packets in 2s)")

        # -- pre-flight c: iperf3 reachability (2s probe = tiny real run)
        probe = run_iperf3_intervals(args.victim_ip, args.port, 2, args.bitrate)
        if not probe:
            abort(
                f"no iperf3 throughput from {args.victim_ip}:{args.port} — "
                f"start `iperf3 -s` on the phone ({args.victim_ip}:{args.port}), "
                "confirm reachable, re-run."
            )
        print(f"[preflight] iperf3 OK ({statistics.median(probe):g} Mbps probe)")

        with out_path.open("w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
            writer.writeheader()

            table_rows = []
            all_off1, all_on, all_off2 = {"tput": [], "rssi": []}, {"tput": [], "rssi": []}, {"tput": [], "rssi": []}
            total_inject = 0

            for cycle in range(1, args.cycles + 1):
                print(f"[cycle {cycle}] OFF-1 ({args.off:g}s)")
                ensure_attack_dead()
                off1 = measure_phase(
                    ont, args.iface, args.victim_ip, args.port,
                    args.off, args.rssi_interval, args.burst, args.gap, args.bitrate,
                )
                log_phase(writer, cycle, "OFF-1", False, off1["tput"], off1["rssi"])

                # non-fatal deaf re-check: the hearing window (~1 min post-
                # Recover) may have lapsed during preflight+OFF-1. If deaf now,
                # this ON will inject nothing -> INCONCLUSIVE; warn so it isn't
                # misread as NO EFFECT.
                try:
                    if check_mon_hearing(args.mon) == 0:
                        print(
                            f"[cycle {cycle}] WARNING: {args.mon} RX-DEAF at ON — "
                            "attack can't hear BFI; expect INCONCLUSIVE. "
                            "Recover Alfa + shorten phases to fit the window.",
                            file=sys.stderr,
                        )
                except OSError:
                    pass

                print(f"[cycle {cycle}] ON ({args.on:g}s)")
                proc, lines, reader_t = spawn_attack(args.mon, args.ap, args.victim)
                on = measure_phase(
                    ont, args.iface, args.victim_ip, args.port,
                    args.on, args.rssi_interval, args.burst, args.gap, args.bitrate,
                )
                ensure_attack_dead(proc)
                reader_t.join(timeout=2)  # drain stdout before counting

                inject_count = count_injections(lines)
                print(f"[cycle {cycle}] successful injections: {inject_count}")
                log_phase(writer, cycle, "ON", True, on["tput"], on["rssi"])

                print(f"[cycle {cycle}] OFF-2 ({args.off:g}s)")
                off2 = measure_phase(
                    ont, args.iface, args.victim_ip, args.port,
                    args.off, args.rssi_interval, args.burst, args.gap, args.bitrate,
                )
                log_phase(writer, cycle, "OFF-2", False, off2["tput"], off2["rssi"])

                s1, s_on, s2 = (
                    phase_stats_tput(off1),
                    phase_stats_tput(on),
                    phase_stats_tput(off2),
                )
                table_rows.append((cycle, "OFF-1", s1, None))
                table_rows.append((cycle, "ON", s_on, inject_count))
                table_rows.append((cycle, "OFF-2", s2, None))

                label, detail = verdict_tput(off1, on, off2, inject_count, args.drift_tol)
                print(f"[cycle {cycle}] {label} — {detail}")

                for dst, src in ((all_off1, off1), (all_on, on), (all_off2, off2)):
                    dst["tput"].extend(src["tput"])
                    dst["rssi"].extend(src["rssi"])
                total_inject += inject_count

        print()
        print_table(table_rows)
        print()
        label, detail = verdict_tput(
            all_off1, all_on, all_off2, total_inject, args.drift_tol,
        )
        print(f"OVERALL: {label} — {detail}")
        print(f"CSV: {out_path}")
        return 0
    finally:
        ensure_attack_dead()
        try:
            ont_cm.__exit__(None, None, None)
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
