#!/usr/bin/env python3
"""Confound-aware A/B/A attack measurement (OFF -> ON -> OFF).

Samples victim downlink MCS + RSSI from the AP over telnet while toggling the
BeamCraft attack binary, and refuses to declare an effect when RSSI drifted.
Run under sudo. Pure logic (rssi_primary / phase_stats / verdict) is hardware
free; all I/O lives in thin helpers orchestrated by main().
"""

import argparse
import csv
import re
import signal
import socket
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from gn630v_telnet import GN630V
from gn630v_telemetry import parse_iwpriv_stat

CSV_FIELDS = [
    "timestamp", "cycle", "phase", "attack_on",
    "tx_mcs", "tx_nss", "tx_bw",
    "rssi0", "rssi1", "rssi2", "rssi3", "rssi_primary",
    "tx_per_pct", "rx_per_pct",
]

ATTACK_BIN = Path(__file__).resolve().parent.parent / "BeamCraft_AE" / "main_su"


# ---------------------------------------------------------------- pure logic

def rssi_primary(sample: dict) -> int:
    """Strongest (least-negative) receive chain = max(rssi0..3)."""
    return max(sample["rssi0"], sample["rssi1"], sample["rssi2"], sample["rssi3"])


def phase_stats(samples: list) -> dict:
    """Aggregate one phase's samples into medians + RSSI range.

    Skips samples whose tx_mcs is None for the MCS median, and whose
    rssi_primary is 0 for the RSSI stats — 0 dBm is physically impossible for a
    real station, so it's the parse-miss sentinel from a garbled telnet read.
    Counting it would blow the RSSI range (0 vs -66 = 66 dB) and spuriously
    flag a steady run CONFOUNDED. Returns keys: median_mcs, median_rssi,
    rssi_range, rssi_min, rssi_max, n.
    """
    mcs_vals = [s["tx_mcs"] for s in samples if s.get("tx_mcs") is not None]
    rssis = [r for s in samples if (r := rssi_primary(s)) != 0]
    if not rssis:
        return {
            "median_mcs": statistics.median(mcs_vals) if mcs_vals else None,
            "median_rssi": None,
            "rssi_range": 0,
            "rssi_min": None,
            "rssi_max": None,
            "n": len(samples),
        }
    return {
        "median_mcs": statistics.median(mcs_vals) if mcs_vals else None,
        "median_rssi": statistics.median(rssis),
        "rssi_range": max(rssis) - min(rssis),
        "rssi_min": min(rssis),
        "rssi_max": max(rssis),
        "n": len(samples),
    }


_SUMMARY_RE = re.compile(r"injected OK:\s*(\d+)")


def count_injections(lines: list) -> int:
    """Count SUCCESSFUL injections from main_su's stdout.

    A failed pcap_inject (TX not permitted) didn't land the attack, so only
    OK counts toward "the attack fired". Prefer main_su's authoritative
    SUMMARY ("injected OK: N", printed on clean SIGTERM exit); fall back to
    its throttled per-frame "INJECT=.. (ok)" lines when the process was
    SIGKILLed (deaf card) before the summary printed.
    """
    for line in lines:
        m = _SUMMARY_RE.search(line)
        if m:
            return int(m.group(1))
    return sum(1 for l in lines if "INJECT=" in l and "(ok)" in l)


def verdict(off1: dict, on: dict, off2: dict, inject_count: int, drift_tol: float):
    """Confound-aware A/B/A verdict. All confound/attack logic lives here.

    Returns (label, detail). label is one of CONFOUNDED / ATTACK CONFIRMED /
    NO EFFECT / INCONCLUSIVE.
    """
    confounded = "result INVALID, re-measure on a steadier signal."
    # Confound test on MEDIAN RSSI, NOT raw range. A real handheld always
    # jitters a few dB around a stable mean — that wobble is harmless and
    # averages out. What INVALIDATES an A/B/A is the signal MEAN drifting: if
    # the OFF baseline moved between OFF-1 and OFF-2, or ON sat at a different
    # level than the OFF baseline, the MCS gap isn't attributable to the attack.
    # Medians over a phase are robust to the jitter; this is the drift the
    # earlier "-55%" result was secretly riding on (RSSI slid -62 -> -73).
    r1, ron, r2 = off1.get("median_rssi"), on.get("median_rssi"), off2.get("median_rssi")
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
        off_base = statistics.median([r1, r2])
        level_gap = abs(ron - off_base)
        if level_gap > drift_tol:
            return (
                "CONFOUNDED",
                f"ON-phase RSSI ({ron:g} dB) sits {level_gap:g} dB off the OFF "
                f"baseline ({off_base:g} dB) — MCS gap not attributable; {confounded}",
            )

    m1, mo, m2 = off1.get("median_mcs"), on.get("median_mcs"), off2.get("median_mcs")
    if inject_count == 0:
        return (
            "INCONCLUSIVE",
            "INJECT=0 — attack never fired; cannot attribute any MCS change.",
        )
    if m1 is None or mo is None or m2 is None:
        return (
            "INCONCLUSIVE",
            "no valid MCS samples in one or more phases.",
        )

    drop1, drop2 = m1 - mo, m2 - mo
    if drop1 >= 1 and drop2 >= 1:
        drop = min(drop1, drop2)
        return (
            "ATTACK CONFIRMED",
            f"MCS dropped {drop:g} index on ON ({m1:g}->{mo:g}), recovered on "
            f"OFF ({m2:g}), INJECT={inject_count}; effect present on ON and gone "
            f"on OFF while RSSI steady.",
        )
    return (
        "NO EFFECT",
        f"MCS flat (OFF medians {m1:g}/{m2:g}, ON {mo:g}) despite "
        f"INJECT={inject_count}; no attributable drop at this MCS.",
    )


# ------------------------------------------------------------------ thin I/O

def abort(msg: str):
    print(f"ABORT: {msg}", file=sys.stderr)
    sys.exit(1)


def mon_rx_packets(mon: str) -> int:
    return int(
        Path(f"/sys/class/net/{mon}/statistics/rx_packets").read_text().strip()
    )


def check_mon_hearing(mon: str) -> int:
    a = mon_rx_packets(mon)
    time.sleep(2)
    return mon_rx_packets(mon) - a


def resolve_victim_ip(victim: str) -> str:
    """Victim flag is a MAC; UDP sounder needs an IP. Look it up in ARP."""
    if ":" not in victim:
        return victim
    mac = victim.lower()
    try:
        arp = Path("/proc/net/arp").read_text().splitlines()[1:]
    except OSError:
        arp = []
    for line in arp:
        parts = line.split()
        if len(parts) >= 4 and parts[3].lower() == mac:
            return parts[0]
    abort(f"cannot resolve victim IP for {victim} — ping the phone first, then re-run.")


def start_sounder(victim_ip: str, stop_event: threading.Event) -> threading.Thread:
    """UDP sounder: 4000 x 1400B datagrams, then 0.25s idle gap, loop.

    The idle gap is what forces the AP to re-sound the victim; steady
    saturation does NOT.
    """

    def run():
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = b"\x00" * 1400
        while not stop_event.is_set():
            for _ in range(4000):
                try:
                    sock.sendto(payload, (victim_ip, 9999))
                except OSError:
                    pass  # victim may ICMP-reject the closed port
            stop_event.wait(0.25)
        sock.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def spawn_attack(mon: str, ap: str, victim: str, alpha: float = 1.0):
    cmd = [
        str(ATTACK_BIN), "--iface", mon, "--ap", ap, "--victim", victim,
        "--alpha", str(alpha), "--type", "0xe0", "--offset", "33",
    ]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1,
    )
    lines = []

    def reader():
        for line in proc.stdout:
            lines.append(line.rstrip("\n"))

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    return proc, lines, t


def ensure_attack_dead(proc=None, grace: float = 1.5):
    """Stop main_su, preferring a clean exit so it prints its INJECT SUMMARY.

    When the card is HEARING (the only case where injection works), main_su is
    actively looping and checks app_stopped between frames, so SIGTERM exits it
    cleanly AND flushes "injected OK: N". Only a DEAF card blocks in
    pcap_next_ex and ignores TERM — hence the SIGKILL + pkill backstop. pkill
    -x by exact name is the proven reaper for the root-owned process.
    """
    if proc is not None and proc.poll() is None:
        try:
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=grace)  # clean exit flushes the SUMMARY
        except subprocess.TimeoutExpired:
            pass
        except OSError:
            pass
    if proc is not None and proc.poll() is None:
        try:
            proc.send_signal(signal.SIGKILL)
        except OSError:
            pass
    try:
        subprocess.run(
            ["pkill", "-KILL", "-x", "main_su"], check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except OSError:
        pass
    if proc is not None:
        try:
            proc.wait(timeout=5)
        except Exception:
            pass
    try:
        alive = subprocess.run(
            ["pgrep", "-x", "main_su"], check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).returncode == 0
    except OSError:
        alive = False
    if alive:
        print("  WARNING: main_su still running after SIGKILL", file=sys.stderr)
    return not alive


def run_phase(ont, iface: str, seconds: float, interval: float,
              cycle: int, phase: str, attack_on: bool, writer):
    """Sample tx_mcs + RSSI over telnet for `seconds`. Returns sample dicts."""
    # ponytail: single-victim `iwpriv stat` in place of per-station
    # `show stainfo` — fine while the X9c is the only associated station;
    # upgrade to show stainfo -> dmesg parse only if a 2nd station associates.
    samples = []
    deadline = time.monotonic() + seconds
    while True:
        try:
            text = ont.run(f"iwpriv {iface} stat")
            st = parse_iwpriv_stat(text)
            row = {
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "cycle": cycle,
                "phase": phase,
                "attack_on": int(attack_on),
                "tx_mcs": st.get("tx_mcs"),
                "tx_nss": st.get("tx_nss"),
                "tx_bw": st.get("tx_bw"),
                "rssi0": st.get("rssi0"),
                "rssi1": st.get("rssi1"),
                "rssi2": st.get("rssi2"),
                "rssi3": st.get("rssi3"),
                "rssi_primary": rssi_primary(st) if st.get("rssi0") is not None else None,
                "tx_per_pct": st.get("tx_per_pct"),
                "rx_per_pct": st.get("rx_per_pct"),
            }
            samples.append(row)
            writer.writerow(row)
        except Exception as e:
            print(f"  [sample skip] {e}", file=sys.stderr)
        if time.monotonic() >= deadline:
            break
        time.sleep(interval)
    return samples


def print_table(rows):
    hdr = (
        f"{'cycle':>5} | {'phase':<6} | {'median_mcs':>10} | {'median_rssi':>11} | "
        f"{'rssi_range':>10} | {'n':>4} | {'inject':>6}"
    )
    print(hdr)
    print("-" * len(hdr))
    for cycle, phase, st, inj in rows:
        mm = "None" if st["median_mcs"] is None else f"{st['median_mcs']:g}"
        mr = "None" if st["median_rssi"] is None else f"{st['median_rssi']:g}"
        inj_s = "-" if inj is None else str(inj)
        print(
            f"{cycle:>5} | {phase:<6} | {mm:>10} | {mr:>11} | "
            f"{st['rssi_range']:>10g} | {st['n']:>4} | {inj_s:>6}"
        )


# ---------------------------------------------------------------------- main

def main(argv=None):
    p = argparse.ArgumentParser(description="Confound-aware A/B/A attack measurement")
    p.add_argument("--host", default="192.168.31.1")
    p.add_argument("--user", default="root")
    p.add_argument("--password", default="REDACTED")
    p.add_argument("--iface", default="wl0")
    p.add_argument("--ap", default="5c:02:14:b0:34:13")
    p.add_argument("--victim", default="fe:40:39:4d:6d:da")
    p.add_argument("--mon", default="mon0")
    p.add_argument("--off", type=float, default=20, metavar="sec")
    p.add_argument("--on", type=float, default=20, metavar="sec")
    p.add_argument("--cycles", type=int, default=1)
    p.add_argument("--preflight", type=float, default=30, metavar="sec")
    p.add_argument("--rssi-tol", type=float, default=3.0, metavar="dB",
                   help="preflight jitter above this just prints a note (advisory, never aborts)")
    p.add_argument("--drift-tol", type=float, default=3.0, metavar="dB",
                   help="median RSSI drift across OFF phases (or ON-vs-OFF gap) above this = CONFOUNDED")
    p.add_argument("--sample-interval", type=float, default=1.5, metavar="sec")
    p.add_argument("--out", default=None, metavar="csvpath")
    args = p.parse_args(argv)

    out_path = Path(args.out) if args.out else (
        Path("results/sessions")
        / f"aba_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.csv"
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # -- pre-flight a: telnet
    try:
        ont_cm = GN630V(args.host, args.user, args.password)
        ont = ont_cm.__enter__()
    except Exception as e:
        abort(f"cannot reach AP ({args.host}): {e}")

    stop_event = threading.Event()
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

        # -- sounder: runs the WHOLE time
        victim_ip = resolve_victim_ip(args.victim)
        start_sounder(victim_ip, stop_event)
        print(f"[sounder] UDP -> {victim_ip}:9999")

        with out_path.open("w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
            writer.writeheader()

            # -- RSSI preflight: ADVISORY, not a gate. A handheld always
            # jitters a few dB; demanding a still signal is unphysical. The real
            # confound (baseline drift) is caught per-cycle in verdict() by
            # comparing median RSSI across the bracketing OFF phases. Here we
            # just report the baseline and bail only on a PATHOLOGICAL swing
            # (phone being moved / losing association).
            pre = run_phase(
                ont, args.iface, args.preflight, args.sample_interval,
                0, "PRE", False, writer,
            )
            rssis = [r for s in pre if (r := rssi_primary(s)) != 0]
            if not rssis:
                abort("preflight read no valid RSSI — is the victim associated? ping it, then re-run.")
            med = statistics.median(rssis)
            spread = max(rssis) - min(rssis)
            print(f"[preflight] RSSI median {med:g} dB, jitter Δ={spread:g} dB over {args.preflight:g}s")
            if spread > args.rssi_tol:
                print(
                    f"[preflight] note: Δ={spread:g} dB jitter is normal for a handheld — "
                    "proceeding. The A/B/A controls drift at the median level per cycle.",
                    file=sys.stderr,
                )
            if spread > 15:
                abort(
                    f"RSSI swinging {spread:g} dB — the phone is moving or dropping "
                    "association, not just jittering. Clamp it, confirm it's connected, re-run."
                )

            table_rows = []
            all_off1, all_on, all_off2 = [], [], []
            total_inject = 0

            for cycle in range(1, args.cycles + 1):
                print(f"[cycle {cycle}] OFF-1 ({args.off:g}s)")
                ensure_attack_dead()
                off1 = run_phase(
                    ont, args.iface, args.off, args.sample_interval,
                    cycle, "OFF-1", False, writer,
                )

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
                on = run_phase(
                    ont, args.iface, args.on, args.sample_interval,
                    cycle, "ON", True, writer,
                )
                ensure_attack_dead(proc)
                reader_t.join(timeout=2)  # drain stdout before counting

                inject_count = count_injections(lines)
                print(f"[cycle {cycle}] successful injections: {inject_count}")

                print(f"[cycle {cycle}] OFF-2 ({args.off:g}s)")
                off2 = run_phase(
                    ont, args.iface, args.off, args.sample_interval,
                    cycle, "OFF-2", False, writer,
                )

                s1, s_on, s2 = phase_stats(off1), phase_stats(on), phase_stats(off2)
                table_rows.append((cycle, "OFF-1", s1, None))
                table_rows.append((cycle, "ON", s_on, inject_count))
                table_rows.append((cycle, "OFF-2", s2, None))

                label, detail = verdict(s1, s_on, s2, inject_count, args.drift_tol)
                print(f"[cycle {cycle}] {label} — {detail}")

                all_off1.extend(off1)
                all_on.extend(on)
                all_off2.extend(off2)
                total_inject += inject_count

        print()
        print_table(table_rows)
        print()
        g1, gon, g2 = (
            phase_stats(all_off1), phase_stats(all_on), phase_stats(all_off2)
        )
        label, detail = verdict(g1, gon, g2, total_inject, args.drift_tol)
        print(f"OVERALL: {label} — {detail}")
        print(f"CSV: {out_path}")
        return 0
    finally:
        stop_event.set()
        ensure_attack_dead()
        try:
            ont_cm.__exit__(None, None, None)
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
