#!/usr/bin/env python3
"""
BeamCraft BFI-forgery attack harness.

Measures the EFFECT of the attack on a victim's Wi-Fi throughput by running
two iperf3 sessions against a victim device running `iperf3 -s`:

  1. Baseline measurement (no attack).
  2. User starts the attack (e.g. main_su on mon0), then presses Enter.
  3. Under-attack measurement.
  4. Reports the throughput drop and whether it meets the >=51% success criterion.

The actual attack is NOT launched by this script — the user starts it manually
between the two measurements.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

IPERF3 = "/usr/bin/iperf3"


def run_iperf3(ip, port, duration, reverse, timeout):
    """Run a single iperf3 measurement and return throughput in Mbps."""
    cmd = [IPERF3, "-c", ip, "-p", str(port), "-t", str(duration), "-J"]
    if reverse:
        cmd.append("-R")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        print(f"ERROR: iperf3 timed out after {timeout}s.", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(f"ERROR: iperf3 not found at {IPERF3}.", file=sys.stderr)
        sys.exit(1)

    if proc.returncode != 0:
        print("ERROR: iperf3 exited with code {}.".format(proc.returncode), file=sys.stderr)
        if proc.stderr.strip():
            print("stderr:\n" + proc.stderr.strip(), file=sys.stderr)
        print(
            f"\nIs `iperf3 -s` running on the victim, and is {ip} reachable?",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print("ERROR: iperf3 returned non-JSON output.", file=sys.stderr)
        if proc.stdout.strip():
            print("stdout (first 500 chars):\n" + proc.stdout[:500], file=sys.stderr)
        if proc.stderr.strip():
            print("stderr:\n" + proc.stderr.strip(), file=sys.stderr)
        print(
            f"\nIs `iperf3 -s` running on the victim, and is {ip} reachable?",
            file=sys.stderr,
        )
        sys.exit(1)

    # Extract bits_per_second from end.sum_received (preferred) or end.sum_sent
    try:
        end = data["end"]
        streams = end.get("sum_received") or end.get("sum_sent")
        bps = streams["bits_per_second"]
    except (KeyError, TypeError):
        print("ERROR: could not parse throughput from iperf3 JSON.", file=sys.stderr)
        print("JSON keys present: " + str(list(data.keys())), file=sys.stderr)
        print(
            f"\nIs `iperf3 -s` running on the victim, and is {ip} reachable?",
            file=sys.stderr,
        )
        sys.exit(1)

    return bps / 1e6  # Mbps


def main():
    parser = argparse.ArgumentParser(
        description="BeamCraft attack harness — measure throughput drop under BFI-forgery attack."
    )
    parser.add_argument("--victim-ip", required=True, help="Victim's iperf3 server IP.")
    parser.add_argument("--port", type=int, default=5201, help="iperf3 port (default 5201).")
    parser.add_argument("--duration", type=int, default=10, help="Seconds per measurement (default 10).")
    parser.add_argument(
        "--reverse",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Measure downlink with iperf3 -R (default: True). Use --no-reverse to disable.",
    )
    parser.add_argument("--out", default=None, help="JSON output path (default results/attack_run_<ts>.json).")
    parser.add_argument("--label", default="", help="Optional note to embed in the result.")

    args = parser.parse_args()

    timeout = args.duration + 15

    # --- Baseline ---
    print(f"[*] Running BASELINE iperf3 against {args.victim_ip}:{args.port} for {args.duration}s"
          f" (reverse={args.reverse}) ...")
    baseline_mbps = run_iperf3(args.victim_ip, args.port, args.duration, args.reverse, timeout)
    baseline_ts = datetime.now(timezone.utc).isoformat()
    print(f"[+] Baseline throughput: {baseline_mbps:.2f} Mbps\n")

    # --- Wait for user to start attack ---
    input("[!] Start the attack now (run main_su on mon0), then press Enter to measure under attack... ")
    print()

    # --- Under attack ---
    print(f"[*] Running ATTACK iperf3 against {args.victim_ip}:{args.port} for {args.duration}s"
          f" (reverse={args.reverse}) ...")
    attack_mbps = run_iperf3(args.victim_ip, args.port, args.duration, args.reverse, timeout)
    attack_ts = datetime.now(timezone.utc).isoformat()
    print(f"[+] Under-attack throughput: {attack_mbps:.2f} Mbps\n")

    # --- Results ---
    if baseline_mbps > 0:
        drop_pct = (baseline_mbps - attack_mbps) / baseline_mbps * 100
    else:
        drop_pct = 0.0

    success = drop_pct >= 51.0

    print("=" * 64)
    print(f"  Baseline  : {baseline_mbps:>8.2f} Mbps")
    print(f"  Under attack: {attack_mbps:>8.2f} Mbps")
    print(f"  Drop      : {drop_pct:>8.2f} %")
    print(f"  SUCCESS (>=51% drop): {'YES' if success else 'NO'}")
    print("=" * 64)

    # --- Save JSON ---
    result = {
        "victim_ip": args.victim_ip,
        "port": args.port,
        "duration": args.duration,
        "reverse": args.reverse,
        "label": args.label,
        "baseline_mbps": round(baseline_mbps, 4),
        "baseline_timestamp": baseline_ts,
        "attack_mbps": round(attack_mbps, 4),
        "attack_timestamp": attack_ts,
        "drop_pct": round(drop_pct, 4),
        "success_51pct": success,
        "cmdline": " ".join(sys.argv),
    }

    if args.out:
        out_path = args.out
    else:
        os.makedirs("results", exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = f"results/attack_run_{ts}.json"

    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)

    print(f"\n[*] Results saved to {out_path}")

    # Exit 0 if success criterion met, 1 otherwise
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
