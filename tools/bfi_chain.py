#!/usr/bin/env python3
"""Chain the three Beam-Warden steps so the operator skips hand-filling fields:

    capture (tshark -> pcap)  ->  decode (bfi_features -> CSV)  ->  train (optional)

Baseline runs pass --train; under-attack runs omit it. Never trains on an
empty capture. `--dry-run` prints the commands and exits (no hardware needed).
"""
import argparse
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "tools"
SESS = ROOT / "results" / "sessions"


def main() -> int:
    ap = argparse.ArgumentParser(description="Beam-Warden capture->decode->train chain")
    ap.add_argument("--iface", default="mon0")
    # ponytail: the Alfa mt7921u wedges at 80MHz after ~1min, so keep --dur <= ~45s;
    # longer gives a truncated pcap (capture dies silently mid-run).
    ap.add_argument("--dur", type=int, default=30, help="capture seconds (<=~45 at 80MHz)")
    ap.add_argument("--run", default=None, help="run-id (default: timestamp)")
    ap.add_argument("--train", action="store_true", help="retrain detector on the captured CSV")
    ap.add_argument("--dry-run", action="store_true", help="print commands and exit")
    a = ap.parse_args()

    run = a.run or time.strftime("%Y%m%d_%H%M%S")
    pcap = SESS / f"{run}_air.pcap"
    csv = SESS / f"{run}.csv"
    model = ROOT / "models" / "detector.joblib"

    capture = ["tshark", "-i", a.iface, "-p", "-a", f"duration:{a.dur}", "-w", str(pcap)]
    decode = ["python", str(TOOLS / "bfi_features.py"), "--pcap", str(pcap), "--out", str(csv)]
    train = ["python", str(TOOLS / "train_detector.py"), "--csv", str(csv), "--out", str(model)]

    if a.dry_run:
        print("CAPTURE:", " ".join(capture))
        print("DECODE: ", " ".join(decode))
        print("TRAIN:  ", " ".join(train), "" if a.train else "(skipped: no --train)")
        return 0

    SESS.mkdir(parents=True, exist_ok=True)

    print(f"[1/3] CAPTURE {a.dur}s on {a.iface} -> {pcap.name}")
    if subprocess.run(capture, check=False).returncode != 0:
        print("  capture FAILED", file=sys.stderr)
        return 1
    print("  ok")

    print(f"[2/3] DECODE -> {csv.name}")
    if subprocess.run(decode, check=False).returncode != 0:
        print("  decode FAILED", file=sys.stderr)
        return 1
    rows = 0
    if csv.exists():
        rows = max(0, sum(1 for _ in csv.open()) - 1)  # minus header
    print(f"  ok ({rows} BFI rows)")

    if not a.train:
        print("[3/3] TRAIN skipped (no --train)")
        return 0
    if rows < 1:
        print("[3/3] TRAIN SKIPPED: empty capture (0 BFI rows) — never train on nothing")
        return 0
    print(f"[3/3] TRAIN on {csv.name} -> {model.name}")
    if subprocess.run(train, check=False).returncode != 0:
        print("  train FAILED", file=sys.stderr)
        return 1
    print("  ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
