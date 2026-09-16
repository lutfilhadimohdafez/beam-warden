#!/usr/bin/env python3
"""Self-check for bfi_features.py.

Runs on data/bfi_he_capture.pcap and asserts structural invariants.
No pytest fixtures — plain assert statements.
"""

from __future__ import annotations

import csv
import os
import sys
import tempfile

import numpy as np

# Ensure tools/ is importable
sys.path.insert(0, os.path.dirname(__file__))

from bfi_features import (
    compute_NANG,
    decode_angles,
    extract_features,
    get_bitwidths,
    _meta_rows,
    _all_frame_bytes,
    _mimo_and_report,
    FEATURE_COLUMNS,
)

PCAP = os.path.join(os.path.dirname(__file__), "..", "data", "bfi_he_capture.pcap")


def main() -> None:
    pcap = os.path.abspath(PCAP)
    assert os.path.isfile(pcap), f"pcap not found: {pcap}"

    # --- Structural decode checks ---
    rows = _meta_rows(pcap)
    assert len(rows) > 100, f"expected >100 HE frames, got {len(rows)}"

    decoded_count = 0
    all_angles_list = []

    fb_cache = _all_frame_bytes(pcap)

    for fn, mc_hex, rl in rows:
        info = _mimo_and_report(pcap, fn, mc_hex, rl, frame_bytes_cache=fb_cache)
        Nr, Nc = int(info["nr"]), int(info["nc"])
        report = info["report"]
        assert isinstance(report, bytes)
        if not report:
            continue

        b_phi, b_psi = get_bitwidths(int(info["feedback_type"]), int(info["codebook"]))
        NANG = compute_NANG(Nr, Nc)
        angles, is_phi_mask, Nst = decode_angles(report, Nr, Nc, b_phi, b_psi)

        assert Nst > 0, f"frame {fn}: Nst=0"
        assert angles.shape == (NANG, Nst), (
            f"frame {fn}: shape {angles.shape} != ({NANG}, {Nst})"
        )
        assert np.all(angles > 0), (
            f"frame {fn}: angle values not all positive"
        )

        all_angles_list.append(angles)
        decoded_count += 1

    assert decoded_count > 100, f"decoded {decoded_count} frames, expected >100"
    print(f"[PASS] decoded {decoded_count} frames, all shapes valid, all angles > 0")

    # --- CSV output checks ---
    features = extract_features(pcap, window=10)
    assert len(features) == decoded_count, (
        f"CSV rows {len(features)} != decoded {decoded_count}"
    )

    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        # Write CSV and read it back
        import bfi_features as mod
        # Use the same CLI logic manually
        import subprocess
        result = subprocess.run(
            [sys.executable, mod.__file__, "--pcap", pcap, "--out", tmp_path, "--window", "10"],
            capture_output=True, text=True,
        )
        assert result.returncode == 0, f"CLI failed: {result.stderr}"
        print(f"[PASS] CLI output: {result.stdout.strip()}")

        with open(tmp_path, newline="") as f:
            reader = csv.DictReader(f)
            csv_rows = list(reader)

        assert len(csv_rows) == decoded_count, (
            f"CSV has {len(csv_rows)} rows, expected {decoded_count}"
        )

        # Check all feature columns are present
        with open(tmp_path, newline="") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames or []
        for col in FEATURE_COLUMNS:
            assert col in fieldnames, f"missing column: {col}"
        print(f"[PASS] CSV has {len(csv_rows)} rows, all {len(FEATURE_COLUMNS)} columns present")

    finally:
        os.unlink(tmp_path)

    print("\n=== ALL CHECKS PASSED ===")


if __name__ == "__main__":
    main()
