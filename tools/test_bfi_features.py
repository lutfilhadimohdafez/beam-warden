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
import threading
from unittest.mock import MagicMock, patch

import numpy as np

# Ensure tools/ is importable
sys.path.insert(0, os.path.dirname(__file__))

from bfi_features import (
    compute_NANG,
    decode_angles,
    extract_features,
    frame_to_features,
    get_bitwidths,
    stream_features,
    _meta_rows,
    _all_frame_bytes,
    _mimo_and_report,
    FEATURE_COLUMNS,
)

PCAP = os.path.join(os.path.dirname(__file__), "..", "data", "bfi_he_capture.pcap")


def test_stream_features_burst_continuity() -> None:
    """stream_features: two bursts, frame_id climbs across boundary."""
    burst_a = [("1", "0x0000000019", 10), ("2", "0x0000000019", 10)]
    burst_b = [("3", "0x0000000019", 10), ("4", "0x0000000019", 10), ("5", "0x0000000019", 10)]

    # mc=0x19: nr=4 (bits[3:5]=3), nc=2 (bits[0:2]=1), codebook=0, feedback=0
    # report needs ≥30 bits for Nst≥1 with NANG=10, b_phi=4, b_psi=2
    _mc = bytes([0x19, 0x00, 0x00, 0x00, 0x00])
    _rpt = b"\xff" * 4
    _fake_frame = _mc + _rpt + b"\x00" * 4

    call_count = 0

    def mock_meta_rows(_pcap):
        nonlocal call_count
        call_count += 1
        return burst_a if call_count <= 2 else burst_b

    def mock_all_frame_bytes(_pcap, frame_numbers=None):
        return {fn: _fake_frame for fn in (frame_numbers or [])}

    mock_proc = MagicMock()
    mock_proc.poll.return_value = 0
    mock_proc.returncode = 0

    stop = threading.Event()

    with patch("bfi_features.subprocess") as mock_sub, \
         patch("bfi_features._meta_rows", side_effect=mock_meta_rows), \
         patch("bfi_features._all_frame_bytes", side_effect=mock_all_frame_bytes):
        mock_sub.Popen.return_value = mock_proc
        mock_sub.PIPE = -1

        feats = []
        for feat in stream_features("lo", stop_event=stop):
            feats.append(feat)
            if len(feats) >= 5:
                stop.set()

    assert len(feats) >= 5, f"expected >=5 feats, got {len(feats)}"
    assert [f["frame"] for f in feats[:5]] == [1, 2, 3, 4, 5], (
        f"first5 frame_ids not contiguous: {[f['frame'] for f in feats[:5]]}"
    )
    print(f"[PASS] stream_features: {len(feats)} feats across 2 bursts, frame_ids 1..5 contiguous")


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

    # --- frame_to_features consistency check ---
    features_via_helper = []
    ws: dict = {}
    for fn, mc_hex, rl in rows:
        info = _mimo_and_report(pcap, fn, mc_hex, rl, frame_bytes_cache=fb_cache)
        feat = frame_to_features(
            info["report"], int(info["nr"]), int(info["nc"]),
            int(info["codebook"]), int(info["feedback_type"]),
            ws, frame_id=int(fn), window=10,
        )
        if feat is not None:
            features_via_helper.append(feat)
    assert len(features_via_helper) == decoded_count, (
        f"frame_to_features yielded {len(features_via_helper)}, expected {decoded_count}"
    )
    print(f"[PASS] frame_to_features produced {len(features_via_helper)} dicts")

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

    test_stream_features_burst_continuity()

    print("\n=== ALL CHECKS PASSED ===")


if __name__ == "__main__":
    main()
