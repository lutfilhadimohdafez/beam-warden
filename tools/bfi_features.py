#!/usr/bin/env python3
"""Decode HE Compressed Beamforming Reports (BFI) from a pcap and emit
per-frame CSI-style features as CSV.

Reads HE Action frames (category_code 30), extracts the Givens-rotation
angles (phi / psi), and computes statistical features suitable for an
anomaly-detection pipeline.

Requires: tshark.  stdlib + numpy only.
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from typing import Dict, Iterator, List, Tuple

import numpy as np


# ---------------------------------------------------------------------------
# Extraction helpers  (tshark-based, matches bfi_capture.py style)
# ---------------------------------------------------------------------------

def _meta_rows(pcap: str) -> List[Tuple[str, str, int]]:
    """Return list of (frame_number, mimo_ctrl_uint40_hex, report_len) for HE BFI frames."""
    out = subprocess.run(
        ["tshark", "-r", pcap, "-Y", "wlan.fixed.category_code==30",
         "-T", "fields",
         "-e", "frame.number",
         "-e", "wlan.he.action.he_mimo_control",
         "-e", "wlan.he.action.he_mimo_control.report_len"],
        capture_output=True, text=True,
    ).stdout.splitlines()
    rows: List[Tuple[str, str, int]] = []
    for line in out:
        parts = line.split("\t")
        if len(parts) >= 3 and parts[1]:
            rows.append((parts[0], parts[1], int(parts[2]) if parts[2] else 0))
    return rows


def _frame_bytes(pcap: str, fn: str) -> bytes:
    """Return raw bytes of a single frame (by frame number) from a pcap."""
    raw = subprocess.run(
        ["tshark", "-r", pcap, "-Y", f"frame.number=={fn}", "-x"],
        capture_output=True, text=True,
    ).stdout
    return _parse_hex_dump(raw)


def _all_frame_bytes(pcap: str, frame_numbers: List[str] | None = None) -> Dict[str, bytes]:
    """Single tshark call: return {frame_number: raw_bytes} for all HE BFI frames.

    One `tshark -x` pass emits per-frame hex dumps separated by blank lines, in
    capture order. We zip those blocks positionally with the frame numbers from
    the SAME cat-30 filter (identical order), avoiding fragile in-band parsing.
    """
    raw = subprocess.run(
        ["tshark", "-r", pcap, "-Y", "wlan.fixed.category_code==30", "-x"],
        capture_output=True, text=True,
    ).stdout
    blocks = [blk for blk in raw.split("\n\n") if blk.strip()]
    if frame_numbers is None:
        frame_numbers = [r[0] for r in _meta_rows(pcap)]
    frames: Dict[str, bytes] = {}
    for fn, blk in zip(frame_numbers, blocks):
        frames[fn] = _parse_hex_dump(blk)
    return frames


def _parse_hex_dump(text: str) -> bytes:
    """Parse tshark -x hex dump text into raw bytes."""
    out = bytearray()
    for line in text.splitlines():
        m = re.match(r'^([0-9a-fA-F]{4,})\s+((?:[0-9a-fA-F]{2} ?){1,16})', line)
        if m:
            for tok in m.group(2).split():
                out.append(int(tok, 16))
    return bytes(out)


def _mimo_and_report(
    pcap: str, fn: str, mc_hex: str, report_len: int,
    frame_bytes_cache: Dict[str, bytes] | None = None,
) -> Dict[str, object]:
    """Decode the HE MIMO Control field and extract the beamforming report."""
    val = int(mc_hex, 16)
    mc_bytes = bytes((val >> (8 * i)) & 0xFF for i in range(5))  # uint40 LE → 5 bytes
    nc = (val & 0x7) + 1
    nr = ((val >> 3) & 0x7) + 1
    codebook = (val >> 9) & 0x1
    feedback_type = (val >> 10) & 0x3
    if frame_bytes_cache is not None:
        fb = frame_bytes_cache.get(fn, b"")
    else:
        fb = _frame_bytes(pcap, fn)
    idx = fb.find(mc_bytes)
    # report follows the 5-byte MIMO control; drop trailing 4-byte FCS if present
    report = fb[idx + 5:] if idx >= 0 else b""
    if len(report) > 4:
        report = report[:-4]  # strip FCS
    return dict(nr=nr, nc=nc, codebook=codebook, feedback_type=feedback_type, report=report)


# ---------------------------------------------------------------------------
# Decode math  (ported from BeamCraft_AE/main_su.cpp)
# ---------------------------------------------------------------------------

def compute_NANG(Nr: int, Nc: int) -> int:
    """Total number of angles for a given antenna geometry."""
    nang = 0
    p = min(Nc, Nr - 1)
    for i in range(1, p + 1):
        nang += 2 * (Nr - i)
    return nang


def get_bitwidths(feedback_type: int, codebook: int) -> Tuple[int, int]:
    """Return (b_phi, b_psi) for the given feedback type and codebook."""
    if feedback_type == 0:  # SU
        if codebook == 0:
            return 4, 2
        return 6, 4
    if feedback_type == 1:  # MU
        if codebook == 0:
            return 7, 5
        return 9, 7
    return 4, 2  # fallback


def decode_angles(
    report: bytes, Nr: int, Nc: int, b_phi: int, b_psi: int,
) -> Tuple[np.ndarray, List[bool], int]:
    """Decode beamforming report into an (NANG, Nst) angle matrix.

    Bit-ordering (per C++ reference):
      - Per byte: MSB-first → reversed (LSB-first), concatenate.
      - Per angle slice: take b_phi/b_psi chars, reverse, interpret as integer.
      - phi value = (2*raw+1) / 2**b_phi
      - psi value = (2*raw+1) / 2**(b_psi+2)

    Returns (angles, is_phi, Nst).
    """
    NANG = compute_NANG(Nr, Nc)

    # Build bitstring: per byte, MSB-first then reversed → LSB-first
    bitstr = ""
    for byte in report:
        bitstr += f"{byte:08b}"[::-1]

    total_bits = len(bitstr)
    # NANG is even; per subcarrier #phi == #psi == NANG//2
    bits_per_sc = (NANG // 2) * (b_phi + b_psi)
    if bits_per_sc == 0:
        return np.zeros((NANG, 0), dtype=np.float64), [False] * NANG, 0
    Nst = total_bits // bits_per_sc

    angles = np.zeros((NANG, Nst), dtype=np.float64)
    is_phi: List[bool] = [False] * NANG

    pos = 0
    for kk in range(Nst):
        angcnt = 0
        for ii in range(Nr - 1, max(Nr - Nc, 1) - 1, -1):
            # phi angles
            for _jj in range(ii):
                raw = int(bitstr[pos:pos + b_phi][::-1], 2)
                angles[angcnt, kk] = (2 * raw + 1) / (2 ** b_phi)
                is_phi[angcnt] = True
                pos += b_phi
                angcnt += 1
            # psi angles
            for _jj in range(ii):
                raw = int(bitstr[pos:pos + b_psi][::-1], 2)
                angles[angcnt, kk] = (2 * raw + 1) / (2 ** (b_psi + 2))
                is_phi[angcnt] = False
                pos += b_psi
                angcnt += 1

    return angles, is_phi, Nst


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

FEATURE_COLUMNS = [
    "frame", "nr", "nc", "nst", "nang",
    "bfi_phi_mean", "bfi_psi_mean",
    "bfi_angle_var", "bfi_subcarrier_var",
    "bfi_phi_temporal_var", "bfi_psi_temporal_var",
]


def frame_to_features(
    report: bytes,
    nr: int,
    nc: int,
    codebook: int,
    feedback_type: int,
    window_state: Dict[str, List[float]],
    frame_id: int = 0,
    window: int = 10,
) -> Dict[str, float] | None:
    """Decode one beamforming report into a feature dict.

    *window_state* is mutated in-place (phi/psi rolling history) so the caller
    can maintain temporal-var state across calls.  Returns None if the report
    is empty or decodes to Nst==0.
    """
    if not report:
        return None

    b_phi, b_psi = get_bitwidths(feedback_type, codebook)
    angles, is_phi_mask, Nst = decode_angles(report, nr, nc, b_phi, b_psi)

    if Nst == 0:
        return None

    NANG = compute_NANG(nr, nc)
    phi_mask = np.array(is_phi_mask, dtype=bool)
    psi_mask = ~phi_mask

    phi_mean = float(np.mean(angles[phi_mask])) if np.any(phi_mask) else 0.0
    psi_mean = float(np.mean(angles[psi_mask])) if np.any(psi_mask) else 0.0

    ws_phi = window_state.setdefault("phi", [])
    ws_psi = window_state.setdefault("psi", [])
    ws_phi.append(phi_mean)
    ws_psi.append(psi_mean)

    if len(ws_phi) >= window:
        phi_temp_var = float(np.var(ws_phi[-window:]))
        psi_temp_var = float(np.var(ws_psi[-window:]))
    else:
        phi_temp_var = 0.0
        psi_temp_var = 0.0

    return {
        "frame": frame_id,
        "nr": nr,
        "nc": nc,
        "nst": Nst,
        "nang": NANG,
        "bfi_phi_mean": phi_mean,
        "bfi_psi_mean": psi_mean,
        "bfi_angle_var": float(np.var(angles)),
        "bfi_subcarrier_var": float(np.mean(np.var(angles, axis=1))),
        "bfi_phi_temporal_var": phi_temp_var,
        "bfi_psi_temporal_var": psi_temp_var,
    }


def extract_features(
    pcap: str, window: int = 10,
) -> List[Dict[str, float]]:
    """Decode all HE BFI frames in *pcap* and return per-frame feature rows."""
    rows = _meta_rows(pcap)
    if not rows:
        return []

    fb_cache = _all_frame_bytes(pcap, frame_numbers=[r[0] for r in rows])

    features: List[Dict[str, float]] = []
    window_state: Dict[str, List[float]] = {}

    for fn, mc_hex, rl in rows:
        info = _mimo_and_report(pcap, fn, mc_hex, rl, frame_bytes_cache=fb_cache)
        Nr = int(info["nr"])
        Nc = int(info["nc"])
        report = info["report"]
        assert isinstance(report, bytes)

        feat = frame_to_features(
            report, Nr, Nc,
            int(info["codebook"]), int(info["feedback_type"]),
            window_state, frame_id=int(fn), window=window,
        )
        if feat is not None:
            features.append(feat)

    return features


# ---------------------------------------------------------------------------
# Live streaming
# ---------------------------------------------------------------------------

def _live_meta_rows(pcap_path: str, seen: set) -> List[Tuple[str, str, int]]:
    """Return category-30 meta rows not yet in *seen*."""
    rows = _meta_rows(pcap_path)
    return [(fn, mc, rl) for fn, mc, rl in rows if fn not in seen]


def _live_frame_bytes(pcap_path: str, frame_numbers: List[str]) -> Dict[str, bytes]:
    """Read raw bytes for specific frames from a (possibly growing) pcap.

    ponytail: tshark -x on a live-written pcap may race; retry on failure.
    """
    for _attempt in range(3):
        try:
            return _all_frame_bytes(pcap_path, frame_numbers=frame_numbers)
        except Exception:
            time.sleep(0.05)
    return {}


def stream_features(
    iface: str,
    duration: int = 0,
    window: int = 10,
) -> Iterator[Dict[str, float]]:
    """Yield feature dicts from live BFI capture on *iface*.

    Uses a background tshark capture writing to a temp pcap, polled
    periodically for new category-30 frames.  Temporal-var window state
    is maintained across yielded frames.

    ponytail: capture-to-tmpfile-then-decode — true real-time raw-byte
    extraction from a live tshark pipe is not viable (tshark -x blocks).
    Latency ceiling: poll_interval (0.5s) + tshark write buffering.
    """
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp_path = tmp.name
    tmp.close()

    stop_event = threading.Event()
    err_holder: list[str] = []

    def _capture():
        cmd = [
            "tshark", "-i", iface,
            "-Y", "wlan.fixed.category_code==30",
            "-w", tmp_path,
        ]
        if duration > 0:
            cmd += ["-a", f"duration:{duration}"]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=(duration + 60) if duration > 0 else None)
            if proc.returncode != 0 and proc.stderr:
                err_holder.append(proc.stderr)
        except Exception as e:
            err_holder.append(str(e))
        finally:
            stop_event.set()

    cap_thread = threading.Thread(target=_capture, daemon=True)
    cap_thread.start()

    seen_frames: set = set()
    window_state: Dict[str, List[float]] = {}
    local_counter = 0
    poll_interval = 0.5
    deadline = time.time() + duration if duration > 0 else float("inf")

    try:
        while not stop_event.is_set() and time.time() < deadline:
            time.sleep(poll_interval)

            if not os.path.exists(tmp_path) or os.path.getsize(tmp_path) < 24:
                continue

            try:
                new_rows = _live_meta_rows(tmp_path, seen_frames)
            except Exception:
                continue

            if not new_rows:
                continue

            fns = [r[0] for r in new_rows]
            fb_cache = _live_frame_bytes(tmp_path, fns)
            if not fb_cache:
                continue

            for fn, mc_hex, rl in new_rows:
                seen_frames.add(fn)
                info = _mimo_and_report(
                    tmp_path, fn, mc_hex, rl, frame_bytes_cache=fb_cache,
                )
                local_counter += 1
                feat = frame_to_features(
                    info["report"],
                    int(info["nr"]), int(info["nc"]),
                    int(info["codebook"]), int(info["feedback_type"]),
                    window_state, frame_id=local_counter, window=window,
                )
                if feat is not None:
                    yield feat

    finally:
        stop_event.set()
        cap_thread.join(timeout=5)
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcap", help="Input pcap with HE BFI frames (offline mode)")
    parser.add_argument("--out", help="Output CSV path (offline mode)")
    parser.add_argument("--live", metavar="IFACE",
                        help="Live capture mode: monitor-mode interface (e.g. mon0)")
    parser.add_argument("--duration", type=int, default=0,
                        help="Live capture duration in seconds (0=unlimited)")
    parser.add_argument("--window", type=int, default=10,
                        help="Rolling window size for temporal variance")
    args = parser.parse_args()

    if args.live:
        import json as _json
        count = 0
        for feat in stream_features(args.live, duration=args.duration, window=args.window):
            print(_json.dumps(feat), flush=True)
            count += 1
        if count == 0:
            print("No HE BFI frames captured.", file=sys.stderr)
            sys.exit(1)

    elif args.pcap and args.out:
        features = extract_features(args.pcap, window=args.window)
        if not features:
            print("No HE BFI frames found.", file=sys.stderr)
            sys.exit(1)

        with open(args.out, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=FEATURE_COLUMNS)
            writer.writeheader()
            writer.writerows(features)

        nr = features[0]["nr"]
        nc = features[0]["nc"]
        nst = features[0]["nst"]
        nang = features[0]["nang"]
        mean_vals = {col: np.mean([r[col] for r in features]) for col in FEATURE_COLUMNS[5:]}
        summary_parts = "  ".join(f"{k}={v:.4f}" for k, v in mean_vals.items())
        print(
            f"{len(features)} frames decoded  Nr={nr} Nc={nc} Nst={nst} NANG={nang}  "
            f"{summary_parts}"
        )

    else:
        parser.error("Either --pcap + --out (offline) or --live <iface> (live) required")


if __name__ == "__main__":
    main()
