#!/usr/bin/env python3
"""bfi_capture.py — Gate 2 BFI format analysis tool.

Captures and inspects 802.11 beamforming feedback (VHT/HE Compressed
Beamforming Report) ACTION frames exchanged between a Wi-Fi client and
a Skyworth GN630v AP (MediaTek MT7916).  Answers: what are the real
Nc, Nr, channel width, and report byte-length, vs the reference
attack code's assumption (Nr=4, Nc=2, Nst=52).

Requires: tshark (sudo/root for live capture).  stdlib + subprocess only.

Usage:
    sudo python3 bfi_capture.py live [--iface mon0] [--duration 20]
                                     [--count 0] [--write out.pcap]
    python3 bfi_capture.py pcap <file.pcap>
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from typing import List, Optional

TSHARK = "/usr/bin/tshark"

# Reference assumption from the existing attack code
REF = {
    "Nr": 4,
    "Nc": 2,
    "Nst": 52,
    "action_type_byte": 0xE0,
}

# Channel-width code → human label
CHAN_WIDTH = {0: "20 MHz", 1: "40 MHz", 2: "80 MHz", 3: "160 MHz / 80+80"}

# Fields we want tshark to emit (one per -e flag)
FIELDS = [
    "frame.time_relative",
    "frame.len",
    "wlan.sa",
    "wlan.da",
    "wlan.ta",
    "wlan.ra",
    "wlan.fixed.category_code",
    "wlan.vht.action",
    "wlan.vht.mimo_control.ncindex",
    "wlan.vht.mimo_control.nrindex",
    "wlan.vht.mimo_control.chanwidth",
    "wlan.vht.mimo_control.grouping",
    "wlan.vht.mimo_control.codebookinfo",
    "wlan.vht.mimo_control.feedbacktype",
    "wlan.vht.mimo_control.remaining_feedback_segs",
    "wlan.vht.compressed_beamforming_report",
    # HE equivalents (may be absent in older tshark / different frames)
    "wlan.he.mimo_control.ncindex",
    "wlan.he.mimo_control.nrindex",
    "wlan.he.mimo_control.chanwidth",
    "wlan.he.mimo_control.grouping",
    "wlan.he.mimo_control.codebookinfo",
    "wlan.he.mimo_control.feedbacktype",
    "wlan.he.mimo_control.remaining_feedback_segs",
    "wlan.he.compressed_beamforming_report",
]

# Cache for tshark -G fields output (computed once per run)
_known_tshark_fields: set[str] | None = None


def _probe_tshark_fields() -> set[str]:
    """Return the set of field names this tshark version knows (cached)."""
    global _known_tshark_fields
    if _known_tshark_fields is not None:
        return _known_tshark_fields
    try:
        proc = subprocess.run(
            [TSHARK, "-G", "fields"],
            capture_output=True, text=True, timeout=30,
        )
        known: set[str] = set()
        for line in proc.stdout.splitlines():
            # Format: TYPE\tDESCRIPTION\tFIELD_NAME\t...
            parts = line.split("\t")
            if len(parts) >= 3:
                known.add(parts[2].strip())
        _known_tshark_fields = known
    except Exception:
        _known_tshark_fields = set()
    return _known_tshark_fields


def _get_valid_fields() -> list[str]:
    """Return only fields from FIELDS that this tshark knows."""
    known = _probe_tshark_fields()
    if not known:
        # Fallback: just use core fields (always present)
        return [f for f in FIELDS if not f.startswith("wlan.he.")]
    return [f for f in FIELDS if f in known]


def _get_active_fields() -> list[str]:
    """Return the list of fields to request, filtering out unsupported ones."""
    valid = _get_valid_fields()
    skipped = set(FIELDS) - set(valid)
    if skipped:
        print(f"[*] Skipping fields not supported by this tshark: "
              f"{', '.join(sorted(skipped))}")
    return valid


# Display filter sub-expressions; we probe each for validity and drop
# the ones this tshark doesn't know.
_DF_PARTS = [
    "wlan.fc.type_subtype == 0x0d",
    "wlan.fc.type_subtype == 0x0e",
    "wlan.fixed.category_code == 21",
    "wlan.fixed.category_code == 30",
    "wlan.vht.action == 0",
    "wlan.he.action",
]


def _get_display_filter() -> str:
    """Build a display filter using only fields this tshark supports."""
    known = _probe_tshark_fields()

    def _df_field(part: str) -> str:
        return part.split()[0]  # "wlan.vht.action == 0" → "wlan.vht.action"

    # Always include the type_subtype guard; optionally add the rest
    valid_parts = ["wlan.fc.type_subtype == 0x0d",
                   "wlan.fc.type_subtype == 0x0e"]
    for p in _DF_PARTS[2:]:
        fname = _df_field(p)
        if not known or fname in known:
            valid_parts.append(p)

    if len(valid_parts) <= 2:
        # Fallback: just catch action frames broadly
        return "(wlan.fc.type_subtype == 0x0d || wlan.fc.type_subtype == 0x0e)"
    inner = " || ".join(valid_parts[2:])
    return (f"({' || '.join(valid_parts[:2])}) && ({inner})")


@dataclass
class BfiFrame:
    """Parsed representation of one beamforming-feedback action frame."""
    time_rel: str = ""
    frame_len: str = ""
    sa: str = ""
    da: str = ""
    ta: str = ""
    ra: str = ""
    category: str = ""
    vht_action: str = ""
    # VHT MIMO control
    vht_nc: str = ""
    vht_nr: str = ""
    vht_bw: str = ""
    vht_grouping: str = ""
    vht_codebook: str = ""
    vht_feedback_type: str = ""
    vht_remaining_segs: str = ""
    vht_report: str = ""
    # HE MIMO control
    he_nc: str = ""
    he_nr: str = ""
    he_bw: str = ""
    he_grouping: str = ""
    he_codebook: str = ""
    he_feedback_type: str = ""
    he_remaining_segs: str = ""
    he_report: str = ""

    @property
    def is_vht(self) -> bool:
        return self.category == "21"

    @property
    def is_he(self) -> bool:
        return self.category == "30"

    @property
    def nc(self) -> Optional[int]:
        v = self.vht_nc if self.is_vht else self.he_nc
        return int(v) if v else None

    @property
    def nr(self) -> Optional[int]:
        v = self.vht_nr if self.is_vht else self.he_nr
        return int(v) if v else None

    @property
    def bw(self) -> Optional[int]:
        v = self.vht_bw if self.is_vht else self.he_bw
        return int(v) if v else None

    @property
    def grouping(self) -> Optional[int]:
        v = self.vht_grouping if self.is_vht else self.he_grouping
        return int(v) if v else None

    @property
    def codebook(self) -> Optional[int]:
        v = self.vht_codebook if self.is_vht else self.he_codebook
        return int(v) if v else None

    @property
    def feedback_type(self) -> Optional[int]:
        v = self.vht_feedback_type if self.is_vht else self.he_feedback_type
        return int(v) if v else None

    @property
    def remaining_segs(self) -> Optional[int]:
        v = self.vht_remaining_segs if self.is_vht else self.he_remaining_segs
        return int(v) if v else None

    @property
    def report_hex(self) -> str:
        return self.vht_report if self.is_vht else self.he_report

    @property
    def report_byte_len(self) -> int:
        h = self.report_hex
        if not h:
            return 0
        return len(h) // 2  # hex string → byte count


def _parse_row(row: List[str], active_fields: list[str]) -> BfiFrame:
    """Map a tshark TSV row to a BfiFrame using active_fields as the column map."""
    # Build field→value dict; missing fields default to ""
    vals = dict(zip(active_fields, row))
    g = vals.get  # shorthand
    return BfiFrame(
        time_rel=g("frame.time_relative", ""),
        frame_len=g("frame.len", ""),
        sa=g("wlan.sa", ""),
        da=g("wlan.da", ""),
        ta=g("wlan.ta", ""),
        ra=g("wlan.ra", ""),
        category=g("wlan.fixed.category_code", ""),
        vht_action=g("wlan.vht.action", ""),
        vht_nc=g("wlan.vht.mimo_control.ncindex", ""),
        vht_nr=g("wlan.vht.mimo_control.nrindex", ""),
        vht_bw=g("wlan.vht.mimo_control.chanwidth", ""),
        vht_grouping=g("wlan.vht.mimo_control.grouping", ""),
        vht_codebook=g("wlan.vht.mimo_control.codebookinfo", ""),
        vht_feedback_type=g("wlan.vht.mimo_control.feedbacktype", ""),
        vht_remaining_segs=g("wlan.vht.mimo_control.remaining_feedback_segs", ""),
        vht_report=g("wlan.vht.compressed_beamforming_report", ""),
        he_nc=g("wlan.he.mimo_control.ncindex", ""),
        he_nr=g("wlan.he.mimo_control.nrindex", ""),
        he_bw=g("wlan.he.mimo_control.chanwidth", ""),
        he_grouping=g("wlan.he.mimo_control.grouping", ""),
        he_codebook=g("wlan.he.mimo_control.codebookinfo", ""),
        he_feedback_type=g("wlan.he.mimo_control.feedbacktype", ""),
        he_remaining_segs=g("wlan.he.mimo_control.remaining_feedback_segs", ""),
        he_report=g("wlan.he.compressed_beamforming_report", ""),
    )


def run_tshark_on_pcap(pcap: str) -> List[BfiFrame]:
    """Run tshark on an existing pcap and return parsed BfiFrame list."""
    active = _get_active_fields()
    cmd = [
        TSHARK, "-r", pcap,
        "-Y", _get_display_filter(),
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "quote=n",
        "-E", "occurrence=f",  # first occurrence only for multi-value fields
    ]
    for f in active:
        cmd += ["-e", f]
    print(f"[*] Running: {' '.join(cmd)}")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0 and proc.stderr:
        print(f"[!] tshark stderr:\n{proc.stderr}", file=sys.stderr)
    frames: List[BfiFrame] = []
    for line in proc.stdout.strip().splitlines():
        if not line.strip():
            continue
        row = line.split("\t")
        frames.append(_parse_row(row, active))
    return frames


def run_tshark_live(iface: str, duration: int, count: int,
                    write_pcap: Optional[str]) -> List[BfiFrame]:
    """Capture live on *iface* then parse.  Returns BfiFrame list."""
    # We capture into a temp pcap (or user-specified one), then analyse.
    tmp = write_pcap or "/tmp/bfi_live_capture.pcap"
    # tshark refuses a display filter (-Y) while capturing to a file (-w):
    # "Display filters aren't supported when capturing and saving." So we
    # capture UNFILTERED here and let run_tshark_on_pcap(tmp) apply -Y on read.
    # ponytail: unfiltered capture can be large on a busy channel — add a BPF
    # capture filter (-f) if pcaps balloon; duration/count already bound it.
    cap_cmd = [
        TSHARK, "-i", iface,
        "-p",  # no promisc: redundant in monitor mode, avoids dmesg toggle spam
        "-a", f"duration:{duration}",
        "-w", tmp,
    ]
    if count > 0:
        cap_cmd += ["-c", str(count)]
    print(f"[*] Capturing on {iface} for {duration}s …")
    print(f"    cmd: {' '.join(cap_cmd)}")
    print(f"    (requires root; press Ctrl-C to stop early)")
    proc = subprocess.run(cap_cmd, capture_output=True, text=True,
                         timeout=duration + 30)
    if proc.returncode != 0:
        print(f"[!] tshark capture stderr:\n{proc.stderr}", file=sys.stderr)
    if not os.path.exists(tmp) or os.path.getsize(tmp) == 0:
        print("[!] No packets captured.")
        return []
    print(f"[*] Analysing {tmp} …")
    return run_tshark_on_pcap(tmp)


def category_label(cat: str) -> str:
    if cat == "21":
        return "VHT"
    if cat == "30":
        return "HE"
    return f"cat={cat}"


def print_frame_summary(frames: List[BfiFrame]) -> None:
    """Print one human-readable line per frame."""
    if not frames:
        return
    print(f"\n{'='*90}")
    print(f"{'#':>3}  {'Time':>8}  {'SA':>17}  {'DA':>17}  "
          f"{'Cat':>5}  {'Nc':>3}  {'Nr':>3}  {'BW':>5}  "
          f"{'Grp':>3}  {'CB':>2}  {'FB':>2}  {'RptBytes':>8}")
    print(f"{'-'*90}")
    for i, f in enumerate(frames, 1):
        nc_s = str(f.nc) if f.nc is not None else "-"
        nr_s = str(f.nr) if f.nr is not None else "-"
        bw_s = CHAN_WIDTH.get(f.bw, str(f.bw)) if f.bw is not None else "-"
        grp_s = str(f.grouping) if f.grouping is not None else "-"
        cb_s = str(f.codebook) if f.codebook is not None else "-"
        ft_s = str(f.feedback_type) if f.feedback_type is not None else "-"
        rpt_s = str(f.report_byte_len) if f.report_byte_len else "-"
        print(f"{i:>3}  {f.time_rel:>8}  {f.sa:>17}  {f.da:>17}  "
              f"{category_label(f.category):>5}  {nc_s:>3}  {nr_s:>3}  "
              f"{bw_s:>5}  {grp_s:>3}  {cb_s:>2}  {ft_s:>2}  {rpt_s:>8}")
    print(f"{'='*90}\n")


def print_analysis(frames: List[BfiFrame]) -> None:
    """Final ANALYSIS block comparing real values vs reference assumption."""
    if not frames:
        print("=" * 60)
        print("ANALYSIS: zero beamforming feedback frames captured.")
        print("=" * 60)
        print("Hints:")
        print("  • A client must be actively associated and exchanging "
              "beamforming sounding frames with the AP.")
        print("  • Make sure the monitor interface is on the correct "
              "channel (the AP's primary channel).")
        print("  • Generate traffic (e.g. ping / iperf) through the AP to "
              "trigger sounding.")
        print("  • The AP must have VHT/HE beamforming enabled and at "
              "least one beamformee-capable STA.")
        return

    # Determine most-common category
    cat_counts = Counter(f.category for f in frames)
    most_common_cat, _ = cat_counts.most_common(1)[0]
    label = category_label(most_common_cat)

    # Collect stats for frames of the dominant category
    relevant = [f for f in frames if f.category == most_common_cat]
    nc_vals = [f.nc for f in relevant if f.nc is not None]
    nr_vals = [f.nr for f in relevant if f.nr is not None]
    bw_vals = [f.bw for f in relevant if f.bw is not None]
    grp_vals = [f.grouping for f in relevant if f.grouping is not None]
    cb_vals = [f.codebook for f in relevant if f.codebook is not None]
    ft_vals = [f.feedback_type for f in relevant if f.feedback_type is not None]
    rpt_vals = [f.report_byte_len for f in relevant if f.report_byte_len]

    def mode(lst):
        return Counter(lst).most_common(1)[0][0] if lst else None

    real_nc = mode(nc_vals)
    real_nr = mode(nr_vals)
    real_bw = mode(bw_vals)
    real_grp = mode(grp_vals)
    real_cb = mode(cb_vals)
    real_ft = mode(ft_vals)
    real_rpt = mode(rpt_vals)

    print("=" * 60)
    print("ANALYSIS — Beamforming Feedback Report Format")
    print("=" * 60)
    print(f"  Frames analysed       : {len(frames)} total, "
          f"{len(relevant)} {label} (dominant)")
    print(f"  Category              : {label} (cat code {most_common_cat})")
    print(f"  Nc  (ncindex+1)       : {real_nc if real_nc is not None else '?'}"
          f"  (ncindex = {real_nc - 1 if real_nc is not None else '?'})")
    print(f"  Nr  (nrindex+1)       : {real_nr if real_nr is not None else '?'}"
          f"  (nrindex = {real_nr - 1 if real_nr is not None else '?'})")
    print(f"  Channel width code    : {real_bw} → "
          f"{CHAN_WIDTH.get(real_bw, '?') if real_bw is not None else '?'}")
    print(f"  Grouping              : {real_grp}")
    print(f"  Codebook              : {real_cb}")
    print(f"  Feedback type         : {real_ft}")
    print(f"  Report byte length    : {real_rpt}")
    print()

    # Comparison table vs reference
    print("-" * 60)
    print(f"{'Field':<26} {'Real':>8} {'Ref':>8} {'Status':>10}")
    print("-" * 60)

    def cmp(label, real, ref):
        if real is None:
            status = "N/A"
        elif real == ref:
            status = "MATCH"
        else:
            status = "DIFFERS"
        r_s = str(real) if real is not None else "?"
        print(f"  {label:<24} {r_s:>8} {str(ref):>8} {status:>10}")

    cmp("Nr (num Rx antennas)", real_nr, REF["Nr"])
    cmp("Nc (num spatial sts)", real_nc, REF["Nc"])
    cmp("Nst (subcarriers)", real_rpt, REF["Nst"])
    cmp("Action-type byte", int(most_common_cat), REF["action_type_byte"])
    print("-" * 60)

    # Extra: show all unique (Nc, Nr, BW) combos seen
    combos = Counter(
        (f.nc, f.nr, f.bw) for f in relevant
        if f.nc is not None and f.nr is not None
    )
    if len(combos) > 1:
        print("\n  Multiple MIMO configs observed:")
        for (nc, nr, bw), cnt in combos.most_common():
            print(f"    Nc={nc} Nr={nr} BW={CHAN_WIDTH.get(bw, bw)} "
                  f"× {cnt} frames")

    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Capture / analyse 802.11 VHT/HE beamforming feedback "
                    "action frames (Gate 2 BFI format analysis).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
LIVE MODE NOTES:
  • The monitor interface (e.g. mon0) must already be up and on the
    target channel.  This script does NOT configure monitor mode.
  • tshark needs root — run via sudo or pkexec.
  • A client must be actively associated with the AP and generating
    traffic so the AP performs beamforming sounding.
""",
    )
    sub = parser.add_subparsers(dest="mode")

    # --- live ---
    p_live = sub.add_parser("live", help="Capture beamforming frames live.")
    p_live.add_argument("--iface", default="mon0",
                        help="Monitor-mode interface (default: mon0)")
    p_live.add_argument("--duration", type=int, default=20,
                        help="Capture duration in seconds (default: 20)")
    p_live.add_argument("--count", type=int, default=0,
                        help="Max frames to capture; 0 = unlimited (default: 0)")
    p_live.add_argument("--write", default=None,
                        help="Also save raw capture to this pcap path")

    # --- pcap ---
    p_pcap = sub.add_parser("pcap", help="Analyse an existing pcap file.")
    p_pcap.add_argument("file", help="Path to pcap/pcapng file")

    args = parser.parse_args()
    if args.mode is None:
        parser.print_help()
        sys.exit(1)

    # Verify tshark exists
    if not os.path.isfile(TSHARK):
        print(f"[!] tshark not found at {TSHARK}.  Install with: "
              "sudo apt install tshark", file=sys.stderr)
        sys.exit(1)

    if args.mode == "live":
        frames = run_tshark_live(args.iface, args.duration, args.count,
                                 args.write)
    else:
        if not os.path.isfile(args.file):
            print(f"[!] File not found: {args.file}", file=sys.stderr)
            sys.exit(1)
        frames = run_tshark_on_pcap(args.file)

    print(f"\n[*] Beamforming feedback frames found: {len(frames)}")
    print_frame_summary(frames)
    print_analysis(frames)


# ---------------------------------------------------------------------------
# Victim discovery (air-side; passive — no network membership needed)
# ---------------------------------------------------------------------------
# Devices emitting HE/VHT compressed-beamforming reports (category 30) ARE the
# beamformees = the only clients the attack can steer. Sniffing them off the air
# needs the iface in monitor mode but NO association / router creds, exactly how
# an attacker picks a target. Shared by the web dashboard and the Tkinter GUI.

def aggregate_victims(text: str) -> List[dict]:
    """Aggregate `tshark -T fields -e wlan.sa -e wlan.ra -e <signal>` lines into
    per-victim rows. Pure (no tshark) so it is unit-testable.

    Source addr = victim (beamformee); receiver = the AP it feeds back to.
    Returns [{mac, ap, frames, rssi}] sorted by frame count desc.
    """
    seen: dict[str, dict] = {}
    for line in text.splitlines():
        parts = line.split("\t")
        sa = (parts[0] if len(parts) > 0 else "").strip().lower()
        ra = (parts[1] if len(parts) > 1 else "").strip().lower()
        sig = (parts[2] if len(parts) > 2 else "").strip()
        if not sa or sa == "ff:ff:ff:ff:ff:ff":
            continue
        v = seen.setdefault(sa, {"mac": sa, "ap": ra, "frames": 0, "rssi": None})
        v["frames"] += 1
        if ra and not v["ap"]:
            v["ap"] = ra
        try:
            r = int(float(sig.split(",")[0]))  # radiotap may list per-chain; take first
            v["rssi"] = r if v["rssi"] is None else max(v["rssi"], r)
        except (TypeError, ValueError):
            pass
    return sorted(seen.values(), key=lambda d: d["frames"], reverse=True)


def scan_victims(iface: str = "mon0", duration: int = 6) -> List[dict]:
    """Passively sniff *iface* (must be in monitor mode) for BFI senders.

    Returns the same rows as aggregate_victims(). Raises RuntimeError on a
    tshark failure so callers can surface the reason (bad iface, not monitor).
    """
    duration = max(2, min(int(duration), 30))
    cmd = [
        TSHARK, "-i", iface, "-p", "-a", f"duration:{duration}",
        "-Y", "wlan.fixed.category_code==30",
        "-T", "fields",
        "-e", "wlan.sa", "-e", "wlan.ra", "-e", "wlan_radio.signal_dbm",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 15)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or f"tshark exit {proc.returncode}")
    return aggregate_victims(proc.stdout)


if __name__ == "__main__":
    main()
