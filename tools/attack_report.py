#!/usr/bin/env python3
"""Forensic attack report from a Beam-Warden telemetry CSV -> PNG + PDF (and
optionally push to Telegram). Shows retry / PER / throughput across the run with
the attack window shaded, a before-vs-during summary, and the verdict.

Run:
  .venv/bin/python tools/attack_report.py data/obj1_<ts>.csv
  .venv/bin/python tools/attack_report.py data/obj1_<ts>.csv --telegram
ponytail: matplotlib for PNG+PDF, curl for the Telegram multipart upload.
"""
import argparse
import csv
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.gridspec import GridSpec

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rig import RIG

OK, DANGER, ACCENT, INK, MUTED = "#2e9e5b", "#d64545", "#e08b2a", "#1b1f27", "#8a93a6"


def _f(row, key):
    v = row.get(key, "")
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _mean(vals, mask):
    xs = [v for v, m in zip(vals, mask) if m and v is not None]
    return sum(xs) / len(xs) if xs else 0.0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("csv")
    ap.add_argument("--out", default=None, help="output basename (default: report_<csv stem>)")
    ap.add_argument("--telegram", action="store_true", help="push PNG to Telegram (token/chat from rig.conf)")
    a = ap.parse_args()

    rows = list(csv.DictReader(open(a.csv)))
    if not rows:
        sys.exit("empty CSV")
    t = list(range(len(rows)))
    retry = [_f(r, "retry_rate") for r in rows]
    per = [_f(r, "tx_per_pct") for r in rows]
    tput = [_f(r, "throughput_tx_mbps") for r in rows]
    is_atk = [r.get("label") == "attack" for r in rows]

    nm, am = [not x for x in is_atk], is_atk
    b_retry, a_retry = _mean(retry, nm), _mean(retry, am)
    b_per, a_per = _mean(per, nm), _mean(per, am)
    b_tput, a_tput = _mean(tput, nm), _mean(tput, am)
    drop = 100 * (b_tput - a_tput) / b_tput if b_tput else 0.0
    detected = (a_retry > b_retry * 1.3) or (b_tput and a_tput < b_tput * 0.85)

    fig = plt.figure(figsize=(9, 7.2), facecolor="white")
    gs = GridSpec(2, 1, height_ratios=[3, 1.25], hspace=0.32)

    # ---- chart: retry/PER (left) + throughput (right), attack shaded ----
    ax = fig.add_subplot(gs[0]); ax.set_facecolor("white")
    ax.plot(t, retry, color=DANGER, lw=2, label="tx-retry rate")
    ax.plot(t, per, color=ACCENT, lw=1.5, label="tx-PER")
    ax.set_ylabel("retry rate / PER", color=INK)
    ax2 = ax.twinx()
    ax2.plot(t, tput, color="#2f6fd0", lw=1.6, label="throughput (Mbps)")
    ax2.set_ylabel("throughput (Mbps)", color="#2f6fd0")
    # shade contiguous attack windows
    s = None
    for i, atk in enumerate(is_atk + [False]):
        if atk and s is None:
            s = i
        elif not atk and s is not None:
            ax.axvspan(s - 0.5, i - 0.5, color=DANGER, alpha=0.08); s = None
    ax.axvspan(-1, -1, color=DANGER, alpha=0.08, label="attack window")  # legend proxy
    ax.set_xlim(0, len(rows) - 1)
    ax.set_xlabel("2-second window")
    ax.set_title("Beam-Warden — Beamforming Attack Report", fontsize=15, fontweight="bold", color=INK, loc="left")
    h1, l1 = ax.get_legend_handles_labels(); h2, l2 = ax2.get_legend_handles_labels()
    ax.legend(h1 + h2, l1 + l2, loc="upper left", fontsize=8, framealpha=0.9)
    for sp in ax.spines.values(): sp.set_color("#d9dde5")
    ax.tick_params(colors=MUTED); ax2.tick_params(colors=MUTED)

    # ---- summary panel ----
    axt = fig.add_subplot(gs[1]); axt.axis("off")
    verdict = "ATTACK DETECTED" if detected else "no clear attack signature"
    vcol = DANGER if detected else OK
    host = RIG.get("ROUTER_HOST", "router"); victim = RIG.get("VICTIM_MAC", "client")
    axt.text(0, 1.0, verdict, fontsize=14, fontweight="bold", color=vcol, va="top")
    lines = [
        f"Router {host}   Protected client {victim}",
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}   Source {Path(a.csv).name}",
        "",
        f"                 normal        under attack",
        f"  retry rate     {b_retry:6.3f}   ->   {a_retry:6.3f}   ({(a_retry-b_retry):+.3f})",
        f"  tx-PER         {b_per:6.3f}   ->   {a_per:6.3f}",
        f"  throughput     {b_tput:5.1f}M   ->   {a_tput:5.1f}M   ({-drop:+.1f}% )",
    ]
    axt.text(0, 0.80, "\n".join(lines), fontsize=9.5, family="monospace", color=INK, va="top", linespacing=1.5)

    stem = a.out or f"report_{Path(a.csv).stem}"
    outdir = Path(a.csv).resolve().parent.parent / "results"
    outdir.mkdir(exist_ok=True)
    png, pdf = outdir / f"{stem}.png", outdir / f"{stem}.pdf"
    fig.savefig(png, dpi=130, bbox_inches="tight", facecolor="white")
    fig.savefig(pdf, bbox_inches="tight", facecolor="white")
    print(f"report: {png}\n        {pdf}\nverdict: {verdict}  (retry {b_retry:.3f}->{a_retry:.3f}, throughput -{drop:.0f}%)")

    if a.telegram:
        token, chat = RIG.get("TELEGRAM_BOT_TOKEN", ""), RIG.get("TELEGRAM_CHAT_ID", "")
        if not token or not chat:
            sys.exit("--telegram: set TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID in rig.conf")
        cap = f"Beam-Warden attack report - {verdict} on {host} (throughput -{drop:.0f}%)"
        r = subprocess.run(["curl", "-s", "--max-time", "20",
                            "-F", f"chat_id={chat}", "-F", f"photo=@{png}", "-F", f"caption={cap}",
                            f"https://api.telegram.org/bot{token}/sendPhoto"],
                           capture_output=True, text=True)
        print("telegram:", "sent" if '"ok":true' in r.stdout else f"failed ({r.stdout[:120]})")


if __name__ == "__main__":
    main()
