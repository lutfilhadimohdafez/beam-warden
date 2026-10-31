#!/usr/bin/env python3
"""Forensic INCIDENT REPORT from a Beam-Warden telemetry CSV -> PNG + PDF, and
optionally push to Telegram with an actionable incident-response caption.

Written for a network admin: what happened, where, who, how, the impact, and what
to do about it. Themed to the Beam-Warden dashboard palette.

Run:
  .venv/bin/python tools/attack_report.py data/obj1_<ts>.csv [--telegram]
ponytail: matplotlib (PNG+PDF), curl for the Telegram upload.
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rig import RIG

# ---- Beam-Warden dashboard palette (dark theme) ----
BG, PANEL, BORDER = "#0b0d12", "#12151d", "#242a38"
ACCENT, TEXT, MUTED = "#fb8d24", "#eef1f6", "#808a9e"
OK, DANGER, BLUE = "#35d07f", "#ff4b4b", "#4ea8f6"


def _f(row, key):
    try:
        return float(row.get(key, ""))
    except (TypeError, ValueError):
        return None


def _mean(vals, mask):
    xs = [v for v, m in zip(vals, mask) if m and v is not None]
    return sum(xs) / len(xs) if xs else 0.0


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("csv")
    ap.add_argument("--out", default=None)
    ap.add_argument("--win", type=float, default=2.0, help="seconds per window (for duration)")
    ap.add_argument("--telegram", action="store_true")
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
    retry_x = (a_retry / b_retry) if b_retry else 0.0
    dur = sum(is_atk) * a.win
    detected = (a_retry > b_retry * 1.3) or (b_tput and a_tput < b_tput * 0.85)
    severity = "HIGH" if (drop >= 40 or retry_x >= 3) else ("MEDIUM" if detected else "INFO")
    sev_col = DANGER if severity == "HIGH" else (ACCENT if severity == "MEDIUM" else MUTED)

    host = RIG.get("ROUTER_HOST", "router"); bssid = RIG.get("ROUTER_AP_BSSID", "?")
    ch = RIG.get("ROUTER_CHANNEL", "?"); victim = RIG.get("VICTIM_MAC", "?"); vip = RIG.get("VICTIM_IP", "?")
    now = datetime.now(timezone.utc)
    iid = "BW-" + now.strftime("%Y%m%d-%H%M%S")

    fig = plt.figure(figsize=(10, 12.6), facecolor=BG)

    def ftext(x, y, s, size=10, color=TEXT, weight="normal", family="monospace", ha="left"):
        fig.text(x, y, s, fontsize=size, color=color, fontweight=weight, family=family, ha=ha, va="top")

    # ---------- header ----------
    ftext(0.06, 0.975, "BEAM-WARDEN", size=19, color=ACCENT, weight="bold", family="sans-serif")
    ftext(0.06, 0.952, "SECURITY INCIDENT REPORT", size=12, color=TEXT, weight="bold", family="sans-serif")
    # severity pill
    axp = fig.add_axes([0.72, 0.94, 0.22, 0.035]); axp.axis("off")
    axp.add_patch(plt.Rectangle((0, 0), 1, 1, facecolor=sev_col, transform=axp.transAxes))
    axp.text(0.5, 0.5, f"SEVERITY: {severity}", ha="center", va="center", color="#111",
             fontweight="bold", fontsize=12, family="sans-serif", transform=axp.transAxes)
    ftext(0.94, 0.928, f"{iid}   {now.strftime('%Y-%m-%d %H:%M UTC')}", size=8.5, color=MUTED, ha="right")

    # ---------- one-line summary ----------
    headline = ("A beamforming-feedback injection (BeamCraft-style) attack is degrading a client's "
                "connection." if detected else "No clear attack signature in this capture.")
    ftext(0.06, 0.900, headline, size=10.5, color=TEXT, family="sans-serif")

    # ---------- chart ----------
    ax = fig.add_axes([0.085, 0.565, 0.83, 0.30], facecolor=PANEL)
    ax.plot(t, retry, color=DANGER, lw=2.0, label="tx-retry rate")
    ax.plot(t, per, color=ACCENT, lw=1.4, label="tx-PER")
    ax.set_ylabel("retry rate / PER", color=MUTED, fontsize=9)
    ax2 = ax.twinx()
    ax2.plot(t, tput, color=BLUE, lw=1.6, label="throughput (Mbps)")
    ax2.set_ylabel("throughput (Mbps)", color=BLUE, fontsize=9)
    s = None
    for i, atk in enumerate(is_atk + [False]):
        if atk and s is None:
            s = i
        elif not atk and s is not None:
            ax.axvspan(s - 0.5, i - 0.5, color=DANGER, alpha=0.12); s = None
    ax.set_xlim(0, len(rows) - 1); ax.set_xlabel("2-second window", color=MUTED, fontsize=9)
    for sp in ax.spines.values(): sp.set_color(BORDER)
    for sp in ax2.spines.values(): sp.set_color(BORDER)
    ax.tick_params(colors=MUTED, labelsize=8); ax2.tick_params(colors=MUTED, labelsize=8)
    # legend ABOVE the plot (outside) so nothing overlaps the data
    h1, l1 = ax.get_legend_handles_labels(); h2, l2 = ax2.get_legend_handles_labels()
    leg = ax.legend(h1 + h2 + [plt.Rectangle((0, 0), 1, 1, fc=DANGER, alpha=0.12)],
                    l1 + l2 + ["attack window"], loc="lower center", bbox_to_anchor=(0.5, 1.02),
                    ncol=4, fontsize=8, framealpha=0, labelcolor=TEXT)
    ftext(0.085, 0.885, "ATTACK TIMELINE", size=9, color=MUTED, weight="bold")

    # ---------- facts grid: WHERE / WHO / WHEN / HOW ----------
    def block(x, y, title, lines, tcol=ACCENT):
        ftext(x, y, title, size=9.5, color=tcol, weight="bold")
        ftext(x, y - 0.018, "\n".join(lines), size=9, color=TEXT, family="monospace")

    gy = 0.515
    block(0.06, gy, "WHERE", [f"Router    {host}", f"AP BSSID  {bssid}", f"Channel   {ch} (5 GHz)"])
    block(0.54, gy, "WHO (target)", [f"Client    {victim}", f"IP        {vip}", "Role      beamformee / victim"])
    gy2 = 0.435
    block(0.06, gy2, "WHEN", [f"Detected  {now.strftime('%Y-%m-%d %H:%M UTC')}",
                              f"Sustained ~{dur:.0f} s ({sum(is_atk)} windows)", "Status    ONGOING at capture"])
    block(0.54, gy2, "HOW", ["Forged BFI mis-steers the AP beam", "away from the client -> it can't ACK",
                             "-> AP retransmits (retry/PER spike)"])

    # ---------- impact ----------
    ftext(0.06, 0.355, "IMPACT", size=9.5, color=DANGER, weight="bold")
    imp = [
        f"Downlink throughput   {b_tput:5.1f} -> {a_tput:5.1f} Mbps   ({-drop:+.0f}%)",
        f"tx-retry rate         {b_retry:5.3f} -> {a_retry:5.3f}         ({retry_x:.1f}x normal)",
        f"tx-PER                {b_per:5.3f} -> {a_per:5.3f}",
    ]
    ftext(0.06, 0.337, "\n".join(imp), size=9.5, color=TEXT, family="monospace")

    # ---------- recommended response ----------
    ftext(0.06, 0.255, "RECOMMENDED RESPONSE", size=9.5, color=OK, weight="bold")
    steps = [
        "1. Treat as an ACTIVE availability attack on the client above - not a password breach.",
        "   It is PHY-layer: changing the Wi-Fi password / key will NOT stop it.",
        "2. A rogue transmitter is within RF range of this AP. Scan for unknown/new clients",
        "   and nearby devices; the attacker must hear the sounding handshake to forge it.",
        "3. Disrupt it now: move or temporarily isolate the client, and/or change the AP",
        "   channel - this breaks the attacker's capture->forge->inject loop.",
        "4. Harden (AP firmware): BFI encryption and channel-reciprocity verification; keep",
        "   Beam-Warden 'watch' running so re-attacks alert immediately.",
        "5. Preserve this report + the source telemetry CSV as incident evidence.",
    ]
    ftext(0.06, 0.237, "\n".join(steps), size=9, color=TEXT, family="monospace")

    ftext(0.06, 0.028, f"Source: {Path(a.csv).name}   |   Generated by Beam-Warden - Beamforming Anomaly Detection Framework",
          size=7.5, color=MUTED)

    stem = a.out or f"report_{Path(a.csv).stem}"
    outdir = Path(a.csv).resolve().parent.parent / "results"; outdir.mkdir(exist_ok=True)
    png, pdf = outdir / f"{stem}.png", outdir / f"{stem}.pdf"
    fig.savefig(png, dpi=130, facecolor=BG); fig.savefig(pdf, facecolor=BG)
    print(f"report: {png}\n        {pdf}\nseverity: {severity}  (retry {retry_x:.1f}x, throughput -{drop:.0f}%)")

    if a.telegram:
        token, chat = RIG.get("TELEGRAM_BOT_TOKEN", ""), RIG.get("TELEGRAM_CHAT_ID", "")
        if not token or not chat:
            sys.exit("--telegram: set TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID in rig.conf")
        caption = (
            f"BEAM-WARDEN SECURITY ALERT - SEVERITY {severity}\n"
            f"Beamforming-injection attack on {host} targeting client {victim} ({vip}).\n"
            f"Impact: downlink {-drop:+.0f}% ({b_tput:.0f}->{a_tput:.0f} Mbps), retry {retry_x:.1f}x normal, sustained ~{dur:.0f}s.\n"
            f"This is a PHY-layer availability attack - a Wi-Fi password change will NOT stop it.\n"
            f"Action: a rogue transmitter is within range of your AP - locate/remove it, or move/isolate "
            f"the client and change channel. Full incident report attached ({iid})."
        )
        r = subprocess.run(["curl", "-s", "--max-time", "25",
                            "-F", f"chat_id={chat}", "-F", f"photo=@{png}", "-F", f"caption={caption}",
                            f"https://api.telegram.org/bot{token}/sendPhoto"],
                           capture_output=True, text=True)
        print("telegram:", "sent" if '"ok":true' in r.stdout else f"failed ({r.stdout[:150]})")


if __name__ == "__main__":
    main()
