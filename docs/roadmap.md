# Beam Warden — Roadmap (as of 2026-11-02 ~02:00)

Snapshot of where things stand the night before the exhibition demo, and what's next.

## ✅ Done (committed + pushed, main @ 9940244+)

- **Live-fire PROVEN via GUI** — Connect → calibrate → attack → detect → alarm →
  Telegram, end-to-end, 4 bounded injection runs, zero crashes.
- **Detector tuning** that makes it alarm reliably: `LOAD_GRACE_WINDOWS=10` (score the
  attack's throughput-collapse windows) + `HITS_TO_ALARM=2`.
- **Telegram**: enabled, report-style incident message, confirmed delivery (stamp only
  on `ok:true`), and a **named profile list** (dropdown + save, like router profiles).
- **Alert audit log**: JSONL line per alarm → `/etc/beamwarden.conf:ALERT_LOG`.
- **Dashboard**: auto-connects on `--mode live` (no more Errno 111 / manual Connect).
- **.ipk** rebuilt `0.1-2` (apk-router install documented).
- **Docs**: two-tier architecture, README index with jump-links, screenshot
  **User Guide**, calibration accuracy fixed (calibrate under load).
- **Tests 99/99**; Codex audit committed.

## 🔴 Morning, pre-demo (low-risk, do first)

1. **Dry-run the click-order** (~3 min): `python tools/dashboard.py --mode live` →
   it auto-connects → Command Center → **Prepare + Run Live Demo** → approve the
   admin prompt → watch the chain.
2. **Phone ready**: Termux `iperf3 -s` running, phone awake + stationary.
3. **Venue internet for Telegram** ⚠️ — the router needs WAN to reach
   `api.telegram.org`. Share the laptop's ethernet to the router WAN, or a phone
   hotspot; then **Send test alert** to confirm. (Detection + the local JSONL log
   work regardless; only Telegram needs WAN.)
4. **Re-calibrate at the venue under load** — the Guided Live Demo does this
   automatically each run, so a fresh run on-site handles it.

## 🟡 Post-demo (fresh eyes, bigger pieces)

- **A. README deep cross-check** — line-by-line verify the technical sections §1–7
  (the math/decode). Viva-critical accuracy; not done the night of, on purpose.
- **B. OBJ1 confirmatory campaign** (the real science gap, Codex P0) — ≥20 valid
  attack trials across sessions + **matched sham/no-injection controls**; report a
  *trial-based success rate* (not just throughput loss) with a confidence interval.
  Tools exist: `tools/collect_interval_campaign.py`, `tools/eval_interval_candidate.py`.
- **C. Feature-parity + model** (Codex P0) — the interval-v2 candidate model
  **rolled back** on a fresh-normal false alarm (`models/candidates/*/deployment.json`).
  Recollect with the unified interval schema, retrain, re-evaluate the real AWK on a
  truly held-out session before deploying.
- **D. BFI/CSI stream restore** — recover the HE angle decoder as a module from git
  `45f7ac0` (`stream_features` + `decode_angles`/`compute_NANG`/`get_bitwidths`), so
  the dashboard's live BFI panel works again. (Regression from the VHT-counter
  repurpose; not demo-critical.)
- **E. NOC collector (the "server" tier)** — SQLite + a webhook: `on_alert` POSTs the
  same JSON to a `/ingest` endpoint → an `/events` dashboard page aggregates many
  routers. Then package it npm-style (`pipx` / Docker) for any Linux.
- **F. LuCI router-hosted dashboard** — the proposal promised an on-router UI; the
  current dashboard is laptop-hosted (Codex gap). Optional, scope later.

## Guardrails (don't forget)

- **Never** run a sustained Alfa injection — the card + uplink share a USB bus and a
  wedge crashes the laptop. Bounded 12s bursts only (the Guided Live Demo is safe).
- **Don't overclaim** in the thesis: objectives are engineering milestones, not yet
  closed acceptance criteria — see `docs/audit-2026-11-01/review.md`.
