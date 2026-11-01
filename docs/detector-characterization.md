# Beam-Warden Detector — Characterization & Honest Limits

What live testing on real hardware (AC2100 + Honor X9c, 2026-11-01) proved, and the
three real-world confounds it exposed. This is the honest robustness picture for the
viva — the concept + metric are proven; real-world hardening is characterized future work.

## What is proven
- **Attack replication (OBJ1):** forged-BFI injection cuts downlink **56–70%** on real
  hardware, RSSI-controlled (`data/obj1_*.csv`).
- **Adapter-free telemetry (OBJ2):** the router's own `iw station dump` (retry/PER/MCS/
  RSSI/throughput) carries the signal — no monitor mode, no capture adapter.
- **ML engine on-router (OBJ3):** a trained RandomForest, exported to an `awk` tree-walk
  (`model.awk`), runs **on the router** (no python/sklearn). **80.1%** leave-one-run-out
  across 5 real runs — *within matched conditions*. Telegram alert + forensic report work.

## The three confounds (each found by a real failure)

| # | Confound | What happens | Status |
|---|---|---|---|
| 1 | **Covert attack** | at a strong link the attack is absorbed (no throughput/retry change) — nothing to detect | **physics limit** — the attack is covert *by design* (paper §5); undetectable from effect alone |
| 2 | **Load (demand)** | light/idle traffic has low throughput + noisy retry → looks like a "collapse" vs a heavy baseline → false alarm | **FIXED — gate-to-load:** only score windows under substantial load (`ACTIVE_MIN_PKTS`); light/idle skipped |
| 3 | **Link drift** | RSSI/rate adapt over minutes (movement, interference, rate control) → a static baseline goes stale → normal looks like an attack | **open — the deep one** |

### Evidence
- **Covert:** 550-mBm run at a close link → −0.8% drop, retry flat → no signature (correct no-detect).
- **Load:** overnight, light traffic (0.4–6.7 Mbps) false-alarmed against a heavy-load baseline.
  Gate-to-load + heavy-load baseline eliminated it (idle + light + heavy-normal → 0 alerts).
- **Drift:** phone at distance; baseline learned at RSSI −80.8 / 50 Mbps, but 5 min later the
  link had drifted to RSSI −87 / 21 Mbps — so *normal* 21 Mbps read as a collapse vs the stale
  50 Mbps baseline → false alarm on the normal phase, even though the attack (−62%) also bit.

## Root cause
**Wi-Fi RF is non-stationary.** Throughput and retry depend on load *and* on a link whose
RSSI/rate wander for non-attack reasons. A **static per-network baseline cannot hold**: when
the link weakens, normal looks like an attack; when it varies, attacks hide. Each fix
(varied-normal, drop-throughput, gate-to-load) removed one confound and revealed the next.

## The research path (future work, not a one-line patch)
1. **Adaptive baseline** — a rolling baseline that tracks current conditions, updated *only*
   when the detector is confident the link is not under attack (avoid self-poisoning).
2. **Drift-robust features** — compare against *expectation*, not an absolute:
   - **per-STA divergence** (plunder fingerprint, `docs/beamcraft-attack-context.md` §6a):
     victim craters *while* another client climbs — a relative signal immune to link drift.
   - **throughput vs the RSSI/MCS it predicts** — flags "worse than this signal should give".
3. **More + cross-hardware data** across distance/channel/load/router to retrain + validate.

## Controlled demo protocol (works today)
The failures are between-condition drift; *within* a stable, freshly-calibrated window the
detector is clean. For a reliable exhibition demo:
1. Stable setup, phone where it will stay, under real load.
2. Run `tools/demo_live.sh` — fresh calibrate (~20 s) + start the watcher.
3. **Immediately** fire the attack (`obj1_auto.py 550`) while the baseline is fresh.
4. Dashboard panel flips **ATTACK** + Telegram alert from the router.

The calibrate→attack gap is seconds, so the baseline matches current RF → clean detection.
