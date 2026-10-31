# Beam-Warden — ML Detection Engine (Objective 3)

**How we detect the BeamCraft beamforming-feedback forgery attack from the
router's OWN telemetry — adapter-free, so it deploys on anyone's OpenWrt router.**

> Supersedes TWO earlier designs:
> 1. **IsolationForest / 11-telemetry** — unsupervised on raw router counters; the
>    raw throughput/RSSI signal was too weak at a strong link.
> 2. **BFI-storm (monitor capture)** — counted the forged BFI frames on-air. Clean
>    (100%) but needs **monitor-mode capture**: a USB adapter in the lab, and a
>    monitor VIF that the AP's own radio won't deliver (verified on the mt7615 — the
>    VIF creates but captures nothing) and that many routers can't do at all. **Not
>    portable**, so it's retired as the deployable detector (kept only as a research
>    result / exhibition demo where the Alfa is present).
>
> The shipped engine reads `iw station dump` — telemetry every OpenWrt router has.

---

## 1. The idea in one line

A forged-BFI attack misdirects the AP's beam, so the victim can't ACK → **the AP
retransmits** → its own **tx-retry / PER** counters climb and MCS/throughput sag.
We detect that retransmit signature from the router's own station telemetry.

```
   iw station dump ─► self-calibrate baseline ─► relative features ─► RandomForest ─► verdict
   (no adapter)        (per network)              (ratio/z vs normal)
```

The attack is **covert by design** (barely dents throughput on a strong link), so
we do NOT rely on a bandwidth alarm — the **retry/PER rise is the physics** (a
misdirected beam *must* cause retransmits), present even when throughput looks fine.

---

## 2. The features ⭐ — self-calibrated (this is what makes it portable)

Per time window, from `iw dev <ap> station dump` (per client):

| Raw metric | Under attack |
|---|---|
| `retry_rate` (tx retries / packets) | **rises** |
| `tx_per` (tx failed / sent) | **rises** |
| `tx_mcs`, `throughput` | sag |
| `rssi` (per-chain) | ~flat (direction, not power) |

**Every network's normal is different** (a quiet home ≠ a busy hall), so a model on
*absolute* values won't transfer. Instead each metric becomes a **relative** feature
vs that network's own calibrated baseline:

```
   retry_ratio = current / baseline_mean      retry_z = (current - mean) / std
```

A 60 % retry jump reads the same whether the baseline is 0.1 or 0.6 → the model
learns the *shape* of an attack, not one rig's numbers.

---

## 3. The model — trained offline, RUNS ON THE ROUTER

**RandomForest** on self-calibrated relative features, evaluated **leave-one-RUN-out**
(hold out a whole capture run → the "works on a network it never saw" number).

- **OBJ3 target: ≥55 %.**
- **Laptop RF (analysis, 5 metrics incl. rx_per):** 83.6 % across 5 real runs / 160 samples.
- **Exported on-router model (4 metrics: retry/PER/throughput/RSSI):** **80.1 %**,
  per-held-out-run **[100, 68, 77, 100, 56]**. Top features: **tx_PER, throughput, retry**.

**The learned model ships ON the router** — not a threshold. `tools/export_model.py`
trains a compact forest (60 trees, depth 8) and **code-generates it to an `awk`
tree-walk** (`model.awk`, ~13 KB). `beamwarden watch` builds the 8 relative features
from `iw station dump` and runs `model.awk` for each verdict — the real forest, no
python/sklearn on the router. Verified: `awk` reproduces sklearn 160/160, and on the
AC2100 `beamwarden status` reports `engine=ML-forest`. (A retry/PER threshold remains
as a fallback only if `model.awk` is absent.)

---

## 4. Results & honest status

- ✅ Meets OBJ3 (**80.1 %** ≥ 55 %) on *unseen-run* data, adapter-free, with the ML
  engine genuinely running on the router.
- ⚠️ **The ~56 % worst fold** is the noisy low-power run — the **covert-attack
  weakness**: when the attack doesn't degrade the link, telemetry barely moves.
  Documented, not hidden. Catching the forged frames directly would fix it but needs
  monitor mode (not portable) — the deliberate tradeoff for universal deployability.
- ⚠️ 5 runs on one rig; more conditions (distance/channel/load/**hardware**) would
  shrink that fold — the outstanding rigor work.

---

## 5. Files

| File | Role |
|---|---|
| `tools/mt76_capture.py` / `tools/obj1_run.py` | collect labelled `iw station dump` telemetry (normal/attack) |
| `tools/train_telemetry.py` | self-calibrated features → RandomForest → leave-one-run-out accuracy (analysis) |
| `tools/export_model.py` | trains the compact forest → **code-gens `model.awk`** (the on-router engine) |
| `openwrt/beamwarden/` | standalone OpenWrt package: `calibrate` + `watch` + `model.awk` + `on_alert` (Telegram), adapter-free |
| `tools/attack_report.py` | forensic incident report (PNG/PDF) + Telegram push |
| `tools/dashboard.py` + `dashboard.html` | live telemetry tiles + Telegram settings panel |

**Reproduce the number / rebuild the on-router model:**
`.venv/bin/python tools/export_model.py data/obj1_*.csv data/real_aba_*.csv`

**Deploy on any router:** `opkg install beamwarden_*.ipk` → `beamwarden calibrate` → `beamwarden watch`.
