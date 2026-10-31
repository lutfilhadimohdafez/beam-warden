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

## 3. The model

**RandomForest** (self-calibrated relative features), evaluated **leave-one-RUN-out**
(hold out a whole capture run → the "works on a network it never saw" number).

- **OBJ3 target: ≥55 %.**
- **Achieved: 82.1 %** leave-one-run-out across 4 real runs / 126 samples.
- Per-held-out-run: **[100, 48, 80, 100]**. Top features: **tx_PER, throughput, retry**.

Train offline (`tools/train_telemetry.py`); the forest's decision is **distilled to
calibrated thresholds** the on-router package runs (no sklearn on the router).

---

## 4. Results & honest status

- ✅ Meets OBJ3 (82.1 % ≥ 55 %) on *unseen-run* data, adapter-free.
- ⚠️ **The 48 % fold** is the one noisy low-power run — the **covert-attack
  weakness**: when the attack doesn't degrade the link, telemetry barely moves.
  Documented, not hidden. Catching the forged frames directly would fix it but needs
  monitor mode (not portable) — the deliberate tradeoff for universal deployability.
- ⚠️ 4 runs on one rig; more conditions (distance/channel/load/hardware) would
  shrink that fold — the outstanding rigor work.

---

## 5. Files

| File | Role |
|---|---|
| `tools/mt76_capture.py` / `tools/obj1_run.py` | collect labelled `iw station dump` telemetry (normal/attack) |
| `tools/train_telemetry.py` | self-calibrated features → RandomForest → leave-one-run-out accuracy |
| `openwrt/beamwarden/` | the standalone OpenWrt package: `calibrate` + `watch` on-router, adapter-free |
| `tools/dashboard.py` + `dashboard.html` | live telemetry tiles (retry/PER/throughput/RSSI) = the live detection view |

**Reproduce the number:**
`.venv/bin/python tools/train_telemetry.py data/obj1_*.csv data/real_aba_*.csv`

**Deploy on any router:** `opkg install beamwarden_*.ipk` → `beamwarden calibrate` → `beamwarden watch`.
