# Beam Warden — ML Detection Engine (Objective 3)

**How we detect the beamforming-spoofing attack from router telemetry, using an
Isolation Forest.** For the team — this is what the ML engine does and which
variables it uses.

---

## 1. The idea in one line

We can't get examples of every possible attack, but we *can* record lots of
**normal** Wi-Fi behaviour. So we train a model to learn "what normal looks like,"
then flag anything that **deviates** from normal as a possible attack. This is
**anomaly detection**, not classification.

```
   router telemetry ──► learn "normal" ──► score each new sample ──► NORMAL / 🚨 ATTACK
```

---

## 2. Why Isolation Forest (not a normal classifier)

| Approach | Needs attack examples? | Catches unseen attacks? |
|---|---|---|
| Classifier (e.g. SVM, NN) | **Yes** — must be trained on labelled attacks | No — only attacks it has seen |
| **Isolation Forest (ours)** | **No** — trains on *normal only* | **Yes** — flags anything unusual |

**Isolation Forest** is an unsupervised anomaly detector. Intuition: it builds many
random decision trees that keep splitting the data on random features at random
thresholds. **Anomalies get "isolated" (cut off alone) after very few splits**,
because they sit far from the dense cluster of normal points. Normal points need
many splits to isolate. So:

```
   short isolation path  =  unusual  =  ANOMALY  (low / negative score)
   long isolation path   =  typical  =  NORMAL   (high / positive score)
```

We use **200 trees** (`n_estimators=200`) and tell it we expect ~**2%** of training
data to look odd (`contamination=0.02`). Trained only on the *normal* dataset.

---

## 3. The variables (features) the engine uses ⭐

The engine reads **11 telemetry variables per 2-second sample**. These are exactly
the metrics that the BeamCraft attack disturbs — so a shift in them is our
fingerprint of an attack.

| # | Variable (`column`) | What it is | Under attack it… |
|---|---|---|---|
| 1 | `throughput_tx_mbps` | uplink goodput (Mbps) | **collapses** |
| 2 | `throughput_rx_mbps` | downlink goodput (Mbps) | **collapses** |
| 3 | `retry_rate` | tx failures ÷ tx attempts | **spikes** (beam misaimed → retransmits) |
| 4 | `tx_per_pct` | transmit packet-error rate (%) | **spikes** |
| 5 | `rx_per_pct` | receive packet-error rate (%) | **spikes** |
| 6 | `rssi0` | signal strength, antenna chain 0 (dBm) | **shifts** (beam energy redirected) |
| 7 | `rssi1` | signal strength, chain 1 (dBm) | shifts |
| 8 | `rssi2` | signal strength, chain 2 (dBm) | shifts |
| 9 | `rssi3` | signal strength, chain 3 (dBm) | shifts |
| 10 | `tx_mcs` | modulation/coding index (link rate) | **drops** (worse channel → lower rate) |
| 11 | `tx_nss` | number of spatial streams | may drop |

All 11 come straight from the router's `iwpriv <iface> stat` counters, collected by
`tools/gn630v_telemetry.py`. The **attack signature** = throughput ⬇, PER & retry ⬆,
MCS ⬇, RSSI shifted — and the Isolation Forest learns to notice that whole pattern
at once, not any single metric.

---

## 4. The pipeline (train → score)

```
        ┌─────────────────────── TRAIN (once, offline) ───────────────────────┐
 normal │  normal_iperf.csv ─► pick the 11 features ─► StandardScaler (z-score) │
 data   │        ─► IsolationForest(200 trees).fit() ─► models/detector.joblib  │
        └─────────────────────────────────────────────────────────────────────┘

        ┌─────────────────────── SCORE (live, per sample) ────────────────────┐
 live   │  telemetry sample ─► same 11 features ─► same scaler.transform()     │
 sample │   ─► model.decision_function() ─► score  (>0 normal, <0 anomalous)   │
        │   ─► model.predict() ─► verdict (+1 normal / −1 attack) ─► dashboard  │
        └─────────────────────────────────────────────────────────────────────┘
```

- **StandardScaler** puts every variable on the same scale (z-score: subtract mean,
  divide by std), so throughput (~98) and retry_rate (~0.13) get equal weight.
- **`decision_function`** gives a continuous **anomaly score** (the dashboard plots
  it; the 0 line is the decision boundary).
- **`predict`** gives the hard verdict used for the 🚨 banner.

---

## 5. Files

| File | Role |
|---|---|
| `tools/train_detector.py` | trains the Isolation Forest on normal data → `models/detector.joblib` |
| `models/detector.joblib` | the saved bundle: `{model, scaler, features}` |
| `tools/dashboard.py` (`score_sample`) | loads the model, scores each live/replayed sample |
| `tools/make_synthetic_attack.py` | builds a labelled *simulated* attack CSV for demoing detection before real attack data exists |

**Retrain:** `.venv/bin/python tools/train_detector.py`

---

## 6. Current results & honest status

- On **normal** telemetry: ~**2%** flagged (the expected false-positive floor).
- On the **synthetic** attack set: **100%** of attack samples flagged.
- ⚠️ The 100% is on *simulated* attack data we generated from the known BeamCraft
  signature — a proof the **pipeline works**, not a real accuracy number. The real
  detection-accuracy figure (proposal target **≥55%**) needs telemetry captured
  during a **real** attack, which requires a 4×4-on-5GHz AP (the GN630v is 2×2).
