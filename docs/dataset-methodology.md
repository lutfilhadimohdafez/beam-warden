# Beam Warden — Dataset & Detection Methodology

> ⚠️ **Superseded direction (kept for rigor notes).** This doc planned a
> throughput/PHY-telemetry IsolationForest dataset. The detector that shipped
> instead reads the **on-air BFI storm** (`tools/bfi_features.py`): per-2s-window
> `bfi_count`/`retry1`, labelled by attack phase, evaluated with GroupKFold-by-phase.
> Its still-valid warnings — leakage-safe (grouped/blocked) CV, multi-condition
> capture — were applied: see [`ml-engine.md`](ml-engine.md). Current real dataset:
> `data/bfi_<ts>.windows.csv`; OBJ3 = 100% within-condition, cross-condition is
> the open item this doc's multi-condition advice addresses.

*How to build a large, defensible dataset and a sound anomaly-detection pipeline for
detecting BFI-spoofing (BeamCraft null-steering) on 802.11ac/ax, replacing the current
150-sample single-condition IsolationForest.* (Compiled from a research pass; sources
cited inline.)

**Root cause of the current failure (state this plainly in the FYP):** the model didn't
learn "attack vs normal." It learned "this one busy-link fingerprint vs everything else."
150 samples at a 2 s poll = 5 minutes of ONE condition. IsolationForest flags idle/other
environments because they are genuinely out-of-distribution relative to that slice — not
because they are attacks. The fix is a normal baseline spanning the real operating
envelope, plus honest attack data.

---

## 1. Normal-baseline design (the main fix)
An unsupervised detector's "normal" must be the union of every benign operating condition
the system will see. WiFi channel features are highly environment-sensitive; BFI derives
from the same channel, so idle-vs-loaded, distance, client, interference and channel all
shift the distribution legitimately. If those shifts aren't in "normal," they read as
anomalies.

**Conditions to cover (factorial-ish, not one-at-a-time):**
- **Load:** idle, light browsing, streaming, saturated iperf (TCP + UDP). Biggest driver.
- **Time of day:** across day and night, spread over ≥1–2 weeks (RF noise/interference cycle).
- **Clients:** 3–4 different STAs (phone, laptops, IoT) — NSS/MCS/BFI stats differ per chipset.
- **Distance/position:** near (~1 m LOS), mid (~5 m), far/NLOS (through a wall).
- **Interference:** quiet channel vs congested (microwave, neighbour AP, Bluetooth).
- **Channels:** ≥2 (e.g. 80 MHz and 40 MHz) — subcarrier count & angle stats depend on BW.

**How much (2 s poll):** 30 samples/min, 1,800/hr, 43,200/day. Aim ~10–30 min per condition
cell (900–1,800 samples/cell); sample ~15–25 representative cells (not the full cross-product).
**Total normal ≈ 30,000–100,000 samples (~20–60 hrs over ≥1 week)** — 200–600× the current set.
Rule of thumb: no legitimate condition should have so few samples that the model treats it as
an outlier (hundreds per condition minimum). Scale reference: public CSI sets run ~1k
(FallDeFi) → ~14k (SignFi) → 271k (Widar 3.0); CIC-IDS2017 ~2.8M flows. Aim for the
"small research dataset done properly" tier.

## 2. Attack data — collection, labelling, avoiding circularity
**The circularity trap (call it out):** the current synthetic attack is *generated to look
anomalous*, so any detector "detects" it by construction — proves nothing. Fixes:
1. **Real transmitted attack, not an edited feature vector.** Run the actual forged-BFI
   transmission so measured telemetry + decoded BFI carry the real signature.
2. **Label by ground-truth event window**, from scripted injection start/stop timestamps —
   never by the detector's own output.
3. **Vary the attack** (forged-angle magnitude, victim client, near/far, quiet/congested),
   and run it **while idle AND while loaded** — else the model learns "low throughput =
   attack" and false-flags benign idle.
4. **Include benign confounders** (far client, interference, competing download, channel
   switch) in the NORMAL set, correctly labelled benign — these are your real false positives.

**How much attack:** ~2,000–10,000 samples across the same condition axes for a stable
held-out eval. Keep attacks rare in the **test** set (5–15%, reflects deployment); rebalance
only the **training** set for supervised models, never the test set.

## 3. One-class (unsupervised) vs supervised
- **Stay one-class now** (only normal data). IsolationForest is a strong, fast, interpretable
  default; add **One-Class SVM + LOF** as baselines (the comparison table is itself a report
  contribution). Autoencoder only worth it once the large normal set exists.
- Set `contamination` from a validation FP budget, not the default.
- **Move to supervised/hybrid once real non-circular attack data exists:** RF/GBM beats
  one-class on *seen* attacks but generalises worse to novel ones. **Best framing = hybrid:**
  keep the one-class detector deployed (catches unknown attacks), use the supervised model +
  labelled test set to evaluate/calibrate the threshold. Report both.

## 4. Feature engineering & leakage
- **Scale on train only:** fit StandardScaler on the training split, transform val/test with
  it. Wrap scaler+model in a scikit-learn `Pipeline` so CV refits per fold. (Same for PCA.)
- **Windowing:** add causal rolling aggregates (mean/std/min/max/delta over 5–15 samples =
  10–30 s) for volatile signals (retry, PER, RSSI, throughput) and BFI variance — captures
  attack *dynamics* a single 2 s snapshot misses.
- **No random k-fold** (adjacent 2 s samples are autocorrelated → temporal leakage). Use
  **temporal/blocked splits** (`TimeSeriesSplit`) with a **purge gap** ≥ one window, split at
  the **session** level (a whole session goes wholly to train or test, never both).
- Check feature importances so the model isn't just reading one collapse-correlated feature.

## 5. Dataset size, imbalance, validation
- **"Huge enough":** normal ~10⁴–10⁵ over ≥15 cells / ≥1 week; attack ~10³–10⁴ matched.
- **Imbalance:** rare attacks in the test set (5–15%); SMOTE/class-weights only inside the
  CV fold on the training set (else it leaks).
- **Do NOT report plain accuracy** (a "always normal" model scores ~90%+ and catches zero
  attacks). Report **attack-class precision/recall/F1, PR-AUC (and ROC-AUC), confusion
  matrix, and benign-condition FP rate** (the metric the current model fails) under temporal CV.
- **Killer FYP result — ablation:** train on the old 150-sample single-condition set vs the
  new multi-condition set; show the FP-rate collapse on idle/new-environment.

## 6. Provenance per capture session (`session_manifest.json`)
session_id, date, start/stop UTC, operator; condition labels (load, distance, client
make/model/chipset, room, interference, day/night); RF/PHY (channel, BW, band, TX power);
hardware/firmware (GN630v + fw, Alfa + driver, iwpriv/Wi-BFI/decoder versions, iperf flags);
attack metadata (tool+version, forged-angle params, victim MAC, injection start/stop,
attacker position); software env (OS, Python + sklearn versions, git commit); file pointers
(pcap, bfi csv, telemetry csv, checksums). Structural precedent: AWID3, CIC-IDS2017.

## 7. Concrete capture protocol + schema
```
dataset/
  raw/        <session_id>/capture.pcap
  telemetry/  <session_id>_iwpriv.csv
  bfi/        <session_id>_bfi.csv
  manifests/  <session_id>.json
  processed/  features.parquet   (merged, windowed, one row per 2s tick)
  splits/     train.txt val.txt test.txt   (session_id lists)
```
Per-tick schema: `session_id, timestamp_utc, condition_load, condition_distance, client_id,
channel, bw, throughput, retry_rate, tx_per, rx_per, rssi_chain0..N, mcs, nss, phi_mean,
psi_mean, angle_var, subcarrier_var, temporal_var, [rolling_*], label{normal|attack}, attack_type`.
Merge telemetry+BFI on nearest 2 s timestamp; keep raw pcap for re-derivation.

**Per session:** write manifest → start monitor capture + BFI decode + iwpriv poll (2 s) +
iperf at target load → run 10–30 min steady state (attacks scripted with logged start/stop,
some idle + some loaded) → stop, checksum, archive. Repeat across the matrix over ≥1 week.

**Split (session-level, temporal):** ~60/20/20 by session, test = most recent sessions +
≥1 held-out environment/client. Train one-class on normal-only training sessions; pick
`contamination`/threshold on val against an FP budget; report final numbers on untouched test.

## Do-this-next checklist
- [ ] Retire the 150-sample model; keep only as the "before" ablation baseline.
- [ ] Define the condition matrix; write a manifest before each capture.
- [ ] Capture ~30k–100k normal over ≥1 week, hundreds+/condition, incl. benign collapse confounders.
- [ ] Capture REAL (transmitted) attacks, labelled by scripted injection timestamps, idle+loaded, near+far.
- [ ] Add causal rolling-window features to telemetry + BFI variance.
- [ ] StandardScaler + model in a Pipeline; fit on train only.
- [ ] Session-level temporal/blocked splits (`TimeSeriesSplit` + purge); test = most recent + held-out env.
- [ ] IsolationForest primary; add OC-SVM + LOF baselines; supervised RF/GBM for eval once real attacks exist.
- [ ] Report attack precision/recall/F1, PR-AUC/ROC-AUC, confusion matrix, benign FP rate — never plain accuracy.
- [ ] Log full provenance per session.
- [ ] Include the before/after ablation (FP-rate collapse on idle/new-environment).

## Sources
- BFI attack surface: https://arxiv.org/html/2604.04179v1 · Wi-BFI decoder: https://arxiv.org/pdf/2309.04408
- WiFi-sensing domain shift: https://dl.acm.org/doi/10.1145/3570325 · https://arxiv.org/pdf/2412.04783
- Anomaly-detector comparison: https://link.springer.com/chapter/10.1007/978-3-032-23297-7_24 · https://www.nature.com/articles/s41598-025-20445-4
- sklearn pitfalls (scale on train / Pipelines): https://scikit-learn.org/stable/common_pitfalls.html
- Temporal leakage / blocked+purged CV: https://arxiv.org/pdf/2506.12183 · https://arxiv.org/pdf/2512.06932
- Imbalance / accuracy misleading / SMOTE: https://doi.org/10.3390/app16020801 · https://join.if.uinsgd.ac.id/index.php/join/article/view/1687
- Dataset scale/structure: https://arxiv.org/pdf/2207.07859 (SenseFi) · https://ieeexplore.ieee.org/document/9360747/ (AWID3) · https://www.unb.ca/cic/datasets/ids-2017.html (CIC-IDS2017)
