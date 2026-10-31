# Beam Warden — ML Detection Engine (Objective 3)

**How we detect the BeamCraft beamforming-feedback forgery attack — from the
attack's own on-air signature.** For the team: what the engine does, which
features it uses, and an honest read of how strong the result is.

> Supersedes the earlier Isolation-Forest / 11-telemetry design. That approach
> (unsupervised anomaly detection on router throughput/PHY counters) was built
> but did not pan out: at a strong, close, single-stream link the attack barely
> moves throughput/RSSI, so there was no reliable telemetry signal to learn. The
> working detector reads the **attack's forged-BFI frames directly off-air.**

---

## 1. The idea in one line

The BeamCraft attack works by **injecting forged beamforming-feedback (BFI)
frames** that impersonate the victim. Those injected frames are *themselves* the
anomaly: during an attack the victim's BFI appears on-air far more often than the
AP could possibly be sounding it, and the forgeries carry the **RETRY=1** bit.
So we don't try to see the attack's *effect* on the link — we detect the
**forgery storm** itself.

```
   monitor victim's BFI frames ─► count per 2s window ─► rate doubled? ─► 🚨 ATTACK
```

This matches the project title ("Beamforming **Anomaly** Detection") and the
BeamCraft journal §6, which names retry/PER on the BFI frames as the strongest
detection feature — far more robust than throughput, which is link-dependent.

---

## 2. The features ⭐

Per **2-second window**, computed from the victim's VHT compressed-beamforming
frames on-air (`wlan.fixed.category_code == 21`, `wlan.sa == <victim MAC>`):

| Feature | What it is | Under attack |
|---|---|---|
| `bfi_count` | victim BFI frames in the window | **~doubles** (genuine + injected forgeries) |
| `bfi_rate` | `bfi_count / 2s` (frames/sec) | **spikes** |
| `retry1_count` | how many carry the RETRY=1 bit | **spikes** (BeamCraft sets RETRY=1 on every forgery) |
| `retry1_ratio` | `retry1_count / bfi_count` | **spikes** |

Measured separation on the real capture (40 normal / 20 attack windows):

```
   normal window : ~8  BFI/s,  retry1 ≈ 0
   attack window : ~16 BFI/s,  retry1 ≈ 17
```

The classes are **widely, cleanly separable** — there is no overlap on
`bfi_count`.

---

## 3. The model (and an honest note about it)

We report a **RandomForest** (200 trees) evaluated with **GroupKFold by phase**
(each 20 s A/B/A phase is one group, so adjacent near-identical 2 s windows never
straddle the train/test split — a leakage-safe estimate).

**Honest framing for the viva:** the real detector is **physics, not a 200-tree
model** — a single threshold `bfi_count ≥ 24` already separates every window.
The right thing to claim is: *injecting forged BFI unavoidably raises the on-air
BFI rate, and that rate anomaly is what we detect.* The RandomForest is just the
reported estimator; the signal is in the data.

**Robustness:** dropping *both* RETRY features (keeping only `bfi_count` +
`bfi_rate`) still gives 100%. So an attacker who omits the RETRY=1 marker does
**not** evade detection — they cannot inject forgeries without raising the rate.

---

## 4. Results & honest status

- **OBJ3 target: ≥55% detection accuracy.**
- **Achieved: 100%** (GroupKFold by phase, leakage-safe; every fold 100%), on
  **real hardware** capture — no synthetic data.
- ⚠️ **Scope limit, stated up front:** this is **within one condition** — one
  ~6-minute capture, two 20 s attack bursts (≈2 truly independent attack events),
  one distance/channel/traffic load. **Cross-condition generalisation is
  untested** and is the honest next step: ≥3 captures across different days /
  distances / channels / loads, reported as held-out-capture accuracy.
- Packaging the engine into OpenWrt firmware as a standalone on-box service is
  **future work** — detection needs a monitor-mode capture, and the AC2100's
  mt7615 does not expose a monitor VIF alongside its AP, so today the engine runs
  on the laptop's Alfa monitor beside the AP.

---

## 5. Files

| File | Role |
|---|---|
| `tools/bfi_run.py` | capture harness — monitor mon0, A/B/A (normal→attack→normal), tcpdump → `data/bfi_<ts>.pcap` + `.phases.json` |
| `tools/bfi_features.py` | offline — slices the pcap into labelled 2 s windows, trains, prints GroupKFold accuracy → `data/bfi_<ts>.windows.csv` |
| `tools/dashboard.py` (`_bfi_verdict`, `--bfi-feed` / `--replay`) | live/replay detection stream to the dashboard |
| `tools/dashboard.html` (BFI-Storm panel) | exhibition NORMAL↔ATTACK display |

**Reproduce the number:**
`.venv/bin/python tools/bfi_features.py --pcap data/bfi_<ts>.pcap --phases data/bfi_<ts>.phases.json`
