# Beam-Warden OpenWrt package (`beamwarden.ipk`)

Standalone, **adapter-free** on-router detector for **beamforming-feedback forgery**
(BeamCraft-style) attacks. OBJ3 deliverable: the anomaly-detection engine as a
self-contained OpenWrt package — **no monitor mode, no capture adapter, no Python,
no cloud.** It reads only `iw dev <ap> station dump`, which every OpenWrt router has,
so it runs on *anyone's* router.

## How a defender uses it (step by step)

1. **Build** (once, OpenWrt SDK for your target): `make package/beamwarden/compile`
2. **Install**: `opkg install beamwarden_*.ipk`
3. **Point it at your AP** — set `AP_IF` in `/etc/beamwarden.conf` (find it with `iw dev`).
4. **Teach it your normal** (the important step):
   ```
   beamwarden calibrate      # 2 min; use the network normally, no attack
   ```
   It learns *this* network's baseline retry/PER. Nothing hard-coded to the lab.
5. **Protect**: `/etc/init.d/beamwarden enable && /etc/init.d/beamwarden start`
6. **Watch**: `logread -e beamwarden -f`
   ```
   ALERT beamforming-attack: retry=0.52 (th 0.47) per=0.31 (th 0.26) ...
   ```
   Optional `/etc/beamwarden/on_alert` hook (args: `retry per`) for LED/Telegram/quarantine.

## How it detects — adapter-free, and why that works on any router

A forged-BFI attack misdirects the AP's beam, so the victim can't ACK → **the AP
retransmits** → its own **`tx retries` / `tx failed` (PER)** climb, and MCS/throughput
sag. Those are all in `iw station dump` — the router's *own* counters. No need to see
the forged frames themselves (that would need monitor mode, which many routers lack).

**Self-calibrating & portable:** `calibrate` learns this network's baseline; `watch`
alerts on a sustained spike *above* it (default ×1.5). Because it's **relative to the
deployed network's own normal**, one build works on a quiet home or a busy hall.

## The ML engine (OBJ3) — train offline, deploy distilled

`tools/train_telemetry.py` trains a **RandomForest** on **self-calibrated relative
features** (ratio + z-score vs each network's baseline: retry, PER, RSSI, throughput)
and evaluates it **leave-one-run-out** (generalisation to an unseen capture).
Measured on 3 real runs: **71.8%** leave-one-run-out (clears OBJ3 ≥55%). The forest's
decision is **distilled to the calibrated thresholds** this package runs — train
complex offline, deploy a cheap rule on the router.

## Honest limits (do not over-claim at viva)
- **Covert-attack weakness.** Detection reads the attack's *effect* (link degradation).
  When the attack is fully covert on a strong link, telemetry barely moves and detection
  weakens — the cross-run folds ranged **[100%, 39%, 77%]**. Catching the forged frames
  directly would fix this but needs monitor mode, which isn't portable. Documented tradeoff.
- **Cross-condition data.** The 71.8% is from 3 runs on one rig. More captures across
  distance/channel/load/hardware are the outstanding rigor work.
- v0.1 is **detect + alert**; active response is a hook. Per-client baselines are future work.
