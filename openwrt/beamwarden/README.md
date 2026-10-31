# Beam-Warden OpenWrt package (`beamwarden.ipk`)

Standalone on-router detector for **beamforming-feedback injection** (BeamCraft-style)
attacks. This is the OBJ3 deliverable: the anomaly-detection engine as a self-contained
OpenWrt package — no laptop, no Python, no scikit-learn, no cloud.

## How a defender uses it (step by step)

1. **Build it** (once, on a dev machine with the OpenWrt SDK for your target):
   ```
   cp -r openwrt/beamwarden <sdk>/package/beamwarden
   cd <sdk> && make package/beamwarden/compile V=s
   # -> bin/packages/<arch>/.../beamwarden_0.1-1_all.ipk
   ```
2. **Install it** on the router:
   ```
   scp beamwarden_*.ipk root@192.168.1.1:/tmp/
   ssh root@192.168.1.1 'opkg install /tmp/beamwarden_*.ipk'
   ```
3. **Point it at your AP radio** — edit `/etc/beamwarden.conf`, set `AP_IF` to your
   5 GHz BSS interface (e.g. `wlan0`). Leave `MAC=` empty to watch every client.
4. **Teach it your normal** (this is the important step):
   ```
   beamwarden calibrate      # runs 2 min; use the network normally meanwhile
   ```
   It measures the peak legitimate BFI frame rate on *your* network and writes an
   alert ceiling above it. Nothing is hard-coded to the lab.
5. **Turn on protection:**
   ```
   /etc/init.d/beamwarden enable
   /etc/init.d/beamwarden start
   ```
6. **Watch for alerts:**
   ```
   logread -e beamwarden -f
   # ALERT beamforming-injection: 38 BFI/2s (ceil 28), retry 50% (th 25%) ...
   ```
   Optional: drop an executable `/etc/beamwarden/on_alert` (args: `bfi ceil ratio%`)
   to flash an LED, push a Telegram message, or quarantine the client.

## How it actually detects — and "how does it know what the attack looks like?"

It does **not** carry a trained model of "attack vs not" from the lab. The knowledge
is **physical**, and it is re-learned per network:

- A beamforming-injection attack *must* put extra VHT compressed-beamforming frames
  (mgmt Action-No-Ack, subtype `0xe0`, category 21) on the air — that is literally
  what the attack is. You cannot inject forged feedback without raising the BFI rate.
- The forged re-injections carry the **RETRY** bit; legitimate sounding almost never
  does. So the retry-ratio of BFI frames jumps from ~0 to ~0.5.

`calibrate` learns the normal BFI-rate envelope for the deployed network; `watch`
raises an alert when a window exceeds that learned ceiling **or** the retry ratio
crosses the threshold. The lab's RandomForest (see `tools/bfi_features.py`) was how
we *found* that this boundary is clean and leak-safe (100% GroupKFold-by-phase); the
shipped engine is that boundary distilled to two physical thresholds that a MIPS
router can evaluate with `tcpdump`.

### Evidence the counting is real (validated offline, no rig)
- `tcpdump 'wlan[0]==0xe0 and wlan src <victim>'` counts **1381** frames — identical
  to tshark's `wlan.fixed.category_code==21` ground truth on the same capture.
- Over a real **heavy + bursty NORMAL** capture (no attack): peak 20 BFI/2s, retry
  ratio 0.00 → **0 / 33 windows tripped (0% false positive)**.
- Over the attack capture: 28–40 BFI/2s, retry ratio ~0.5 → every attack window flagged.

## Honest limits (do not over-claim at viva)
- **Capture capability on the AP:** v0.1 adds a monitor vif on the AP radio and
  counts received BFI there. Whether a given AP chipset surfaces its own received
  sounding frames in monitor mode is the one thing to confirm on first flash
  (`beamwarden status` + `beamwarden calibrate` should show non-zero counts). On
  mt7615/mt76 a parallel monitor vif is supported; validate counts are non-zero.
- **One capture, one normal condition** so far. The 0% FP number is from a single
  65 s normal capture. Multi-condition captures (distance/channel/load, real apps)
  are the outstanding rigor work before claiming it generalizes.
- v0.1 is **detect + alert**. Active response (quarantine/firewall) is a hook, not
  built in. Multi-client calibration (per-MAC baselines) is future work.
