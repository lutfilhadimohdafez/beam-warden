# BeamCraft Attack — Context & Detection Mapping

Reference: Xu, He, Li, Hu, Chen, Xiao, Luo. *"Beamforming made Malicious: Manipulating Wi-Fi
Traffic via Beamforming Feedback Forgery."* ACM MobiCom '24. Artifact: `github.com/Dxploto/BeamCraft_AE`
(vendored here as `BeamCraft_AE/`). Local PDF: `beamcraft_attack (1).pdf`.

Purpose: ground the Beam-Warden detection features in what the paper actually attacks and measures.
**Testbed alignment:** the paper uses the *same* hardware we have — Alfa AWUS036ACM (monitor+inject),
Raspberry Pi 4 (attacker host), `iperf3` for throughput, commodity Wi-Fi APs (Xiaomi). Our GN630v
plays the AP/victim-sensor role.

---

## 1. What the attack is (and is NOT)

BeamCraft is an **availability / traffic-manipulation attack**, not a confidentiality attack.
It forges the clear-text **Beamforming Feedback Information (BFI)** a client sends to the AP, so the
AP steers its beam using *wrong* channel info. Two goals:

- **Traffic disruption** — beam the victim's data into a *null* (wrong direction) → victim throughput collapses (~80% drop).
- **Traffic plunder** — forge the victim's BFI to copy the attacker's channel direction (MU-MIMO) → AP can't separate them → attacker steals the victim's airtime share (+17–20% attacker, −40% victim).

Neither mode hands the attacker readable data — see §5.

## 2. The channel-sounding handshake + the "retry" forgery

Normal beamforming needs a sounding handshake; the attacker sniffs it and injects a forged BFI
flagged as a retransmission so it overrides the genuine feedback regardless of arrival order.

```
   AP                          VICTIM (real user)         ATTACKER (Alfa: monitor + inject)
   |                                |                              |
   |--- NDP Announcement (token,seq=42) --->                      |  << sniffs token+seq off the air
   |                                |----------------------------->|
   |--- NDP (sounding pilots) ----->|                             |
   |                                |  measures channel (CSI)     |  forges fake feedback matrix,
   |                                |  builds feedback matrix V    |  spoofs VICTIM MAC,
   |                                |                             |  reuses token, seq=42, RETRY=1
   |<-- genuine BFI (seq=42) -------|                             |
   |<========= FORGED BFI (seq=42, RETRY=1) ======================|
   |
   |  AP already saw seq=42; a plain duplicate would be dropped as stale.
   |  The RETRY bit says "this is a re-send of that frame" -> AP ACCEPTS it
   |  and the forged matrix OVERWRITES the genuine one.
   |
   |==== AP now beamforms DATA using the FORGED matrix ====>  wrong direction
```

The retry bit is essential: the forged BFI arrives *after* the genuine one, so without `RETRY=1`
it would be discarded as a duplicate. Setting it makes the forgery win every sounding cycle.
**Side effect (detection gold):** this inflates the AP's retransmission / PER counters.

## 3. Beam geometry

**Traffic disruption (SU-MIMO)** — forged matrix in the nullspace of the real channel:

```
   NORMAL:   AP ~~~~~~~~~~~~~~~~~>  [VICTIM]      strong signal, full throughput

   ATTACK:   AP ~~~~~~\
                       \~~~~~~~>  (empty air / null)      [VICTIM] <- ~0 signal
                                                          throughput collapses (~80% drop)
```

**Traffic plunder (MU-MIMO)** — forge victim BFI to copy the attacker's direction:

```
   AP thinks VICTIM and ATTACKER share one spot -> can't separate them
   -> shared airtime/power handed to the ATTACKER (beneficiary)

   ATTACKER throughput  +17..20%        VICTIM throughput  -40%
```

Plunder preconditions: AP in **MU-MIMO** (`mu_bf=1` — GN630v qualifies), attacker needs **two NICs**
(monitor+inject *and* a beneficiary client), gain bounded and rises with channel correlation `|rho|`.

## 4. Metrics the paper measured

| Metric | Definition | Reported result |
|---|---|---|
| **Throughput (Mbps)** | measured with **iperf3**, AP<->users | disruption avg 112.9 -> 21.3 Mbps (2-ant) |
| **Reduction rate** | `(tN - tA)/tN`, victim drop % | ~80.4% avg (up to 88% at distance) |
| **Increase rate** | `(tA - tN)/tN`, beneficiary gain % | +16.9..19.6% (plunder) |
| Video QoE | rebuffering % | 0% -> **78%** under attack |
| Game QoE | client-server latency | 13.7 ms -> **55.1 ms** |
| Decoding probability | forged BFI decoded at AP vs victim | 100% @AP / **0% @victim** (covertness) |
| Forge latency | decompress+forge+compress vs sounding interval | ~1.9 ms << 43.7 ms |

**How they justify "attack is ongoing":** time-series throughput with a clean step-down at the
injection instant (Fig 4, attack starts t=50s), quantified by reduction rate, and QoE collapse.
Crucially, **BeamCraft is covert to the victim by design** (forged BFI undecodable at victim,
spoofed MAC, low exposure). The paper builds **no detector** — §6.2 only sketches prevention
(BFI encryption, channel-reciprocity verification, pilot randomization). **That gap is Beam-Warden.**

## 5. Encryption / interception clarification

- Beamforming is a **PHY-layer** technique — it only shapes *where RF energy goes* in space.
- **WPA2/WPA3 (AES-CCMP/GCMP) encryption is link-layer and untouched by beamforming.**
- Therefore the attack **never yields readable data** — disruption sends the beam to a null;
  plunder steals airtime. Even the *cited* (not implemented) selective-eavesdropping cousin
  [refs 56,57] only improves the attacker's SNR on **ciphertext** — you still need the session key.
- Conclusion: BeamCraft threatens **availability**, not confidentiality. Beam-Warden detects it by
  the degradation footprint, not by anyone reading diverted plaintext.

## 6. Detection signatures -> GN630v telemetry (verified fields)

The attack leaves fingerprints on the **AP's own telemetry** even while invisible to the victim.
Fields below are from `iwpriv <if> stat` on the GN630v (see `docs/hardware/gn630v-uart-recon.md`).

| BeamCraft artifact | GN630v telemetry field | Feature |
|---|---|---|
| Throughput reduction at injection | `Packets/Bytes Sent+Received` (diff) / iperf3 | goodput drop |
| Beam misdirected -> victim SNR/MCS drops | `Rssi:` (per-chain x4) + `Last TX Rate NSSx_MCSy` | SNR, MCS |
| Forged BFI flagged `RETRY=1` | `Tx fail count ... PER` (retransmit/PER counters) | retry/PER spike |
| MU->SU mode flapping (AP misreads forged low-corr BFIs, Fig 15a) | radio mode (driver log / stat) | mode instability |
| CSI-in-pilot vs reported compressed-CSI mismatch (§6.2) | packet-level (Alfa side) | (out-of-band feature) |

The retry-flag mechanism is the strongest physics-grounded feature: BeamCraft *must* set the retry
bit, which directly spikes the AP's retransmission/PER counters we already read live.

### 6a. Per-STA divergence — a plunder-specific fingerprint

Disruption and plunder look different in **per-station** telemetry, and that difference discriminates
the two attack classes:

- **Disruption:** the victim's stream is nulled -> victim MCS/SNR/throughput crater, and **no client gains.**
  The signature is one-sided degradation.
- **Plunder:** the AP stops nulling interference toward the victim, so within the *same sounding cycle*
  the **beneficiary's MCS/SNR climbs while the victim's craters.** The signature is a **simultaneous
  opposite-direction divergence** between two associated stations.

```
   sounding cycle t:      MCS / SNR
     BENEFICIARY (attacker)   ^  climbs (interference-free, +throughput)
     VICTIM                   v  craters (misdirected stream, SINR ~0)
```

To observe this the collector must read **per-STA** stats, not just per-BSS `stat`. On the GN630v that
means `iwpriv <if> show stainfo` / `get_mac_table`, whose output lands in **dmesg / the kernel ring
buffer, not stdout** (see recon doc) — so the agent issues the command then reads `dmesg`/`/dev/kmsg`.
Per-BSS `stat` alone catches disruption (aggregate degradation) but can miss plunder, since one client
rising and one falling can partially cancel in the aggregate. **Per-STA divergence is therefore the
feature that separates plunder from disruption** and should be in the labelled dataset for Objective 3.

## 7. How the forged BFI matrix is built (attack side)

The BFI carries a **compressed feedback matrix V** (quantized Givens-rotation angles phi/psi)
plus an **average SNR** per stream. BeamCraft modifies the *matrix*, not the SNR (forging SNR alone
barely moves traffic — paper Fig 4). This all runs on the **Alfa NIC** (monitor+inject); the code is
`BeamCraft_AE/main_su.cpp` (disruption) and `main_mu.cpp` (plunder).

```
  1. SNIFF        Alfa (monitor) captures a genuine BFI action frame off-air
        |
        v
  2. DECOMPRESS   BFI Givens angles (phi, psi)  -->  feedback matrix V  (Mt x Mr)
        |                                            + avg SNR  (left untouched)
        v
  3. FORGE MATRIX   compute V^f from V, dialed by rho in [0,1]:
        |             disruption:  V^f = sqrt(1 - rho^2) * V_perp  +  rho * V
        |                          V_perp is orthogonal to V (Gram-Schmidt / nullspace)
        |                          rho = 1 -> genuine (no attack);  rho -> 0 -> beam into a null
        |             plunder:     V^f made orthogonal to the BENEFICIARY's channel
        |                          -> AP stops nulling interference -> beneficiary SINR jumps
        v
  4. RECOMPRESS   V^f --> Givens angles --> repack into a BFI frame
        |            spoof VICTIM MAC, reuse dialog token + seq, set RETRY = 1
        v
  5. INJECT       Alfa transmits forged BFI --> AP accepts it (retry) over the genuine one
                  --> AP beamforms the victim's data the wrong way
```

**The one knob is `rho`** (`rho^f` in the paper): the correlation between the forged and genuine
matrix. `rho = 1` is a no-op; `rho -> 0` is maximum misdirection. Sweeping `rho` dials attack
strength (reduction rate rises as `rho` falls — paper Fig 11d), which is how the **attack class**
gets graded intensities for the dataset. In our testbed the GN630v is the AP; the degradation this
forgery causes is exactly what `tools/gn630v_telemetry.py --label attack` records.
