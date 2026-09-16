# Beam Warden — Beamforming (BFI) Spoofing Attack & Detection

**Final Year Project**

Modern Wi-Fi (802.11n/ac/ax/be) steers signal toward each client using
**beamforming**. To do it, every client tells the access point how to aim — it
sends **Beamforming Feedback Information (BFI)**, a compressed description of the
wireless channel. Critically, **BFI is transmitted in cleartext with no
authentication or integrity protection — even under WPA3/PMF.** An attacker with
a commodity Wi-Fi adapter can capture a victim's BFI, forge a malicious version,
and inject it as if it came from the victim — hijacking the AP's beam and cutting
the victim's throughput by up to **83%** (the *BeamCraft* attack).

**Beam Warden** (1) replicates that attack against real hardware, and (2) detects
it from router PHY telemetry using an unsupervised ML model (Isolation Forest) —
without touching the Wi-Fi protocol itself.

---

## Status at a glance

| # | Objective | Target | Status |
|---|-----------|--------|--------|
| 1 | Replicate a forged-BFI attack | ≥51% success | 🟢 **injection proven 30/30 on real target**; forge step pending HE port (see §6) |
| 2 | Automate PHY telemetry | ≥10 samples, ≥15% variance | 🟢 **live** — 150-sample normal dataset + live dashboard |
| 3 | ML anomaly detection | ≥55% accuracy | 🟡 Isolation Forest built + wired; **BFI→CSI feature pipeline validated** (V unitary 1e-16) and detectable on synthetic attack (98.8%); real-world accuracy pending Obj-1 attack data from a 4×4 AP |

**Proven on hardware this cycle:** the attacker (Alfa AWUS036ACM) injects crafted
802.11 frames onto the target's channel (30/30 ACKs); the target (Skyworth GN630v,
MediaTek MT7916) emits real beamforming feedback we capture live; that feedback
is **802.11ax (HE)**, which pins down the exact remaining work (§6).

---

## 1. What beamforming is (and why BFI exists)

To transmit to a client, the AP (the *beamformer*) shapes its antenna signals so
they add up **in phase** at the client — a focused beam instead of a
broadcast. To know how to aim, it needs the **channel** `H` between its antennas
and the client's. The client (the *beamformee*) measures `H` and feeds back the
optimal steering matrix `V`. This exchange is **channel sounding**:

```
        (1) Null Data Packet Announcement + NDP (known training fields)
   AP  ───────────────────────────────────────────────────────────────►  CLIENT
 (beamformer)                                                        (beamformee)
        │                                                                 │
        │                                    (2) estimate channel H,      │
        │                                        SVD → steering matrix V, │
        │                                        COMPRESS V → angles φ,ψ  │
        │                                                                 │
   AP  ◄───────────────────────────────────────────────────────────────  CLIENT
        (3) Compressed Beamforming Report  =  the BFI  (cleartext!)
        │
        │  (4) AP rebuilds V from the angles, pre-codes the next
        ▼      downlink transmission → beam aimed at the client
```

The report in step 3 is what an attacker sniffs and forges.

---

## 2. Beamforming across Wi-Fi versions

The **feedback mechanism is the same family** across generations — only the
parameters change. This is *why a single, parametrized decoder works everywhere.*

| Standard | Wi-Fi | Beamforming | Data subcarriers `Nsc` (20/40/80/160 MHz) | SU angles `b_φ`/`b_ψ` | MU angles `b_φ`/`b_ψ` | Report container |
|---|---|---|---|---|---|---|
| 802.11n  | 4 | optional (rarely deployed) | 56 / 114 / – / – | — | — | HT (uncommon) |
| 802.11ac | 5 | **explicit SU + MU (VHT)** | 52 / 108 / 234 / 468 | 6 / 4 | 9 / 7 | **VHT** MIMO Control |
| 802.11ax | 6/6E | **explicit SU+MU (HE)**, trigger-based | 242 / 484 / **996** / 1992 (RU-grouped) | 6 / 4 | 9 / 7 | **HE** MIMO Control |
| 802.11be | 7 | explicit (EHT), up to 320 MHz | up to 4×996 | 6 / 4 | 9 / 7 | **EHT** MIMO Control |

**Invariant across versions** (reusable in one decoder):
- the compression algorithm (Givens rotations, §3),
- the **angle codebook bit-widths** — SU = `φ:6, ψ:4`; MU = `φ:9, ψ:7`
  (a function of SU/MU, **not** of the Wi-Fi generation),
- the **order** of angles for a given antenna geometry `Nr×Nc` (§3, Table).

**Changes across versions** (what a port must re-parametrize):
- **`Nsc`** — the subcarrier count (bandwidth-dependent, and HE/EHT apply
  *sub-carrier grouping* `Ng` ∈ {4,16} to shrink it),
- the **frame container** — VHT vs HE vs EHT MIMO-Control field layout & offset,
- SU-vs-MU selection (sets the bit-widths above).

---

## 3. The math: how BFI is decoded

**Step A — channel to steering matrix (at the beamformee).** For each subcarrier
`k`, the estimated channel `Hₖ` (size `M×N`, M=tx antennas, N=rx antennas) is
decomposed by SVD:

```
    Hₖᵀ = Uₖ · Sₖ · Zₖᴴ          →     Vₖ = first Nss columns of Zₖ   (M × Nss)
```

`Vₖ` is the steering matrix the AP needs. Sending it as raw complex numbers is
expensive, so 802.11 **compresses** it into real **angles**.

**Step B — compress V into angles (Givens rotations).** `Vₖ` is factored into a
product of diagonal phase matrices `Dₖ,ᵢ` (carrying **φ** angles) and Givens
rotation matrices `Gₖ,ℓ,ᵢ` (carrying **ψ** angles):

```
            ┌ min(Nss, M−1)          M                    ┐
    Ṽₖ  =   │      ∏        ( Dₖ,ᵢ ·  ∏  Gₖ,ℓ,ᵢᵀ )        │ · I(M×Nss)
            └     i=1               ℓ=i+1                  ┘

    Dₖ,ᵢ = diag(1,…, e^{jφ}, …, 1)     Gₖ,ℓ,ᵢ = rotation by ψ in the (i,ℓ) plane
```

Only the `φ` and `ψ` angles are transmitted — the beamformer reconstructs `Vₖ`
from them exactly (the last row of `Ṽ` is real by construction, so it's dropped).

**Step C — quantize the angles.** Each angle is packed into a fixed number of bits
(`b_φ` for φ, `b_ψ = b_φ − 2` for ψ):

```
    φ = π · ( 1/2^(b_φ−1) + q_φ / 2^(b_φ) )        q_φ ∈ {0 … 2^(b_φ)−1}
    ψ =     ( 1/2^(b_ψ+2) + q_ψ / 2^(b_ψ+1) )      q_ψ ∈ {0 … 2^(b_ψ)−1}
```

**Number & order of angles** depend only on the antenna geometry `Nr×Nc`:

| Nr×Nc | #angles | Order (as packed in the report) |
|---|---|---|
| 2×1 | 2  | φ11, ψ21 |
| 2×2 | 2  | φ11, ψ21 |
| 3×2 | 6  | φ11, φ21, ψ21, ψ31, φ22, ψ32 |
| 4×2 | 10 | φ11, φ21, φ31, ψ21, ψ31, ψ41, φ22, φ32, ψ32, ψ42 |
| 4×4 | 12 | φ11, φ21, φ31, ψ21, ψ31, ψ41, φ22, φ32, ψ32, ψ42, φ33, ψ43 |

**Decoding (reverse of B+C)** — what our tooling and the attack do:

```
   raw BFI bytes ─► bit-unpack (b_φ, b_ψ) ─► angles φ,ψ  ─►  rebuild Dₖ,ᵢ, Gₖ,ℓ,ᵢ
                                                          ─►  Vₖ = ∏ D·Gᵀ   (per subcarrier)
```

This is the algorithm implemented in `BeamCraft_AE/main_su.cpp :: re_beamforming()`
(VHT) and, identically, in the **Wi-BFI** reference (HE) — same rotations, only
`Nsc`, the bit-widths, and the frame offset differ per §2.

---

## 4. The attack: forging BFI (BeamCraft)

Because the AP blindly trusts the most recent report "from the victim", an
attacker who can hear a report and transmit can **substitute a malicious one**:

```
 ① sniff victim's compressed report ──► ② decode angles → rebuild TRUE Vₖ (§3)
                                                     │
                                                     ▼
 ④ inject forged report              ◄── ③ craft Wₖ  ⟂  Vₖ  (Gram–Schmidt on a
    (src MAC = victim, so the AP           random matrix), then blend:
    accepts it as the victim's)               Wₖ = √(1−α)·Vₖ + √α·Wₖ,orth
                                                     │
                                                     ▼
                              AP pre-codes with Wₖ instead of Vₖ →
                              energy steered AWAY from the victim →
                              victim SNR / throughput collapses
```

`α` (0…1) tunes the attack: `α=1` = fully orthogonal = maximum disruption;
`α=0` = honest feedback (no attack); `0<α<1` = a covert, partial degradation.
`main_su` = single-user **disruption**; the MU **plunder** variant (steer toward
the attacker) is future work.

**Why it works:** the report carries no signature and the attacker spoofs the
source MAC — nothing in 802.11 lets the AP tell a forged report from a real one.

---

## 5. System architecture (attack + detection)

```
 ┌──────────────┐   beamformed 5 GHz    ┌───────────────────────────┐
 │  VICTIM STA  │◄─────── downlink ─────►│  GN630v AP  (MT7916)      │
 │ (beamformee) │   ──BFI (cleartext)──► │  SU/MU beamforming, ch48  │
 └──────────────┘                        └────────────┬──────────────┘
        ▲                                              │ iwpriv rai1 stat
        ╎ ① sniff BFI  ② forge  ③ inject               │ (telnet, 2 s poll)
        ╎  (forged report, spoofed as victim)          ▼
 ┌──────┴───────────────────┐              ┌───────────────────────────┐
 │ ATTACKER  (Alfa MT7921)  │              │  TELEMETRY + ML (this PC) │
 │ monitor+inject on mon0   │              │  collector → dashboard    │
 │ main_su (BeamCraft SU)   │              │  → Isolation Forest → 🚨  │
 └──────────────────────────┘              └───────────────────────────┘
```

---

## 6. Gate 2 finding — the target speaks HE, not VHT

First live capture (`data/bfi_he_capture.pcap`): **171 compressed beamforming
reports** from the victim → GN630v, **action category 30 = HE (802.11ax)**,
~277-byte frames, on channel 48. See `docs/gate2-bfi-findings.md`.

**Consequence:** the reference `main_su.cpp` decodes a **VHT** report; the target
emits **HE**. Per §2/§3 the *algorithm* is identical — the port only re-parametrizes:

| Parameter | `main_su` (VHT 20 MHz) | GN630v (HE 80 MHz) | Action |
|---|---|---|---|
| Subcarriers `Nsc` | 52 | ~242 (grouped) | **change `NST` + Eigen dims** |
| SU angle bits `φ/ψ` | 6 / 4 | 6 / 4 (if SU) | keep — **confirm SU vs MU** |
| Angle order (`Nr×Nc`) | 4×2 → 10 | read from HE MIMO Control | confirm geometry |
| Report offset | `len_head+7` (VHT) | HE: 1+1+5+2 hdr fields | **recompute** |

**Fast path:** [Wi-BFI](https://github.com/kfoysalhaque/Wi-BFI) (open-source, pip)
already parses HE BFAs — feed it our pcap to read the exact `Nsc/Nr/Nc/grouping`,
then plug those into `main_su`. Turns "decode HE from scratch" into "set 4 values."

---

## 7. Detection pipeline (Objective 2 → 3)

```
   GN630v AP (victim + sensor)
        │  iwpriv rai1 stat   (poll every 2 s, over telnet)
        ▼
   RAW COUNTERS (cumulative)          INSTANT GAUGES
     Tx success / Tx fail               Rssi0..3  (per-chain → SNR)
     Rx success / Rx CRC                Last TX/RX Rate: NSS, MCS, BW, GI, HE-mode
     Packets / Bytes                    Temperature
        │  compute_deltas() over dt
        ▼
   FEATURES per 2 s window                         behaviour under attack
     throughput_tx/rx_mbps  ── goodput ──────────────────► collapses
     retry_rate = txfail/(txsucc+txfail) ────────────────► spikes
     tx_per / rx_per ── packet error rate ───────────────► spikes
     rssi0..3 ── per-chain SNR ──────────────────────────► shifts (beam misaimed)
     tx_mcs / tx_nss ── modulation ──────────────────────► drops
        │  --label normal | attack
        ▼
   CSV dataset  →  Isolation Forest (train on NORMAL only)  →  anomaly score  →  🚨
```

**Why Isolation Forest?** We reliably have only *normal* traffic to learn from;
attacks are rare and varied. Unsupervised anomaly detection trains on normal and
flags whatever "isolates" too easily — catching an attack it never trained on.

### 7.1 How the ML engine actually works

The engine **never learns what an attack looks like** — it learns only what
*normal* looks like, then flags anything that does not fit (one-class / unsupervised
anomaly detection). It is two small pieces, not a monolith:

| Stage | Code | What happens |
|---|---|---|
| Train | `tools/train_detector.py` | `StandardScaler` learns the mean/spread of normal, then `IsolationForest(200 trees, contamination 0.02)` learns the *shape/density* of normal. Saved as `models/detector.joblib` = `{model, scaler, features}`. |
| Score | `tools/dashboard.py::score_sample()` | Each live sample → same scaler → `decision_function` (continuous, + = normal, − = anomaly) + `predict` (+1 normal / −1 attack badge). |

**The trick (Isolation Forest):** build 200 trees, each repeatedly splitting on a
*random feature* at a *random value* until every point is isolated. Anomalies sit
in sparse regions, so they isolate in **few** splits (short path); normal points
are buried in a dense crowd and take **many** splits. Short average path length =
anomalous. `contamination=0.02` sets the +1/−1 threshold (≈2% training FPR). The
same `scaler` + `features` travel inside the `.joblib` from train to score, so a
live sample is judged against normal on identical footing.

### 7.2 Two feature sources

The detector is fed by **two independent vantages** of the same link:

```
  A. MAC counters   telnet → GN630v → iwpriv rai1 stat   (the §7 pipeline)
     throughput, retry_rate, tx/rx_per, rssi0..3, tx_mcs, tx_nss
     → sees the AFTERMATH (throughput drop, PER spike)

  B. BFI / CSI      Alfa in MONITOR mode → sniffs the air (OFF-AIR)
     the victim's HE Compressed Beamforming Report, decoded to Givens angles
     → sees the FORGERY ITSELF (the exact frame BeamCraft manipulates)
```

**BFI/CSI pipeline (`tools/bfi_features.py`):** decodes captured HE compressed
beamforming reports (φ/ψ Givens angles, ported and V-unitarity-validated from
`main_su.cpp`) into per-frame CSI-style features:

| Feature | Meaning |
|---|---|
| `bfi_phi_mean`, `bfi_psi_mean` | phase / amplitude geometry of the steering matrix |
| `bfi_angle_var` | CSI-matrix variance |
| `bfi_subcarrier_var` | variance across subcarriers = multipath / frequency selectivity |
| `bfi_phi/psi_temporal_var` | frame-to-frame channel stability (rolling window) |

Because BFI is captured **off-air**, these CSI features work on the **current 2×2
rig today** — decoupling the normal-side dataset from the 4×4 hardware blocker.
Attack-side CSI needs the 4×4 AP, or the synthetic generator
(`tools/make_synthetic_bfi_attack.py`, 98.8% detection / 2.3% FP) for pipeline
validation in the meantime. *(Raw per-subcarrier CSI would need PicoScenes + an
AX210 + Ubuntu — see Future Work.)*

---

## 8. Tools

| Tool | What it does |
|---|---|
| `tools/gn630v_telemetry.py` | telnet → `iwpriv rai1 stat` every 2 s → CSV (RSSI/MCS/throughput/retry), labelled `normal`/`attack`. Backed by `gn630v_telnet.py` (stdlib raw-socket telnet). |
| `tools/dashboard.py` + `dashboard.html` | **live** telemetry web dashboard **+ Command Center** (Starlette + WebSocket + Chart.js). `--mode live` polls the router; `--mode replay` streams a CSV (demo-safe, no router); `--bfi-iface` folds live off-air CSI features in. Hosts the button-driven task runner (see §9). Run via `.venv/bin/python`. See `docs/dashboard.md`. |
| `tools/tasks.py` | Command Center task registry — the single source of truth for the CLI tasks the dashboard can run (predefined only; no arbitrary shell). |
| `tools/bfi_features.py` | decode captured HE compressed beamforming reports → per-frame CSI features CSV (`--pcap`/`--out`); also `stream_features()` for live off-air decode. V-unitarity validated. |
| `tools/make_synthetic_bfi_attack.py` | perturb real normal BFI → labelled synthetic *attack* CSI features for detector validation (`--severity`). 98.8% detection / 2.3% FP. |
| `tools/bfi_capture.py` | capture/inspect VHT/HE beamforming action frames (tshark) → decode `Nc/Nr/width` and compare vs assumptions. *(live mode note: capture raw with `tshark -w`, analyse with `pcap` mode.)* |
| `tools/attack_harness.py` | iperf3 baseline-vs-attack downlink throughput → drop % + ≥51% success gate → JSON. |
| `tools/attack_gui.py` | Tkinter panel (legacy; superseded by the Command Center): scan NIC, monitor mode, patch+compile+run `main_su` via one `pkexec`. |
| `BeamCraft_AE/main_su.cpp` | BeamCraft SU attack (configurable: `--iface/--ap/--victim/--alpha/--type/--offset`, `NR/NC/NST` defines). |

---

## 9. Command Center (Mission Control) — how to use

The dashboard doubles as a **Command Center**: a browser panel that runs the
project's CLI tools via buttons and streams their live output into a read-only
console — so you drive captures, training, and the attack without leaving the page.

**Start it** (localhost only — the task runner refuses non-loopback requests):

```bash
.venv/bin/python tools/dashboard.py --mode live          # live telemetry + Command Center
# or, demo-safe with no router:
.venv/bin/python tools/dashboard.py --mode replay --csv data/synthetic_attack.csv
# add live off-air CSI features:
.venv/bin/python tools/dashboard.py --mode live --bfi-iface mon0
```
Open **http://localhost:8080**.

**Layout:**

```
  ┌── BEAM // WARDEN — Command Center ─────────────────────────────┐
  │  shared params: [mon iface] [gn630v host] [channel] [duration]  │
  │  [Setup Monitor] [Scan Adapters] [Capture BFI] [Start Attack]   │  ← task buttons
  │  [Train Detector] [Gen Synthetic] [Decode Features] [Stop]      │
  │  status chips:  ●running / ✓done / ✗failed   per task           │
  │  ┌── LIVE CONSOLE (read-only, stdout+stderr) ────────────────┐  │
  │  │ $ tshark -i mon0 -w results/sessions/<run>_air.pcap        │  │
  │  │ 171 HE frames captured …                                   │  │
  │  └────────────────────────────────────────────────────────────┘ │
  │  ── telemetry tiles · charts · ML anomaly · CSI panel · replay ── │
  └────────────────────────────────────────────────────────────────┘
```

**Tasks** (defined in `tools/tasks.py`): `setup_monitor`, `scan_adapters`,
`capture_bfi`, `start_attack`, `train_detector`, `gen_synthetic`,
`decode_features`. Fill the shared params at the top; each button resolves them
into the underlying CLI command and streams the result to the console. Privileged
tasks (monitor mode, capture, attack) run via `pkexec`; **Stop** kills a running
task (root-kill for privileged ones).

**How it works:** `POST /run/{name}` spawns the task as a subprocess and streams
`{type:"log"}` lines over the existing WebSocket; `{type:"status"}` drives the
chips. `GET /tasks` returns the registry. It is a **predefined registry only** —
no arbitrary shell — and every endpoint rejects non-loopback callers.

**Concurrent capture:** because the Alfa runs monitor mode and the GN630v is
polled over telnet (different NICs), you can **Capture BFI** while live telemetry
streams — just keep the GN630v reachable over ethernet/the Intel NIC (the Alfa is
busy in monitor mode).

---

## 10. Datasets

| File | Class | Conditions |
|---|---|---|
| `data/normal_iperf.csv` | **normal** | legit traffic + live iperf3 load, **no attack** (~98 Mbps, PER ~15%, retry ~0.13, MCS 3–4, HE_SU BW80) |
| `data/bfi_he_capture.pcap` | — | 171 live HE beamforming reports (Gate-2 evidence) |
| `data/bfi_features.csv` | **normal** | 171 rows of CSI features decoded from the BFI capture (`bfi_features.py`) |
| `data/bfi_synthetic_attack.csv` | normal + **attack** | 171 real-normal + 171 synthetic-attack CSI rows, labelled (`make_synthetic_bfi_attack.py`); 98.8% detectable |
| _(next)_ `data/attack_*.csv` | **attack** | same link while forged BFI is injected (needs the 4×4 AP) |

---

## 11. Hardware & stack

| Role | Device / tech |
|---|---|
| Target AP / telemetry sensor | Skyworth **GN630v** ONT — MediaTek **MT7916**, 5 GHz ch48, SU/MU HE beamforming |
| Attacker NIC | Alfa **AWUS036ACM** — MediaTek **MT7921** (`mt76`), monitor + injection |
| Attack code | C++ (`main_su`), libpcap, Eigen3; aircrack-ng for injection verification |
| Telemetry + ML | Python 3, Starlette/uvicorn (dashboard), scikit-learn (Isolation Forest) |
| Detection host (target) | OpenWrt 24.10+ LuCI + Telegram alerts *(deployment target)* |

---

## 12. Repo layout

- `docs/` — progress report, challenges logs (`challenges.md`, `challenges-2026-09-17.md`), Gate-2 findings, dashboard guide, ML-engine notes, hardware recon.
- `tools/` — our scripts (tracked).
- `data/` — datasets + captures.
- `BeamCraft_AE/`, `BFM-tool/` — external reference repos (gitignored). `BeamCraft_AE` = the VHT attack; `BFM-tool` = raw BFI capture.
- `Wi-BFI-WFI6.pdf` — the HE BFI extraction reference (Wi-BFI, WiNTECH '23).
- `*.pdf` — proposal, BeamCraft paper.

---

## Team

Muhammad Lutfil Hadi bin Mohd Hafez · a teammate ·
a teammate · a teammate
Supervisor: the supervisor

## References

- **BeamCraft** (2026) — the forged-BFI attack this project replicates.
- **Wi-BFI** (Haque, Meneghello, Restuccia; ACM WiNTECH '23) — extracting 802.11ac/ax
  BFI from commodity devices; the HE decoder reference (`Wi-BFI-WFI6.pdf`).
- IEEE 802.11-2020 §21 (VHT) / §27 (HE) — compressed beamforming report format.
- Full related work (LeakyBeam, KIT KASTEL) in the proposal PDF §15.
