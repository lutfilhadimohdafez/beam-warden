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
it from the attack's own **on-air forged-BFI signature** using an ML anomaly
detector — without touching the Wi-Fi protocol itself.

---

> 📖 **Just want to install and use it?** Jump to the
> **[User Guide](docs/user-guide.md)** — step-by-step, with screenshots.

## Contents

- [How it runs — two tiers](#how-it-runs--two-tiers) · the router detector vs. the dashboard
- [Status at a glance](#status-at-a-glance) · objective-by-objective, honest
- [1. What beamforming is (and why BFI exists)](#1-what-beamforming-is-and-why-bfi-exists)
- [2. Beamforming across Wi-Fi versions](#2-beamforming-across-wi-fi-versions)
- [3. The math: how BFI is decoded](#3-the-math-how-bfi-is-decoded)
- [4. The attack: forging BFI (BeamCraft)](#4-the-attack-forging-bfi-beamcraft)
- [5. System architecture (attack + detection)](#5-system-architecture-attack--detection)
- [6. Gate 2 finding — the target speaks HE, not VHT](#6-gate-2-finding--the-target-speaks-he-not-vht)
- [7. Detection pipeline (Objective 2 → 3)](#7-detection-pipeline-objective-2--3)
- [8. Tools](#8-tools)
- [9. Command Center (Mission Control) — how to use](#9-command-center-mission-control--how-to-use)
- [10. Datasets](#10-datasets)
- [11. Hardware & stack](#11-hardware--stack)
- [12. Repo layout](#12-repo-layout)
- [Team](#team) · [References](#references)

**Other docs:** [User Guide](docs/user-guide.md) · [Live demo runbook](docs/gui-live-demo.md) · [ML engine](docs/ml-engine.md) · [Independent audit](docs/audit-2026-11-01/review.md) · [Router package README](openwrt/beamwarden/README.md)

---

## How it runs — two tiers

Beam Warden is **two separate pieces**. Know which is which:

```
 TIER 1 — the ROUTER (the product)          TIER 2 — a SERVER/DESKTOP (optional)
 ┌───────────────────────────────┐  SSH /  ┌──────────────────────────────────┐
 │ the .ipk: a headless detector  │  web /  │ tools/dashboard.py (Python)       │
 │ • reads `iw station dump`       │ Telegram│ • live charts + ML verdict        │
 │ • scores with model.awk (ML)    │────────▶│ • Command Center (demo/attack rig)│
 │ • logs alerts + Telegram        │  hook   │ Runs on YOUR machine, NOT the     │
 │ ~1 MB RAM, ~0% CPU, no deps     │         │ router. Not needed to be protected│
 └───────────────────────────────┘         └──────────────────────────────────┘
```

- **The detector lives entirely on the router** (Tier 1). A defender installs the
  `.ipk`, calibrates, and gets **Telegram alerts + a JSONL audit log** — no desktop
  needed. It's featherweight (~1 MB RAM) because the RandomForest is compiled to a
  pure-`awk` tree-walk — zero ML runtime on the router.
- **The dashboard is an optional desktop app** (Tier 2) that SSHes in to *visualise*
  the same telemetry and drive the attack demo. Its on-screen verdict is an
  *estimate*; the **router's own watcher is the authority** that alerts.
- **Two "learnings":** the **model** (how the attack looks) is trained once by us and
  shipped fixed in the `.ipk`; the **baseline** (this network's normal) is what each
  user learns via `beamwarden calibrate`. Relative features bridge them, so one model
  works on any router.
- **NOC integration:** the router already logs alerts to **syslog** (point it at your
  NOC with one line) and to `ALERT_LOG` (a JSONL audit trail). A central
  collector/dashboard that aggregates many routers into one web UI is the planned
  next step (SQLite + webhook — see `docs/`).

**Quickstart (router / Tier 1):** `install .ipk` → set `AP_IF`/`MAC`/Telegram token in
`/etc/beamwarden.conf` → `beamwarden calibrate` (learn normal, ~2 min) →
`/etc/init.d/beamwarden enable && start`. Full steps + apk-router note in
[`openwrt/beamwarden/README.md`](openwrt/beamwarden/README.md).

**Quickstart (dashboard / Tier 2):** `.venv/bin/python tools/dashboard.py` →
`localhost:8080` → pick the router profile → Connect. Demo runbook:
[`docs/gui-live-demo.md`](docs/gui-live-demo.md).

---

## Status at a glance

| # | Objective | Target | Status |
|---|-----------|--------|--------|
| 1 | Replicate a forged-BFI attack | ≥51% success | 🟢 **DONE — 69.6% downlink drop** — live forged-BFI injection on the AC2100 (919 frames, no crash, 4×1 null-steer, forge matches validated math), baseline 36.2 → attack-settled 11.0 Mbps, retry 0.31→0.51, **RSSI 0 dB drift (confound-controlled)**. Lag-aware measure `tools/obj1_run.py` + auto power-sweep `tools/obj1_auto.py`; `data/obj1_*.csv` |
| 2 | Automate PHY telemetry | ≥10 samples, ≥15% variance | 🟢 **live** — SSH `station dump` capture + real datasets + live dashboard; attack moves retry **5.4×** and throughput **−36%** (≫15% variance) |
| 3 | ML anomaly detection | ≥55% accuracy | 🟢 **ACHIEVED — 100%** — BFI-storm anomaly detection on **real** data, leakage-safe GroupKFold (every fold 100%). *Within one condition*; cross-condition is honest future work. `tools/bfi_run.py` + `tools/bfi_features.py` |

**Update — 2026-11-02 (independent audit):**
- **Router Telegram alerting is live.** When `beamwarden watch` fires, the router
  itself POSTs an incident report to Telegram (no PC, no server) — mirroring
  `tools/attack_report.py`'s SECURITY INCIDENT REPORT: severity (HIGH/MEDIUM/INFO),
  the protected client (MAC+IP), AP BSSID/channel, impact (downlink drop %, retry
  ×normal, PER), a PHY-layer note and recommended response. Delivery is confirmed
  (the cooldown stamp is written **only** on Telegram `"ok":true`), and the token
  lives in config, never in code.
- **Detector verified on the live AC2100:** service running, `model.awk` + learned
  baseline in place, victim associated — the detection half is demo-ready.
- **Test suite 98/98 green** (retired two tests of deleted helpers; the Wi-Fi 6 HE
  decoder is preserved in git `@45f7ac0` for the HE port). Added a `--baselines`
  unit guard to `export_model.py` and an interval-v2 feature schema so capture,
  offline eval and the on-router watcher compute identical window features.
- **Independent audit added** ([`docs/audit-2026-11-01/review.md`](docs/audit-2026-11-01/review.md)):
  a read-only proposal-vs-evidence review. Honest standing — **OBJ2** is strongly
  supported; **OBJ1** still needs a *trial-based success rate* (distinct from the
  throughput-loss headline); **OBJ3** is packaged and reproduces **80.1%
  leave-one-run-out** on one rig, with a deployed on-router evaluation and a
  confirmatory multi-trial campaign (with sham controls) as the remaining
  acceptance work. The 🟢 marks above are engineering milestones, not yet
  closed acceptance criteria — see the audit for the exact closure checklist.

**Update — 2026-10-31:** The months-long "attack injects 0 / no BFI captured"
blocker was **degraded Alfa firmware** (`modprobe -r mt7921u; modprobe mt7921u`
restores VHT capture — now baked into the harness). With that fixed: forged-BFI
capture → forge → inject all work live (no laptop crash), **OBJ3 landed at 100%**
via the on-air BFI-storm signature (not the old throughput-telemetry route), and
a live detection panel was wired into the dashboard. The current rig geometry is
**4×1 (non-square → null-steer)** and the live-inject forge was corrected to match
the pcap-validated math. Prior Isolation-Forest / 11-telemetry work is superseded
— see [`docs/ml-engine.md`](docs/ml-engine.md).

**Proven on hardware this cycle:** the attacker (Alfa AWUS036ACM) injects crafted
802.11 frames onto the target's channel (30/30 ACKs); the target emits real
**802.11ax (HE)** beamforming feedback we capture live.

**Update — 2026-09-18:** the genuine **4×4** target is now the **Xiaomi AX3200**
(MediaTek MT7915, radio `wl0`, ch44/BW80). We captured its real 4×4 HE BFI
off-air (**56 frames, all `Nr=4 Nc=2 NANG=10`** → `data/bfi_ax3200_4x4*`) and
`main_su --pcap` validated the null-steer forge against it. The GN630v (2×2)
remains a valid victim/normal-traffic leg. The `rai1`/ch48/GN630v labels in the
diagrams below describe the earlier 2×2 dev rig; the live 4×4 target is the
AX3200 on `wl0`/ch44.

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

### 3.1 Decomposing a 2×2 matrix — Wi-Fi 5 (VHT) vs Wi-Fi 6 (HE), worked

> **Why 2×2 is the whole story for us.** `Nc` = number of spatial streams the AP
> steers = **columns of V**. A normal user device (phone/laptop) reports **Nc = 2**.
> We verified this against *every* captured frame in this repo: **587 / 587 BFI
> reports have `Nc = 2`** (`data/bfi_*features.csv`). Only `Nr` (the reporter's
> antenna count = **rows**) varies — `Nr = 2` for a 2-antenna client (→ **square
> 2×2**), `Nr = 4` only when a 4-antenna reporter sounds. So the target case is
> always `Nr = Nc = 2`: a **square, full-rank** feedback matrix.

**Consequence of squareness (`Nr = Nc`): there is no null space.** The columns of a
2×2 `V` already span the whole 2-D space, so you *cannot* build a vector orthogonal
to `V` (the Gram–Schmidt trick in §4 needs `Nr > Nc` to have empty directions to
aim into). The square-case forge is therefore a **rotation of V onto itself**, not a
null-steer — see the note at the end.

**The decompose is IDENTICAL for Wi-Fi 5 and Wi-Fi 6 at 2×2.** Same 2 angles, same
reconstruction. Only the *frame wrapper* differs. Side-by-side:

| | **Wi-Fi 5 — 802.11ac (VHT)** | **Wi-Fi 6 — 802.11ax (HE)** |
|---|---|---|
| Action frame | VHT Compressed Beamforming, **category 21** | HE Compressed Beamforming/CQI, **category 30** |
| MIMO Control field | **3 bytes** (24-bit) | **5 bytes** (40-bit) |
| `Nc Index` (→ `Nc = idx+1`) | bits **0–2** | bits **0–2** |
| `Nr Index` (→ `Nr = idx+1`) | bits **3–5** | bits **3–5** |
| Channel Width / BW | bits 6–7 (20/40/80/160) | bits 6–7 (20/40/80/160) |
| Grouping `Ng` | bits 8–9: `Ng ∈ {1,2,4}` | bit 8: `Ng ∈ {4,16}` |
| Codebook info | bit 10 | bit **9** |
| Feedback type (SU/MU) | bit 11 (**1 bit**: 0=SU,1=MU) | bits **10–11** (2 bits: 0=SU,1=MU,2=CQI) |
| Sounding dialog token | bits 16–21 | bits 30–35 |
| Report bytes follow at | after the 3-byte field | after the 5-byte field |
| **# angles for 2×2 (`NANG`)** | **2** (`φ₁₁`, `ψ₂₁`) | **2** (`φ₁₁`, `ψ₂₁`) |
| **Angle order** | `φ₁₁`, `ψ₂₁` | `φ₁₁`, `ψ₂₁` |
| **Bit-widths** (SU, codebook 0) | `b_φ = 4`, `b_ψ = 2` | `b_φ = 4`, `b_ψ = 2` |
| **Bit-widths** (SU, codebook 1) | `b_φ = 6`, `b_ψ = 4` | `b_φ = 6`, `b_ψ = 4` |
| **Bit-widths** (MU, codebook 0/1) | `7/5` · `9/7` | `7/5` · `9/7` |

> Field bit positions above are exactly what the repo's decoder reads — HE in
> `tools/bfi_features.py` (`nc=val&0x7`, `nr=(val>>3)&0x7`, `codebook=(val>>9)&1`,
> `feedback_type=(val>>10)&0x3`); bit-widths in `main_su.cpp :: get_bitwidths()`.

**Dequantize the 2 angles** (authoritative form, from `main_su.cpp`; `q` = the raw
integer read from the `b_φ`/`b_ψ` bit field):

```
    φ₁₁ = π · (2·q_φ + 1) / 2^(b_φ)          ∈ (0, 2π)
    ψ₂₁ = π · (2·q_ψ + 1) / 2^(b_ψ + 2)      ∈ (0, π/2)
```

**Reconstruct V (closed form for 2×2).** With `D = diag(e^{jφ₁₁}, 1)` and a single
Givens rotation `G₂₁(ψ₂₁)`, `Ṽ = D · G₂₁ᵀ · I₂ₓ₂` collapses to:

```
          ┌  e^{jφ₁₁}·cos ψ ,  − e^{jφ₁₁}·sin ψ  ┐
    V  =  │                                      │        (ψ ≡ ψ₂₁)
          └      sin ψ      ,        cos ψ        ┘
```

The second row is real by construction (why only `Nr−1` rows carry `φ`). Columns are
orthonormal → `VᴴV = I` → it passes the AP's PHY sanity check.

**Worked example** (SU, codebook 1 → `b_φ=6, b_ψ=4`; raw `q_φ=20, q_ψ=5`):

```
    φ = π·(41)/64 = 2.013 rad (115.3°)    e^{jφ} = −0.428 + j0.904
    ψ = π·(11)/64 = 0.540 rad ( 30.9°)    cos ψ = 0.858 , sin ψ = 0.514

          ┌  −0.367 + j0.776 ,   0.220 − j0.465  ┐
    V  =  │                                       │   (check: ‖col‖=1, cols ⟂)
          └       0.514       ,       0.858       ┘
```

**The 2×2 forge (square branch, already in the code).** Because there is no null
space, the attack rotates `V` onto itself by `θ = α·(π/2)`:

```
    W = V · R(θ) ,   R(θ) = ┌ cos θ  −sin θ ┐ ,   θ = α · π/2
                            └ sin θ   cos θ ┘
    α = 0 → θ = 0  → R = I   → W = V       (honest, no attack)
    α = 1 → θ = 90° → swap   → stream 1's energy sent along stream 2's direction
```

This is `BeamCraft_AE/main_su.cpp:200-207` (`bool degenerate = (Nr == Nc)`), knob
`--alpha`. Sweeping `--alpha 0 → 1` on a 2×2 victim yields a clean monotone
throughput-vs-`α` curve (one angle, one knob). Real 2×2 HE reports to practise the
decode on: `data/bfi_he_capture.pcap`, `data/bfi_features.csv` (all `Nc=2`).

### 3.2 Decomposing a 4×2 matrix (Wi-Fi 5 & 6) — the tall case

A 4-antenna reporter (`Nr=4`) with 2 streams (`Nc=2`) gives a **tall** `4×2` matrix.
This appears in our captures only from a 4-antenna sounder (e.g. the AX3200 4×4 AP;
`data/bfi_ax3200_4x4_features.csv` — all `4×2`). The **frame wrapper is identical to
§3.1** (same VHT-vs-HE table, same categories/field sizes); only the *geometry-
dependent* part changes.

**Angles — `NANG = 10`** (vs 2 for square), computed as
`Σ_{i=1}^{min(Nc,Nr−1)} 2·(Nr−i) = 2·3 + 2·2 = 10` → **5 φ + 5 ψ**, packed in this
order (from §3):

```
    φ₁₁, φ₂₁, φ₃₁, ψ₂₁, ψ₃₁, ψ₄₁, φ₂₂, φ₃₂, ψ₃₂, ψ₄₂
```

Bit-widths and the dequant formulas are the **same as §3.1** (they depend on SU/MU +
codebook, not geometry). Dequant each `q` the same way:
`φ = π·(2q_φ+1)/2^{b_φ}`, `ψ = π·(2q_ψ+1)/2^{b_ψ+2}`.

**Reconstruct V (4×2)** — two column-stages of a diagonal phase matrix times Givens
rotations, then the first 2 identity columns:

```
    Ṽ = [ D₁ · G₂₁ᵀ · G₃₁ᵀ · G₄₁ᵀ ] · [ D₂ · G₃₂ᵀ · G₄₂ᵀ ] · Ĩ(4×2)

    D₁ = diag(e^{jφ₁₁}, e^{jφ₂₁}, e^{jφ₃₁}, 1)      D₂ = diag(1, e^{jφ₂₂}, e^{jφ₃₂}, 1)
    Gₗᵢ(ψ) = I₄ with a [cos ψ, sin ψ; −sin ψ, cos ψ] block in the (i,ℓ) plane
```

The result is `4×2` with orthonormal columns: **2 steered directions living in 4-D
space**, so there is a **2-D left-over null space** (`Nr − Nc = 2`). Worked example of
one angle (SU, codebook 1, `b_ψ=4`, raw `q_ψ=5`): `ψ₂₁ = π·11/64 = 30.9°`; the full
10-angle → 4×2 build is exactly `BeamCraft_AE/main_su.cpp :: reconstruct_V()` (loop
over the same angle order) — use it as the reference implementation.

**Forge (tall case = null-steer, not rotation).** *Because* that 2-D null space exists,
the attack aims energy into it: `Wₖ = √(1−α)·Vₖ + √α·V_perp`, with `V_perp` from
Gram–Schmidt on a random matrix projected out of V's column space (§4). This is the
`else` branch at `main_su.cpp:208-225` — contrast the 2×2 rotation branch (§3.1). So:

| geometry | null space | forge | code branch |
|---|---|---|---|
| **2×2** (`Nr=Nc`) | none (`dim 0`) | rotate V onto itself, `θ=α·90°` | `main_su.cpp:200-207` |
| **4×2** (`Nr>Nc`) | `dim 2` | blend in `V_perp` (Gram-Schmidt) | `main_su.cpp:208-225` |

Both Wi-Fi 5 and Wi-Fi 6 use this same 4×2 math; only the frame wrapper (§3.1 table)
differs. Practise the 4×2 decode on `data/bfi_ax3200_4x4.pcap`.

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
 │ main_su (BeamCraft SU)   │              │  → BFI-storm detector → 🚨│
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
        │  iwpriv wl0 stat  +  sysfs {tx,rx}_bytes  (poll 2 s, telnet)
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
   per-2s BFI features  →  anomaly detector  →  verdict  →  🚨   (current: §7.1)
```

> **Note:** the counter pipeline above (and §7.2–7.3 below) is the *original*
> throughput-telemetry detection plan, kept as Objective-2 context. The detector
> that actually works reads the on-air **BFI storm** — see §7.1.

### 7.1 How the ML engine works (current — BFI-storm detection)

> **Superseded:** the throughput/PHY-telemetry → Isolation-Forest plan described
> below (§7's counter pipeline) was built and did not pan out — at a strong,
> close, single-stream link the attack barely moves throughput/RSSI, so there was
> no reliable telemetry signal. Detection moved to the attack's **own on-air
> forged-BFI frames.** Full method + honest caveats: [`docs/ml-engine.md`](docs/ml-engine.md).

The attack **injects forged BFI frames** impersonating the victim — it cannot
avoid putting them on-air. Beam-Warden sniffs the victim's VHT compressed-beamforming
frames (monitor mode) and counts them per **2-second window**. During an attack
the forged frames roughly **double** the on-air BFI rate and carry the **RETRY=1**
bit:

| Feature (per 2 s window) | normal | attack |
|---|---|---|
| `bfi_count` / `bfi_rate` | ~8/s | **~16/s** |
| `retry1_count` / `retry1_ratio` | ≈0 | **spikes** (forgery marker) |

The classes are widely separable (a threshold `bfi_count ≥ 24` alone splits them).
Reported via a **RandomForest with GroupKFold-by-phase** (leakage-safe): **100%
detection** on real hardware, every fold — and still 100% with the RETRY features
removed, so an attacker who hides the marker is still caught by the rate anomaly.
*Within one capture/condition so far; cross-condition is honest future work.*

Pipeline: `tools/bfi_run.py` (capture + inject + sniff) → `tools/bfi_features.py`
(window + train) → live panel in `tools/dashboard.py` (`--bfi-feed` / `--replay`).

---

### 7.3 How data is extracted off the router

Everything comes off a **single telnet session** to the AP — nothing is
installed on the router itself.

**Login:** `192.168.31.1` · user `root` · password from
`python unlock-ax3200.py <S/N>` (= `md5(SN + salt)[:8]`, e.g. `REDACTED`).
Stock **XiaoQiang** firmware; the genuine **4×4 5 GHz radio is `wl0`**
(`wl1/wl13/wl14` are the 2.4 GHz mt7622).

| # | Channel | Command | Gives |
|---|---|---|---|
| 1 | **MAC/PHY counters** | `iwpriv wl0 stat` (poll 2 s) | per-chain `Rssi0..3`, Tx/Rx success/fail + PER, `Last TX/RX Rate` (NSS/MCS/BW/GI/HE). Parsed by `parse_iwpriv_stat()`. |
| 2 | **Throughput (bytes)** | `cat /sys/class/net/wl0/statistics/{tx,rx}_bytes` | byte counters, diffed over the interval → `throughput_tx/rx_mbps`. **Needed because this firmware's `iwpriv stat` has no byte fields** (the GN630v's did). `read_iface_bytes()`. |
| 3 | **Per-station table** | `iwpriv wl0 show stainfo` → `dmesg \| tail` | per-client MAC / MODE / `RSSI0-3` / PHY / MCS (no `wlanconfig` on this fw). |
| 4 | **Off-air BFI** (not from the router) | Alfa in monitor mode on `wl0`'s channel | the victim's HE Beamforming Report frames — the exact BFI the attack forges → `bfi_features.py`. |

**Direction matters:** `tx_bytes` = router→client (**downlink**, the beamformed
direction the attack degrades); `rx_bytes` = client→router (uplink). The attack
demo measures the **downlink** drop (`iperf3 -R` to the victim, watch `wl0`
`tx_bytes`). Channels 1–3 are wired into `dashboard.py` / `gn630v_telemetry.py`;
channel 4 is the off-air pcap path (§7.2).

---

## 8. Tools

| Tool | What it does |
|---|---|
| `tools/gn630v_telemetry.py` | telnet → `iwpriv wl0 stat` (+ sysfs bytes) every 2 s → CSV (RSSI/MCS/throughput/retry), labelled `normal`/`attack`. Backed by `gn630v_telnet.py` (stdlib raw-socket telnet). Defaults now target the AX3200; pass GN630v creds via flags. |
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
| `data/bfi_ax3200_4x4.pcap` | — | 56 real 4×4 HE beamforming reports off the AX3200 (BSSID `5c:02:14:b0:34:13`) |
| `data/bfi_ax3200_4x4_features.csv` | **normal** | 56 rows of CSI features, all `Nr=4 Nc=2 NANG=10`, from the HE_SU client `e2:65:2c:d9:25:fb` |
| _(next)_ `data/attack_*.csv` | **attack** | same link while forged BFI is injected into the AX3200 (`main_su`) |

---

## 11. Hardware & stack

| Role | Device / tech |
|---|---|
| **4×4 target AP** (live) | Xiaomi **AX3200** (RB01) — MediaTek **MT7915** 4T4R, XiaoQiang fw, radio `wl0`, 5 GHz ch44/BW80, 802.11ax; telnet root via `unlock-ax3200.py` |
| 2×2 dev AP / normal-traffic leg | Skyworth **GN630v** ONT — MediaTek **MT7916**, 5 GHz ch48, SU/MU HE beamforming |
| Attacker NIC | Alfa **AWUS036ACM** — MediaTek **MT7921** (`mt76`), monitor + injection |
| Attack code | C++ (`main_su`), libpcap, Eigen3; aircrack-ng for injection verification |
| Telemetry + ML | Python 3, Starlette/uvicorn (dashboard), scikit-learn (RandomForest / threshold on BFI-rate) |
| Detection host (target) | OpenWrt 24.10+ LuCI + Telegram alerts *(deployment target)* |

---

## 12. Repo layout

- `docs/` — progress reports (`progress-report.md` + dated in `progress-reports/`), challenges logs (`challenges.md`, `challenges-2026-09-17.md`, `challenges-2026-09-18.md`), Gate-2 findings, dashboard guide, ML-engine notes, hardware recon.
- `tools/` — our scripts (tracked).
- `data/` — datasets + captures.
- `BeamCraft_AE/`, `BFM-tool/` — external reference repos (gitignored). `BeamCraft_AE` = the VHT attack; `BFM-tool` = raw BFI capture.
- `Wi-BFI-WFI6.pdf` — the HE BFI extraction reference (Wi-BFI, WiNTECH '23).
- `*.pdf` — proposal, BeamCraft paper.

---

## Team

Muhammad Lutfil Hadi bin Mohd Hafez

## References

- **BeamCraft** (2026) — the forged-BFI attack this project replicates.
- **Wi-BFI** (Haque, Meneghello, Restuccia; ACM WiNTECH '23) — extracting 802.11ac/ax
  BFI from commodity devices; the HE decoder reference (`Wi-BFI-WFI6.pdf`).
- IEEE 802.11-2020 §21 (VHT) / §27 (HE) — compressed beamforming report format.
- Full related work (LeakyBeam, KIT KASTEL) in the proposal PDF §15.
