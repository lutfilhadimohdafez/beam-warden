# Beam Warden — Challenges Encountered (Session 2026-09-16/17)

**Final Year Project**
*BFI→CSI feature pipeline, Command Center (Mission Control), router-hardware
selection, and detector validation.*

Grouped as *challenge → impact → how we handled it*.
Status: 🟢 handled · 🟡 partial · 🔴 open.

This session extends the earlier log in [`challenges.md`](challenges.md).

---

## E. Router hardware selection (the "4 antennas ≠ 4×4" trap)

**E1 — The strong attack needs Nr > Nc, i.e. a real 4×4 5 GHz radio** 🟢 (understood)
BeamCraft's null-steer forge is mathematically degenerate on a full-rank link:
when the beamformer antennas `Nr` equal the victim's streams `Nc` (our 2×2 →
`Nr = Nc = 2`), the steering matrix `V` is square/unitary — there is **no null
space** to steer energy away from the victim, so the forge collapses to `W = 0`
(→ NaN). A null can only be aimed when there are **spare antennas**:
`Nr − Nc > 0`. A 4×4 AP against a normal 2-antenna client (→ 4×2) has a
2-dimensional null space → the attack lands.
*Handled:* documented the requirement; the decision rule for any candidate router
is simply its **5 GHz PHY rate** (see E2).

**E2 — "4 external antennas" is NOT "4×4 MIMO" (nearly a wasted purchase)** 🟢
Marketing lists antenna *count*, not spatial *streams*. The decision rule:

| 5 GHz PHY rate | Spatial streams | Null space (Nr−Nc) | Usable for the attack |
|---|---|---|---|
| 867 Mbps | 2×2 | 0 | ❌ dead end |
| 1733 Mbps | 4×4 | 2 | ✅ |
| 2402 Mbps | 4×4 (HE) | 2 | ✅ |

Verdicts (verified against chipset/PHY specs):
- **Xiaomi Mi Router 4A / 4A Gigabit** = AC1200 = **2×2** (867 Mbps). The four
  antennas are diversity pairs. ❌ **Dead end** — identical ceiling to what we
  already own.
- **Ruckus ZoneFlex R500** = **2×2:2** (867 Mbps), *and* its "BeamFlex+" is
  proprietary antenna-pattern switching driven by 2 RF chains — not the standard
  explicit beamforming BeamCraft targets. ❌ Doubly wrong.
- **Xiaomi Router AX3200 (Redmi AX6S)** = **genuine 4×4** (MediaTek MT7915E 4T4R,
  2402 Mbps @ 4 SS, 6 antennas). ✅ **Works** — and it is 802.11ax/**HE**, so it
  exercises our generalized HE code path (arguably a stronger result: proves the
  attack generalizes to Wi-Fi 6).
- **Xiaomi Redmi AC2100 (RM2100)** = **4×4** (MT7615N, 1733 Mbps, 802.11ac). ✅
  The paper's literal device — cleanest "exact replication" claim.
*Handled:* recommend the **AX3200** (HE, matches our code) or **AC2100** (paper's
device). Lutfil to confirm the sticker of the router already purchased; if it is a
Mi 4A it is the wrong 2×2 box — **but still useful** as a legitimate AP, a
normal-traffic generator, or the victim leg of the topology (not wasted).

**E3 — Can firmware/OpenWrt turn a 2×2 into a 4×4?** 🟢 (no)
Spatial streams are a **hardware** property — the number of RF chains (PA + LNA +
antenna trace) physically populated on the board. OpenWrt/`iw` can only *mask*
existing chains (disable, never add). The Mi 4A and AC2100 share the MT7615
*family*, but the 4A board is **depopulated** (2 PAs). No config conjures a PA
that is not soldered on.
*Handled:* silicon is the ceiling; documented so no time is lost flashing firmware.

**E4 — Why the attack needs a null space (BeamCraft's own math confirms Nr>Nc)** 🟢
A natural misreading of the BeamCraft paper is *"the forged matrix just needs to be
≈ 0, not a null space."* The paper says the opposite. Its argument:

- The attacker injects a forged feedback matrix `Vf` to kill the equivalent channel
  gain `U Λ Vᴴ Vf`. The naive idea — set `Vf = 0` — **explicitly does not work**,
  because the feedback is compressed to **phases (Givens angles)**; reconstructing
  any set of angles yields a matrix that is **never zero** (it is always
  column-orthonormal — the same "V unitary, dev 0" our decoder validated). So a
  near-zero `Vf` is unreachable through the real compressed-feedback format.
- Instead the paper minimises `‖Λ Vᴴ Vf‖` and states the optimum:
  **`Vf,★` must lie in the null space of the genuine feedback matrix `V`, i.e.
  `Vᴴ Vf,★ = 0`**, computed via Gram–Schmidt. So `Vf ≈ 0` is the *strawman the paper
  knocks down*; `Vf ⊥ V` (null space) is the actual method.

**Why that forces Nr > Nc** (the hardware gate):
`V` is `Nr × Nc` with orthonormal columns (`Nr` = AP TX antennas, `Nc` = victim
streams). `Vᴴ Vf = 0` requires every column of `Vf` to be orthogonal to `col(V)`,
i.e. to live in its **orthogonal complement, of dimension `Nr − Nc`**. A non-zero
`Vf` therefore exists **iff `Nr − Nc ≥ 1`, i.e. `Nr > Nc`**. Gram–Schmidt only has a
basis to build from when that complement is non-empty.

- **2×2 (our GN630v vs a 2-stream victim):** `Nr = Nc = 2` → `V` is square unitary →
  `col(V) = ℂ²` → orthogonal complement = `{0}` → the only solution is `Vf = 0`
  (already ruled out) → **W = 0 → NaN**. This is exactly the degeneracy we proved,
  and it is why a 2×2 radio can inject a forged frame but never collapse a full-rank
  link.
- **4×2 (Redmi AC2100 / Xiaomi AX3200 vs a 2-antenna client):** complement dimension
  `4 − 2 = 2` → Gram–Schmidt yields a real orthogonal `Vf,★` → the AP beams
  orthogonal to the channel → victim throughput ≈ 0. Attack lands.

*Conclusion:* the paper's null-space formulation **is** the Nr>Nc requirement — it is
not an alternative to it. This is the mathematical justification for why the 4×4
5 GHz radio (§E2) is mandatory and the 2×2 is a genuine dead end (a legitimate,
report-worthy research finding, not a rig limitation).

---

## F. Raw CSI extraction (PicoScenes)

**F1 — PicoScenes is not installable on this rig** 🔴 (deferred → Future Work)
Raw per-subcarrier CSI (complex |H|, phase) would be the richest detection signal.
PicoScenes is the tool, but:
- **Supported NICs:** Intel AX210/AX200/IWL5300, Qualcomm QCA9300 only. Our
  **Intel 8265** and **Alfa MT7921** are **both unsupported**.
- **OS:** requires **Ubuntu 22.04 LTS** + kernel-matched prebuilt driver modules.
  We run **Arch Linux, kernel 7.2.6** — no matching package, different distro.
*Status: deferred* — logged as **Future Work**: an **Intel AX210** card + an
Ubuntu 22.04 install would unlock true raw CSI. Not a gap: the BFI path (§G) gives
a compressed CSI proxy on hardware we already own.

---

## G. BFI → CSI feature decoding

**G1 — tshark 4.7.3 does not dissect the HE compressed beamforming report** 🟢
The report bytes are **not exposed as a named field**. What *is* available:
`wlan.he.action.he_mimo_control` (a 40-bit / 5-byte field → Nr/Nc/codebook/
feedback-type) and `...he_mimo_control.report_len`.
*Handled:* extract the report by **slicing the raw frame** immediately after the
5-byte MIMO Control field. One `tshark -x` pass over `wlan.fixed.category_code==30`
yields per-frame hex dumps in capture order; split on blank lines and
**positionally zip** with the same-filtered metadata rows (identical order) — no
fragile in-band parsing. Verified byte-exact against a per-frame extraction.

**G2 — Compressed-report bit-unpacking is order-sensitive** 🟢
The Givens angles are packed LSB-first with a per-byte and per-slice reversal
(ported from `main_su.cpp`): each byte is `MSB-first → reversed`, concatenated;
each `b_phi`/`b_psi` slice is reversed again before integer conversion;
`φ = (2·raw+1)/2^b_phi`, `ψ = (2·raw+1)/2^(b_psi+2)`.
*Handled:* ported exactly; `Nst` is derived from the available bits, not the
(slightly larger) `report_len` field. Capture params: Nr=2, Nc=2, SU, codebook 0,
report ≈ 190 B, Nst ≈ 248, φ=4/ψ=2 bit.

**G3 — Angle range is NOT (0,1)** 🟢
An initial spec/QA assumption that all decoded angles fall in `(0,1)` was wrong:
standard 802.11 angles are `φ ∈ (0,2)` and `ψ ∈ (0,0.5)` (they are scaled by π at
reconstruction). A φ value of 1.6875 is valid, not a bug.
*Handled:* corrected the bound; the real correctness check is **V unitarity**.

**G4 — Extraction fast-path bug returned zero frames** 🟢
The first implementation's single-call extractor detected frame boundaries by
"a bare integer on its own line" — but hex-dump **offset** lines (`0000`, `0010`,
…) are all-digits and collided with that heuristic, fragmenting every frame →
**empty CSV**. Caught in QA before it shipped.
*Handled:* replaced with the positional-zip method (G1). One `tshark` call, not
171; decodes all frames in ~2 s.

**G5 — Proving the decode is correct** 🟢
*Handled:* reconstructed the steering matrix `V` from the decoded angles via Givens
rotations and confirmed `Vᴴ·V = I` to **1.11×10⁻¹⁶** (machine epsilon) across all
171 frames and every subcarrier — matching the C++ reference's "V unitary, dev 0".

**G6 — The insight that unblocks Objective 3's normal side** 🟢
BFI is captured **off-air** (Alfa in monitor mode), **not** from the GN630v's
telnet counters. The GN630v already solicits/receives real HE beamforming feedback
(171 frames proven). So **CSI-style features are obtainable on the current 2×2 rig
today** — this decouples the *normal-side* CSI dataset from the 4×4 hardware
blocker. Attack-side CSI still requires the 4×4 AP (or synthetic, §H).

---

## H. Detector validation without attack hardware

**H1 — First synthetic-attack BFI was statistically indistinguishable** 🟢
To validate the detection pipeline before the 4×4 AP arrives, we perturb real
normal BFI to emulate a null-steer forge. The first attempt was far too subtle
(it even *reduced* ψ variance) — an IsolationForest trained on normal caught only
**1%** of it. A self-check that only compared feature *means* passed on a
technicality and masked the problem.
*Handled:* reworked the perturbation to a realistic null-steer signature (drive ψ
to a boundary → increased spread; inject per-subcarrier decoherence noise; inflate
φ), and replaced the self-check with a **detection-rate** gate (≥80%).
Independently verified: **98.8% detection at 2.3% false-positive.**
*Caveat carried forward:* synthetic data validates the *pipeline*, not real-world
accuracy — the real number still needs attack telemetry from a 4×4 radio.

---

## I. Tooling & process

**I1 — A monitoring wait-loop deadlocked for ~80 min** 🟢
A background wait `until [ "$(pgrep -fc opencode)" -eq 0 ]` counted **its own**
command line (which contains the string "opencode"), so the count never reached
zero — it waited on itself long after the workers had finished.
*Handled:* killed it and checked the deliverable files directly. Lesson: never
match a process by a substring that appears in the waiter's own argv; poll the
output artifact instead.

**I2 — Parallel subagent workers (was a known crash risk)** 🟢
A prior gotcha held that concurrent `opencode` workers crash with
"database is locked". This session ran them **in parallel with `--pure`**
(disjoint file sets) with **no lock** — likely `--pure`'s state isolation.
*Handled:* parallel fan-out on disjoint files is viable with `--pure`; still watch
for the lock and keep file sets disjoint.

---

## Summary for the panel

- The attack's hardware requirement is now precisely stated (**Nr > Nc**, i.e. a
  genuine **4×4** 5 GHz radio) with a one-number buying rule (**5 GHz PHY rate**).
- A **BFI→CSI feature pipeline** was built and **cryptographically validated**
  (V unitary to 1e-16), giving real CSI-style detection features **on existing
  2×2 hardware** — decoupling the normal-side dataset from the hardware blocker.
- A **synthetic attack generator** now yields a detectable signature
  (98.8% / 2.3% FP), letting Objective 3 be validated end-to-end pending the 4×4 AP.
- Raw CSI (PicoScenes) is deferred to **Future Work** (needs an AX210 + Ubuntu).
