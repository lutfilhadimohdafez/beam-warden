# Beam Warden — Challenges Encountered (Session 2026-09-17/18)

**Final Year Project**
*The 4×4 router arrives: hardware bring-up, first real 4×4 HE BFI capture,
attack-pipeline validation, and live-throughput telemetry.*

Grouped as *challenge → impact → how we handled it*.
Status: 🟢 handled · 🟡 partial · 🔴 open.

This session continues [`challenges-2026-09-17.md`](challenges-2026-09-17.md)
(which covered the BFI→CSI pipeline, Mission Control, and router selection).

---

## F. Bringing up the Xiaomi AX3200 (genuine 4×4)

**F1 — Telnet credentials + non-obvious login** 🟢
The AX3200 (RB01) ships with telnet closed and no published root password.
*Handled:* `unlock-ax3200.py <S/N>` derives the password as `md5(SN + salt)[:8]`
(the `REDACTED` we now use). Login is `192.168.31.1` · `root` · `REDACTED`.

**F2 — Firmware is XiaoQiang, not BusyBox → interface names changed** 🟢
Every earlier tool assumed the GN630v's MediaTek naming (`rai0`/`rai1`). The
AX3200 runs stock **XiaoQiang**, which names radios `wlN`. Running `iwpriv rai1
stat` returns *"no private ioctls"* — the interface simply doesn't exist.
*Impact:* the whole telemetry path pointed at a dead iface.
*Handled:* enumerated live with `iwconfig` — **`wl0` = the MT7915 4×4 5 GHz
radio** (ESSID `Xiaomi_115B_5G`, BSSID `5c:02:14:b0:34:13`), `wl1/wl13/wl14` =
the mt7622 2.4 GHz. Repointed `dashboard.py` + `gn630v_telemetry.py` defaults to
`wl0`; corrected `docs/dashboard.md`. (`rai1` references in dated reports /
GN630v recon docs are left as historical record.)

**F3 — Confirming it is *actually* 4×4 (not marketing "4 antennas")** 🟢
The whole project hinges on `Nr > Nc` (see E1). Antenna count lies.
*Handled:* `iwpriv wl0 stat` reports **`Rssi: -43 -41 -45 -40`** — four
populated RX chains — and the per-station table (`iwpriv wl0 show stainfo` →
`dmesg`) shows `RSSI0/1/2/3` per client. Genuine 4×4 confirmed on silicon.

**F4 — No `wlanconfig`; station table hides in the kernel log** 🟢
`wlanconfig wl0 list sta` (the usual MediaTek enumerator) isn't present.
*Handled:* `iwpriv wl0 show stainfo` prints the MAC/MODE/RSSI0-3/PHY/MCS table
to `dmesg` — read it back with `dmesg | tail`.

## G. First real 4×4 HE BFI dataset

**G1 — `bfi_capture.py live --write` captures zero packets** 🔴 (bug logged)
The live path passes tshark a display filter (`-Y`) **and** a write file
(`-w`) together; tshark refuses ("Display filters aren't supported when
capturing and saving") and captures nothing.
*Impact:* the one-shot live capture-and-analyze command is broken.
*Handled (workaround):* capture raw with plain tshark, analyze offline. **Real
fix still open** — flynn's job (use a capture filter, or drop `-Y` and filter
the saved file on read).

**G2 — Neighbour 2×2 APs drown out our 4×4 frames** 🟢
A blanket decode of a mixed capture reported `Nr=2` because 294 of 353
beamforming frames on ch44 came from neighbouring 2×2 APs; only ~59 were ours.
*Handled:* filter to our AP (`wlan.addr==5c:02:14:b0:34:13` +
`wlan.fixed.category_code==30`). Result: **56 frames, all `Nr=4 Nc=2 NANG=10`**,
all from the HE_SU client `e2:65:2c:d9:25:fb` → `data/bfi_ax3200_4x4*`.

**G3 — Monitor drifts / huge capture files** 🟢
`mon0` started on the wrong channel (ch48/20 MHz) and an unfiltered 10 s grab
was 3.9 GB (2.25 M frames).
*Handled:* tuned `mon0` to match `wl0` (`iw dev mon0 set freq 5220 80 5210`);
confirmed NetworkManager does **not** manage `mon0`, so it holds. Extracted the
353 category-30 frames to a 190 KB pcap before decoding; gitignored multi-GB
raw captures (`data/*.pcapng`, `data/bfi_*_2026*.pcap`).

## H. Attack against the AX3200

**H1 — Is the attack even valid on this AP? (offline validation)** 🟢
Before transmitting anything, ran `main_su --pcap data/bfi_ax3200_4x4.pcap`
(validation mode, no injection). Result: **`Detected: 4x2, MU, codebook 0,
phi=7/psi=5 bits, NANG=10, forge=null-steer`** with the first `W^H·V` cross
matrix driven to zeros. The HE MIMO-Control is parsed at runtime, so the
VHT-flavoured `--type 0xe0`/`--offset 33` defaults **did not** block parsing —
my earlier caveat was overcautious. The null-steer math runs on real data.

**H2 — Live attack effect not yet proven** 🟡
Prior runs (2026-09-15, against a *different* ch48 AP) errored with
`pcap_activate: -5` and recorded no throughput drop, so the end-to-end effect
is unproven. That error is a libpcap/monitor activation issue, **not** a format
problem (H1 clears the format). *Open:* stage a victim we control running
`iperf3 -s`, launch `main_su` on `mon0`, measure the ≥51 % downlink drop.

**H3 — `attack_gui.py` still targeted the old AP + a dead test** 🟢/🟡
The GUI hardcoded the ch48 AP/victim; also `test_attack_gui.py` imports
functions (`extract_current`, `patch_source`, …) that vanished when the GUI was
rewritten to a Tk `App` class.
*Handled:* GUI defaults now point at the AX3200 (ap/victim/ch44). *Open:* the
dead test needs rewriting or deletion (flynn).

## I. Live throughput telemetry

**I1 — `iwpriv wl0 stat` reports no throughput / no bytes** 🟢
The dashboard showed 0 Mb/s under load. The AX3200's `stat` exposes only
*frame* counts + PHY rate — **no byte counters** (the GN630v's did), so the
byte-delta throughput math produced 0.
*Handled:* the kernel keeps them in sysfs — added `read_iface_bytes()` reading
`/sys/class/net/wl0/statistics/{tx,rx}_bytes` in one telnet round-trip, injected
before `compute_deltas` in both poll loops. **Validated live:** sysfs `wl0` TX
≈ 275 Mb/s vs iperf3 239 Mb/s goodput (the delta = 802.11 framing +
retransmits, expected). *Ceiling:* this is total-radio throughput, not
per-station goodput — the attack success number still uses per-flow iperf3.

**I2 — Which byte counter is which direction** 🟢
An early check read 3 Mb/s during a 220 Mb/s test — because that traffic was
*uplink* (client→router = `wl0` **rx_bytes**), while `tx_bytes` carried only
ACKs. `tx_bytes` = downlink (router→client, the beamformed direction the attack
degrades); `rx_bytes` = uplink. The attack demo measures **downlink** (`-R`
iperf3 to the victim).

## J. Workflow

**J1 — Delegated fix ran ~40 min with no output** 🟡
The throughput fix (I1) was dispatched to flynn (MiMo via opencode) per the
standing framework, but the run streamed for ~40 min without writing files
(alive — CPU ticks advancing, API socket open — just slow). *Handled:* on
Lutfil's call, killed it and applied the ~25-line fix inline; scanned for
NUL-truncated partial writes first (none), self-checked, committed.
*Lesson:* for genuinely few-line glue diffs the dispatch+wait overhead can
exceed the edit — keep the inline-takeover option live when a worker stalls.

---

*See [`README.md` §8/§10](../README.md) for how data is extracted off the
router, and [`progress-reports/progress-report-2026-09-18_0026.md`](progress-reports/progress-report-2026-09-18_0026.md)
for the updated scoreboard.*
