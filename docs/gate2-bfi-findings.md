# Gate 2 — Real GN630v BFI Capture Findings

**Beam Warden**
Captured **15 September 2026, ~01:20 (MYT)**

## What we did

With a victim device pulling sustained downlink traffic over `SKYW_B62D_5GHz`
(the GN630v now has real internet via a double-NAT to the TIME/Huawei uplink),
we put the Alfa (`mt7921u`) into monitor mode on **channel 48** and captured the
live air for 30 s (`data/bfi_he_capture.pcap`, 3.4 MB, 6620 management frames).

## Result — beamforming feedback IS present, and it is **HE (802.11ax)**

| Property | Value |
|---|---|
| Beamforming feedback frames captured | **171** in 30 s |
| Sender (beamformee / victim) | **`d2:93:e5:7c:20:71`** |
| Receiver (beamformer / AP) | **`fe:7a:58:92:b6:31`** (GN630v 5 GHz) |
| Action category | **30 = HE** (802.11ax) |
| Typical report frame length | **277 bytes** |

The victim is emitting an **HE Compressed Beamforming Report** to the GN630v
roughly every ~40 ms under load — exactly the frame BeamCraft forges.

## The pivotal finding (Gate 2)

**The GN630v (MediaTek MT7916) performs 802.11ax (HE) beamforming — not the
802.11ac (VHT) beamforming that the reference BeamCraft attack targets.**

The reference `main_su.cpp` decodes a **VHT** compressed beamforming report
(VHT MIMO Control field + VHT angle codebook, `Nr=4, Nc=2, Nst=52`, φ=6/ψ=4 bits).
HE uses a **different** compressed beamforming report structure — a different MIMO
Control field, different subcarrier grouping (RU-based), and its own angle
quantisation. So a byte-for-byte port of the VHT decoder will not parse these
frames correctly.

Note: even Wireshark 4.7.3 does not fully dissect the HE MIMO-Control sub-fields
(`wlan.he.mimo_control.*` are unsupported), so Nc/Nr must be decoded from the raw
report bytes — see the preserved pcap.

## What this proves vs. what remains

| Claim | Status |
|---|---|
| Attacker can inject on the target's channel | ✅ proven (30/30) |
| Victim emits real beamforming feedback we can capture | ✅ **proven (171 HE frames)** |
| The target's BFI format identified | ✅ **HE / 802.11ax, ~277-byte report** |
| Forge HE BFI + collapse victim throughput | ⛔ requires the VHT→HE port below |

## Next research step (well-scoped)

Port the BFI decode/re-encode in `main_su.cpp` (`re_beamforming()`) from the **VHT**
compressed beamforming report to the **HE** report format:
1. Parse the HE MIMO Control field (Nc, Nr, RU/subcarrier grouping, feedback type)
   from `data/bfi_he_capture.pcap` raw bytes.
2. Map the HE angle codebook (φ/ψ bit widths + ordering per the 802.11ax spec).
3. Rebuild V, craft the orthogonal W (unchanged math), re-encode to HE angles.
4. Inject with `--victim d2:93:e5:7c:20:71 --ap fe:7a:58:92:b6:31 --iface mon0`,
   then measure throughput drop with `tools/attack_harness.py`.

This is a substantial but bounded extension — the attack primitive (inject) and the
target (a live HE beamformer) are both confirmed.
