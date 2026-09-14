# Beam Warden — Challenges Encountered

**Final Year Project**
*Engineering challenges faced while replicating the BeamCraft BFI-forgery attack*
As of **14 September 2026**

Grouped as *challenge → impact → how we handled it*. Status: 🟢 handled · 🟡 partial · 🔴 open.

---

## A. Target platform

**A1 — Target is a locked ISP router, not OpenWrt** 🟢
The GN630v (TM Unifi ONT) runs stock BusyBox and cannot host our detection engine.
*Handled:* rooted it over UART + telnet to extract PHY telemetry; the OpenWrt
detection host is a separate planned device.

**A2 — Chipset mismatch (the headline research risk)** 🔴
BeamCraft's released code is hard-coded to *its* lab chipset — fixed BFI matrix
dimensions (`Nr=4, Nc=2, Nst=52`), byte offsets, and action-frame type (`0xe0`).
Our target is a **MediaTek MT7916**, whose compressed beamforming report likely
differs (VHT vs HE, bandwidth, stream count).
*Status: open* — the BFI parser must be re-derived from real GN630v captures
("Gate 2"). This is the main remaining research work, not a formality.

---

## B. Attack hardware & operating system

**B1 — NetworkManager + `iwd` sabotaged monitor mode** 🟢
The attack PC uses NetworkManager with the `iwd` Wi-Fi backend. `iwd` silently
creates a **P2P-device** on the attack adapter's radio that holds the hardware
"busy": channel-set failed (`EBUSY`), and injection produced **0 ACKs** because
frames never left on a stable channel.
*Handled:* stand the Wi-Fi stack down (`systemctl stop NetworkManager iwd`) for the
attack window, then build a clean `mon0` monitor interface.

**B2 — The adapter refused to change channel** 🟢
`iw set channel/freq` was silently ignored or returned `EBUSY`; the card stayed
welded to whatever channel it last used.
*Handled:* same root fix (free it from `iwd`) plus a dedicated monitor interface —
the channel then locked cleanly.

**B3 — 5 GHz DFS/radar channels block transmit** 🟢
The router's auto-channel selected **channel 128 (DFS)**, on which the attack
adapter is legally barred from transmitting (`no-IR`, radar detection).
*Handled:* pinned the AP to a **non-DFS channel (48)** where injection is permitted.

**B4 — Attacker and target ended up on different channels** 🟢
The adapter was stuck on ch48; the target was initially on ch40 — no overlap, no
attack.
*Handled:* moved the *target* to ch48 (align the AP to the attacker — far cheaper
than fighting the driver's channel lock).

**B5 — Single internet path couples with the attack radio** 🟢
The machine's only internet is campus Wi-Fi, and both wireless cards share the one
backend, so freeing the attack radio drops internet.
*Handled:* moved internet onto the built-in adapter; accept that the attack window
drops Wi-Fi (fine — telemetry runs over Ethernet), with a guaranteed auto-restore
afterwards.

**B6 — Privilege / authentication friction** 🟢
No terminal for `sudo` through the tooling, `pkexec` needed a polkit agent, and
`faillock` locked the account after failed password attempts.
*Handled:* run privileged steps via `pkexec` once `faillock` was cleared.

---

## C. Verification & measurement

**C1 — No reliable "did it actually transmit?" signal** 🟢
The kernel `tx_packets` counter read **0** even while injecting, so it can't be
used to confirm transmission on a monitor interface.
*Handled:* relied on 802.11 semantics instead — an ACK is a **mandatory,
hardware-generated** reply to any valid unicast frame, so **30/30 ACKs** is
definitive proof the adapter transmitted 30 frames that reached the target.

**C2 — Standard injection test failed on 5 GHz** 🟢
`aireplay-ng -9` in broadcast mode found 0 APs (5 GHz APs often ignore broadcast
probes).
*Handled:* switched to a **directed** test against the target's specific BSSID.

**C3 — Scan tooling returned false data** 🟢
NetworkManager's scan reported garbage (impossible shared MAC prefixes, wrong
channels).
*Handled:* used raw `iw dev … scan` exclusively and parsed it directly.

---

## D. Method & scope constraints

**D1 — Ethics / authorization** 🟢
We may only attack our **own** GN630v, never campus infrastructure — this shaped
the entire lab topology (our router as the sole target).

**D2 — A live victim client is required** 🟡
Beamforming only occurs under active traffic + channel sounding, so the demo needs
a dedicated victim device generating load on the target's 5 GHz link.

**D3 — Research-grade upstream code** 🟡
BeamCraft's public release is testbed-specific, hard-coded, and sparsely documented
(comments in Chinese) — it is a reference, not a plug-and-play tool.

---

## Summary for the panel

- **Proven:** attacker rig can inject crafted frames at the real target (30/30, 100%);
  monitor capture works; the target advertises the beamforming feature attacked.
- **Biggest open risk:** the BFI parser must be adapted from BeamCraft's chipset to
  the MT7916 (A2 / Gate 2) — this is the next milestone and the core research
  contribution.
- **Takeaway:** most obstacles were **driver / RF-regulatory / OS-level**, not
  conceptual — resolving them required understanding 802.11 MAC behaviour, Linux
  wireless internals (`mac80211`, `iwd`, monitor mode), and DFS/regulatory rules.
