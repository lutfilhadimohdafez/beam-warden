# Skyworth GN630v — UART / Console Recon

**Objective 1 evidence** — hardware bring-up and console access for the Beam-Warden target ONT.
Captured 2026-08-18 via UART (`/dev/ttyUSB0` @ 115200 8N1, minicom) + telnet over LAN.

> Authorized research on Lutfil's own device. TM Unifi-branded unit (`ONT login:` banner).

## 1. Device profile

| Item | Value |
|------|-------|
| Model | Skyworth **GN630v** (TM Unifi rebadge) |
| SoC | EcoNet/Airoha **EN7523 / EN7529CT**, ARMv7 dual-core (Cortex-A15 class) |
| RAM | 512 MB DDR3-1866 (496 MiB usable) |
| Flash | Micron **MT29F2G01** SPI-NAND, 256 MB, 128 KiB erase / 2048 B page |
| Kernel | Linux **4.4.115** SMP, built 2023-10-22 (`liaoxiaohui@sky655`, Buildroot 2015.08 gcc 4.9.3) |
| Bootloader | **U-Boot 2014.04-rc1-svn52995** (Feb 2023), dual-image, `autoboot: 0` (near-zero delay) |
| Userland | BusyBox v1.00, **squashfs rootfs (read-only)**, TR-069/CWMP managed |
| Mesh | EasyMesh / **Multi-AP R2 Controller** (`Controller_B62D`, MESH ID `3F6135`) |
| WiFi | MediaTek **MT7906/MT7916**, 2×2 802.11ax, `su_bf=1 mu_bf=1`, HE160 |

Base MAC (`ethaddr`): `fc:7a:58:f2:b6:2d`. Radio MAC: `fc:7a:58:f2:b6:31`.

## 2. Access surface

| Vector | State | Notes |
|--------|-------|-------|
| **UART serial** | ✅ | Kernel console (`console=ttyS0`) **and** U-Boot. `ONT login:` via `/bin/login`. |
| **telnet :23** | ✅ **working shell** | Clean pty, no kernel-log spam. Preferred for interactive work. |
| dropbear SSH | up | Running per boot log; not yet exercised. |
| boa httpd :80 | up | Admin web GUI. |

**Serial interactive-shell caveat:** a correct login on the serial console spawns a shell that
immediately exits, because the kernel `printk` flood (endless `udhcpc Sending discover...`,
`tc3162ser_startup`) clobbers the shell's stdin. Fix once any shell is held:

```sh
echo 1 > /proc/sys/kernel/printk    # or: dmesg -n 1
```

…then serial becomes a clean interactive shell too. Serial's unique value over telnet:
pre-boot / U-Boot access, single-user root (`init=/bin/sh`), flash dump/reflash, live kernel &
MT7916 driver telemetry, and out-of-band survival when the network stack is broken.

## 3. Credentials — and a finding

Confirmed working (telnet): **`tmadmin` / `REDACTED`** → **root busybox `#` shell**.

`/etc/passwd` (sole account, `/etc` is a tmpfs symlink `/etc → /tmp/etc`):

```
tmadmin:$1$$RzBNl1SXxjORpXu0SlYTn1:0:0:root:/:/bin/sh
```

uid 0 / gid 0, shell `/bin/sh` — `tmadmin` *is* root, not a restricted CLI. Hash is MD5-crypt with
an **empty salt** (`$1$$…`) — trivially crackable, though moot given the password is known.
busybox provides `dd`, `hexdump`, `tftp`, `ftpput`, `insmod`, `ip`, `mount` — enough to dump flash
directly off the box. No separate `/etc/shadow`.

**FINDING — predictable admin credential.** The password is `Adm@` + the **last 4 hex digits of
the device MAC**, uppercased: MAC `…b6:2d` → `REDACTED`. Those 4 digits are printed on the device
label *and* broadcast in every beacon frame (SSID `SKYW_B62D` encodes the same suffix). A second
unit observed used `Adm@45E2` — same derivation. So the console/telnet admin password is
recoverable by anyone in RF range or with line-of-sight to the label. Writeup-worthy.

## 4. Flash / MTD map (from boot log)

```
0x00000000-0x00080000  bootloader      (512K)
0x00080000-0x000c0000  romfile         (256K)   <- config blob
0x000c0000-0x00349ba8  kernel          (RO)
0x00349ca0-0x017c9ca0  rootfs squashfs (RO)
0x000c0000-0x020c0000  tclinux         (32M, image 0)
0x020c0000-0x0234a4c1  kernel_slave    (RO)
0x0234a5bc-0x037fa5bc  rootfs_slave    (RO)
0x020c0000-0x040c0000  tclinux_slave   (32M, image 1)  <- CURRENTLY BOOTED (bootflag==1)
0x040c0000-0x048c0000  config          (8M)
0x048c0000-0x068c0000  ubifs           (32M)
0x0ddc0000-0x0e000000  reservearea              <- calibration / provisioning data
```

## 5. Secrets leaked in plaintext at boot (serial console)

- **Mesh backhaul WPA2 PSK:** `F3SmGLKlF6V7R6V5FbWnG6V3QbJ8RnR3` (`SKYMESH_2.4G_BH_*` + `SKYMESH_5G_BH_*`)
- Front-haul SSIDs `SKYW_B62D`, `SKYW_B62D_5GHz` (pre-provision key logged literally as `password`)
- Full radio MAC table, mesh controller role, MESH ID `3F6135`

A console that prints the backhaul PSK on every boot is itself a finding.

## 5a. Telemetry surface — Objective 2 dataset schema (verified live)

The GN630v is the **detection sensor / victim**: when forged BFI degrades its beamforming, its own
radio telemetry degrades measurably. Captured live over telnet with an iPhone associated to `ra1`
(SSID `SKYW_B62D`, 2.4G). **Source command: `iwpriv <if> stat`** — clean to stdout.

Live sample (`iwpriv ra1 stat`, iPhone @ -81 dBm):

```
CurrentTemperature = 55
Tx success = 69
Tx fail count = 55, PER=44.3%
Rx success = 1769
Rx with CRC = 73230, PER=97.6%
Rx drop due to out of resource = 18
Rssi: -81 -87 -109 -109
Last TX Rate = NSS1_MCS5, BW20, 0.8us GI, HE_SU, LDPC
Last RX Rate = 6M, BW20, OFDM
Packets Received = 2220 / Sent = 190
Bytes Received = 73423 / Sent = 25794
```

Feature vector for the ML engine:

| Feature | Field in `iwpriv stat` | Attack signal (forged BFI) |
|---|---|---|
| TX PER | `Tx fail count … PER` | beamforming fails → TX PER spikes |
| RX PER | `Rx with CRC … PER` | ↑ under degraded link |
| MCS / NSS / mode | `Last TX Rate` (`NSS1_MCS5 … HE_SU`) | MCS drops, HE→legacy downgrade |
| per-chain RSSI ×4 | `Rssi:` | SNR / spatial shift |
| BW / GI / coding | `Last TX Rate`, `Current BW Tx count` | rate-adaptation collapse |
| throughput | `Packets/Bytes Sent+Received` (diff) | goodput drop |
| PHY temp | `CurrentTemperature` | health baseline |

**Collection method:** poll `iwpriv <if> stat` on an interval, diff cumulative counters
(`Tx success/fail`, `Rx success/CRC`, `Packets/Bytes`) → rates; read `Rssi` / `Last TX Rate`
instantaneously. Same diff pattern as `tools/telemetry_capture.py` (built for OpenWrt
`iw station dump`) — needs a **GN630v/`iwpriv stat` parser adapter**.

**Per-STA schema** (verified via `iwpriv <if> show stainfo` -> dmesg; columns present even when no
STA is associated). This is the richest feature set — one row per associated client:

```
MAC  MODE  AID  WCID  BSS  PSM  WMM  MIMOPS  RSSI0/1/2/3  PhMd(T/R)  BW(T/R)  MCS(T/R)  SGI(T/R)  STBC(T/R)  Idle  Rate(T/R)
```

Per-client features: **`RSSI0/1/2/3`** (per-chain, per-STA), **`MCS(T/R)`**, `PhMd`/`BW`/`SGI`/`STBC`
(rate mode), `Idle`, `Rate(T/R)`. Enables the plunder vs disruption discrimination (per-STA divergence,
see `docs/beamcraft-attack-context.md` §6a).

Collector gotchas (verified):
- `iwpriv <if> show stainfo` / `get_mac_table` print to **dmesg/kernel ring buffer, not stdout** —
  only needed for per-STA breakdown with multiple clients; per-BSS `stat` suffices for single STA.
- On-box busybox is minimal: **no `tail`, no `printf`, no `sort`** — an on-box awk agent must avoid them.
- SSID→interface map (live): `ra0`=`SKYMESH_2.4G_BH`(hidden), `ra1`=`SKYW_B62D`, `ra2..4`=`SKYW_B62D_2..4`;
  `rai0`=`SKYMESH_5G_BH`(hidden), `rai1`=`SKYW_B62D_5GHz`, `rai2..4`=`..._6/7/8_5GHz`.

## 6. Relevance to Beam-Warden

- **MT7916 with `su_bf=1 mu_bf=1`** = genuine explicit SU/MU beamforming in hardware → this ONT is
  both a valid **beamforming attack target** and a **telemetry source** for the anomaly model.
- The serial console streams **live radio state** (`RadarStateCheck`, `CAC`, `wifi_sys_linkup`,
  per-BSS caps) — a candidate kernel-level anomaly signal that survives driver crashes.
- **OpenWrt path:** dual-image squashfs; reflashing needs the U-Boot route (Section 7).

## 7. Next steps

1. Confirm privilege: `id` over telnet — is `tmadmin` uid 0 (busybox `#`) or a restricted CLI? (find shell escape if CLI)
2. Quiet console (`echo 1 > /proc/sys/kernel/printk`) → use serial interactively.
3. Dump `/etc/passwd`, `/etc/shadow`, and the `romfile`/`config` MTD partitions for offline analysis.
4. Catch U-Boot (hold a key from power-on to beat `autoboot: 0`) → `printenv`, then flash dump / OpenWrt bring-up.
5. Dump MT7916 beamforming config (`iwpriv ra0`, relevant `/proc` entries) → feed the telemetry pipeline.
