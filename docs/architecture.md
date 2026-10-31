# Beam Warden — System Architecture

> ⚠️ **ML-engine note (31 Oct 2026):** the "learns" box below is described as an
> Isolation Forest on router telemetry — that is superseded. The working detector
> is a **BFI-storm anomaly detector** (RandomForest / rate threshold) that reads the
> victim's on-air beamforming-feedback frames via a monitor NIC, not router PHY
> counters. Topology is otherwise current (rig is now the AC2100). See
> [`ml-engine.md`](ml-engine.md).

How the pieces fit: who attacks, who senses, who learns, who decides. Grounds the
proposal (§10 Principle of Operation, Objective 3, Appendix 16.1) against the real
hardware we now have.

## Roles — four boxes, four jobs

| Box | Role | Runs |
|---|---|---|
| **OpenWrt router** (budgeted, RM450) | Victim AP **+** telemetry sensor **+** package host | the `beamwarden` ipk |
| **Laptop / ML engine** | Trains the model (once) **+** runs inference (the external ML engine) | Python, scikit-learn (Isolation Forest) |
| **Alfa AWUS036ACM** (+ RPi/Kali) | Attack rig — sniff, forge, inject BFI | BeamCraft_AE `main_su`/`main_mu` |
| **Skyworth GN630v** (stock MTK) | *Bonus* real victim + telemetry source (proves collection on stock gear) | `gn630v_telemetry.py` off-box via telnet |

> **The GN630v is NOT OpenWrt** — stock MediaTek BusyBox, no compiler/python/opkg.
> It cannot host the ipk. Its EN7523/Airoha GPON SoC has ~no mainline OpenWrt
> support, so treat flashing it as infeasible. It stays a stock-firmware victim we
> validated the `iwpriv`-telemetry approach on; the **OpenWrt router** is the package host.

## Data flow (proposal §10 — external ML engine)

```
   CLIENTS ──wifi──► OpenWrt ROUTER (victim AP + sensor)
                          │
                          │  beamwarden ipk:
                          │   collector  → features (RSSI, MCS, retry_rate, throughput)
                          │   transmitter → MQTT/HTTP
                          ▼
                     LAPTOP — external ML engine
                          │   Isolation Forest .predict()  → anomaly score / label
                          ▼
                     verdict back to router
                          │
                          │   responder: LuCI dashboard alert  +  Telegram
                          │              + optional firewall block (isolate MAC)
                          ▼
                        operator
   ▲
   │  ATTACK: Alfa (monitor+inject) forges BFI toward the router  → telemetry degrades
```

The ML **engine is external** (on the laptop). The router package **collects, ships,
displays, and responds** — it does not run scikit-learn.

## Train once (laptop) → infer many (wherever detection lives)

Two phases people conflate:

- **Training / "learning"** — one-time, **offline on the laptop**, scikit-learn over the
  labelled dataset (`data/normal_iperf.csv` + attack CSVs). Produces a **learned model file**
  (the forest of trees). Heavy; happens once.
- **Inference / "detecting"** — cheap, per-sample: load the learned parameters, score the
  telemetry. Runs continuously.

You never train on the router. If detection runs on the router (on-device option), you ship
the **learned model file**, not scikit-learn.

## What the OpenWrt package (`.ipk`) is

An `.ipk` is OpenWrt's installable package (its `.deb`/`.apk`). The `beamwarden` ipk is the
**entire router-side application**, of which "interface to the external ML" is one module:

```
   beamwarden.ipk =
     collector    reads `iw station dump` (nl80211) -> feature vectors
     transmitter  ships features to the laptop ML   (MQTT/HTTP)   ← interfacing
     responder    receives verdict -> LuCI alert + Telegram + optional firewall block
     service glue init.d script, UCI config, LuCI dashboard page
```

`opkg install beamwarden.ipk` drops it in; `/etc/init.d/beamwarden start` runs it.

## The Makefile builds *for* the router, *on* the laptop

An OpenWrt package Makefile is a **build recipe** run by the OpenWrt SDK on the dev machine —
NOT a script that runs on the router. It cross-compiles the source, declares dependencies, and
lists which files install where. Its output is the `.ipk`.

```
   LAPTOP (OpenWrt SDK)                              OPENWRT ROUTER
   ┌───────────────────────────┐                    ┌────────────────────────┐
   │ package/beamwarden/        │                    │                        │
   │   Makefile   (recipe)      │  make →  .ipk      │  opkg install *.ipk    │
   │   src/  collector+resp     │  ─────────────────►│  /etc/init.d/beamwarden│
   │   files/ beamwarden.init   │                    │    start → runs live   │
   │   (model.params if on-dev) │                    │                        │
   └───────────────────────────┘                    └────────────────────────┘
        train model here (once)                          collect/ship/respond
```

Skeleton (external-ML variant — no scikit-learn dependency on the router):

```make
include $(TOPDIR)/rules.mk
PKG_NAME:=beamwarden
PKG_VERSION:=0.1
include $(INCLUDE_DIR)/package.mk

define Package/beamwarden
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=Beam Warden BFI-anomaly telemetry + response
  DEPENDS:=+libiwinfo +libmosquitto      # collector + MQTT transmitter; no python needed
endef

define Package/beamwarden/install
  $(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d
  $(INSTALL_BIN) ./src/beamwarden      $(1)/usr/bin/
  $(INSTALL_BIN) ./files/beamwarden.init $(1)/etc/init.d/beamwarden
endef

$(eval $(call BuildPackage,beamwarden))
```

(On-device-inference variant instead adds `+python3-light +python3-numpy` and ships an exported
Isolation-Forest tree-walk + `model.params` under `/usr/share/beamwarden/`.)

## Design choice: external ML vs on-device inference

| | External ML (proposal §10) | On-device inference (Obj 3 literal) |
|---|---|---|
| Where inference runs | Laptop | Router |
| Router package holds | collector + transmitter + responder | + exported model + tree-walk |
| Router deps | light (C/lua/mqtt) | python3-light+numpy or a C tree-walk |
| Risk / effort | lower — matches §10 | higher — must export/port the forest |
| External dependency | needs laptop reachable | self-contained |

**Recommendation:** build the **external-ML** path first (matches §10, lowest risk, gets Objective 3
demonstrable). Port inference on-device later only if you want the fully self-contained story.

## Where the current tools land

- `tools/telemetry_capture.py` — the collector logic for the **OpenWrt** router (`iw station dump`);
  becomes the ipk's collector.
- `tools/gn630v_telemetry.py` + `gn630v_telnet.py` — the **GN630v** collector (`iwpriv stat` over
  telnet); off-box on the laptop, proves telemetry on stock gear + generates dataset.
- `data/normal_iperf.csv` — the `normal` training class (see `docs/beamcraft-attack-context.md` for
  metrics + attack mechanics; `docs/hardware/gn630v-uart-recon.md` for the sensor fields).
