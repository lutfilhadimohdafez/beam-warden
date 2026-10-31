#
# Beam-Warden: standalone BFI-storm anomaly detector (OpenWrt package)
# Build on the laptop with the OpenWrt SDK; install on the router with opkg.
#
include $(TOPDIR)/rules.mk

PKG_NAME:=beamwarden
PKG_VERSION:=0.1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/beamwarden
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Beam-Warden beamforming-injection (BFI-storm) detector
  URL:=https://beamwarden.coldcollectives.my
  DEPENDS:=+tcpdump-mini +iw
  PKGARCH:=all
endef

define Package/beamwarden/description
  Detects WiFi beamforming-feedback injection (BeamCraft-style) attacks on-device
  by watching the on-air VHT compressed-BF frame rate and retry ratio. Self-
  calibrates a per-network normal baseline; no python/sklearn/cloud needed.
endef

# nothing to cross-compile - it is a shell detector + configs
define Build/Compile
endef

define Package/beamwarden/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d $(1)/etc/beamwarden
	$(INSTALL_BIN) ./files/beamwarden.sh   $(1)/usr/bin/beamwarden
	$(INSTALL_BIN) ./files/beamwarden.init $(1)/etc/init.d/beamwarden
	$(INSTALL_CONF) ./files/beamwarden.conf $(1)/etc/beamwarden.conf
endef

define Package/beamwarden/conffiles
/etc/beamwarden.conf
endef

$(eval $(call BuildPackage,beamwarden))
