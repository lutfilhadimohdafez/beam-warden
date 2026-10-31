#!/bin/sh
# beamwarden - standalone BFI-storm anomaly detector for OpenWrt.
#
# Physics, not magic: a beamforming-injection attack (BeamCraft-style) sprays
# FORGED VHT compressed-beamforming frames (802.11 mgmt Action-No-Ack, subtype
# 0xe0, category 21) at the AP. That does two measurable things on air:
#   1. the on-air BFI frame RATE for the victim client roughly DOUBLES, and
#   2. ~half the forged frames carry the RETRY bit (re-injection), where normal
#      sounding carries it ~never.
# Validated offline against a real capture: tcpdump 'wlan[0]==0xe0 and wlan src
# <mac>' counts exactly the same frames tshark's category_code==21 filter does
# (1381 == 1381), and over a real heavy+bursty NORMAL capture the thresholds
# below tripped 0/33 windows.
#
# This detector does NOT ship a fixed magic number. It CALIBRATES the normal BFI
# envelope on the network it is deployed to, then alerts on a surge above that
# learned ceiling or a retry-ratio spike. That is the answer to "does it work on
# a network that isn't the lab" - it learns *your* normal first.
#
# ponytail: one ash script, tcpdump for counting, logger for alerts. No python,
#           no sklearn, no MQTT, no LuCI. Add those only if a demo needs them.

CONF=/etc/beamwarden.conf
[ -f "$CONF" ] && . "$CONF"

# --- defaults (overridable in /etc/beamwarden.conf) ------------------------
AP_IF="${AP_IF:-wlan0}"        # the AP radio interface to tap
MON="${MON:-bwmon0}"           # monitor vif this tool creates on AP_IF
MAC="${MAC:-}"                 # client MAC to protect; empty = any client
WIN="${WIN:-2}"                # window seconds (matches the trained pipeline)
CAL_SECONDS="${CAL_SECONDS:-120}"
MARGIN="${MARGIN:-40}"         # alert ceiling = normal_peak * (100+MARGIN)%
RATIO_PCT="${RATIO_PCT:-25}"   # retry-ratio alert threshold, percent (normal~0, attack~50)
DEFAULT_CEIL="${DEFAULT_CEIL:-24}"   # fallback ceiling if never calibrated
STATE_CEIL=/var/run/beamwarden.ceil
ALERT_HOOK=/etc/beamwarden/on_alert   # optional: your script, args: bfi ceil ratio%
TMP=/tmp/bw_win.pcap

log() { logger -t beamwarden "$@"; }

ensure_mon() {
	iw dev "$MON" info >/dev/null 2>&1 && return 0
	iw dev "$AP_IF" interface add "$MON" type monitor >/dev/null 2>&1
	ip link set "$MON" up >/dev/null 2>&1
	iw dev "$MON" info >/dev/null 2>&1
}

# capture one WIN-second window, print "<bfi_count> <retry_bfi_count>"
count_window() {
	local filt="wlan[0]==0xe0"
	[ -n "$MAC" ] && filt="$filt and wlan src $MAC"
	timeout "$WIN" tcpdump -i "$MON" -nn -w "$TMP" "$filt" >/dev/null 2>&1
	local b r
	b=$(tcpdump -r "$TMP" -nn 2>/dev/null | grep -c .)
	r=$(tcpdump -r "$TMP" -nn "wlan[1]&0x8!=0" 2>/dev/null | grep -c .)
	rm -f "$TMP"
	echo "${b:-0} ${r:-0}"
}

cmd_calibrate() {
	ensure_mon || { echo "cannot create monitor vif $MON on $AP_IF"; exit 1; }
	echo "calibrating ${CAL_SECONDS}s of NORMAL traffic on $MON (mac=${MAC:-any})..."
	echo "run your usual load now (browsing/streaming/download). do NOT attack."
	local n=$((CAL_SECONDS / WIN)) i=0 maxb=0
	while [ $i -lt $n ]; do
		set -- $(count_window); [ "$1" -gt "$maxb" ] && maxb=$1
		i=$((i+1))
	done
	local ceil=$(( maxb * (100 + MARGIN) / 100 ))
	[ $ceil -lt $((maxb + 6)) ] && ceil=$((maxb + 6))
	echo "$ceil" > "$STATE_CEIL"
	log "calibrated: normal peak=${maxb}/${WIN}s -> alert ceiling=${ceil}, retry>${RATIO_PCT}%"
	echo "baseline learned: normal peak ${maxb} BFI/${WIN}s  ->  alert ceiling ${ceil}"
}

cmd_watch() {
	ensure_mon || { log "cannot create monitor vif $MON on $AP_IF"; exit 1; }
	local ceil; ceil=$(cat "$STATE_CEIL" 2>/dev/null || echo "$DEFAULT_CEIL")
	log "watching $MON: ceiling=${ceil} BFI/${WIN}s, retry>${RATIO_PCT}%, mac=${MAC:-any}"
	while :; do
		set -- $(count_window); local b=$1 r=$2 ratio=0
		[ "$b" -gt 0 ] && ratio=$(( r * 100 / b ))
		if [ "$b" -gt "$ceil" ] || [ "$ratio" -gt "$RATIO_PCT" ]; then
			log "ALERT beamforming-injection: ${b} BFI/${WIN}s (ceil ${ceil}), retry ${ratio}% (th ${RATIO_PCT}%), src=${MAC:-any}"
			[ -x "$ALERT_HOOK" ] && "$ALERT_HOOK" "$b" "$ceil" "$ratio" &
		fi
	done
}

cmd_status() {
	echo "AP_IF=$AP_IF MON=$MON mac=${MAC:-any} win=${WIN}s"
	echo "ceiling=$(cat "$STATE_CEIL" 2>/dev/null || echo "$DEFAULT_CEIL (uncalibrated)") retry_th=${RATIO_PCT}%"
	iw dev "$MON" info >/dev/null 2>&1 && echo "monitor $MON: UP" || echo "monitor $MON: DOWN"
}

case "$1" in
	calibrate) cmd_calibrate ;;
	watch)     cmd_watch ;;
	status)    cmd_status ;;
	*) echo "usage: beamwarden {calibrate|watch|status}"; exit 1 ;;
esac
