#!/bin/sh
# beamwarden - adapter-free beamforming-attack detector for OpenWrt.
#
# Reads ONLY `iw dev <ap> station dump` (retry / PER / throughput / RSSI) - telemetry
# every OpenWrt router has. No monitor mode, no capture adapter, no python.
#
# It ships the TRAINED RandomForest as an awk tree-walk (model.awk) - the real ML
# engine runs ON the router. Self-calibrated RELATIVE features (ratio + z vs this
# network's baseline) so one trained model transfers to any network. Falls back to a
# retry/PER threshold if model.awk is missing.
#
#   calibrate : learn this network's normal (mean+std of 4 metrics) - NO attack needed
#   watch     : each window -> 8 relative features -> model.awk verdict -> on_alert
#   status    : show config, baseline, and the current live reading
# ponytail: one ash script + awk; the heavy ML stays offline (export_model.py).

CONF=/etc/beamwarden.conf
[ -f "$CONF" ] && . "$CONF"

AP_IF="${AP_IF:-wlan0}"
MAC="${MAC:-}"                       # client MAC to protect; empty = aggregate all
WIN="${WIN:-2}"
CAL_SECONDS="${CAL_SECONDS:-120}"
HITS_TO_ALARM="${HITS_TO_ALARM:-3}"  # consecutive attack windows before alerting
ACTIVE_MIN_PKTS="${ACTIVE_MIN_PKTS:-100}"  # skip detection when the link is idle (no
                                     # traffic -> throughput 0 looks like a collapse);
                                     # the model only knows under-load normal vs attack
RETRY_MULT="${RETRY_MULT:-1.5}"      # fallback threshold only (no model.awk)
RETRY_FLOOR="${RETRY_FLOOR:-0.30}"   # fallback threshold only
MODEL="${MODEL:-/etc/beamwarden/model.awk}"
STATE=/var/run/beamwarden.base
ALERT_HOOK=/etc/beamwarden/on_alert
TMP=/tmp/bw_cal.$$

log() { logger -t beamwarden "$@"; }

# aggregate counters for the target station(s): "retries packets failed txbytes rssi"
# rssi = mean of the per-chain values in the `signal:` line.
counters() {
	iw dev "$AP_IF" station dump 2>/dev/null | awk -v mac="$MAC" '
		/^Station/ { s=$2; want=(mac=="" || tolower(s)==tolower(mac)) }
		want && /tx retries:/ { r+=$3 }
		want && /tx packets:/ { p+=$3 }
		want && /tx failed:/  { f+=$3 }
		want && /tx bytes:/   { b+=$3 }
		want && /signal:/ && $0 !~ /avg/ {
			g=$0; sub(/.*\[/,"",g); sub(/\].*/,"",g); gsub(/,/," ",g)
			ns=split(g,ch," "); sm=0; for(i=1;i<=ns;i++) sm+=ch[i]
			if (ns) { rsum+=sm/ns; rn++ } }
		END { printf "%.0f %.0f %.0f %.0f %.1f\n", r, p, f, b, (rn?rsum/rn:-60) }'
}

# one WIN-second window -> "retry_rate tx_per throughput_mbps rssi"
sample() {
	set -- $(counters); local r1=$1 p1=$2 f1=$3 b1=$4
	sleep "$WIN"
	set -- $(counters); local r2=$1 p2=$2 f2=$3 b2=$4 rs2=$5
	awk -v dr=$((r2-r1)) -v dp=$((p2-p1)) -v df=$((f2-f1)) -v db=$((b2-b1)) -v rs="$rs2" -v w="$WIN" 'BEGIN{
		tot=dp+dr; if(tot<1)tot=1; sent=dp+df; if(sent<1)sent=1
		printf "%.5f %.5f %.3f %.1f %.0f\n", dr/tot, df/sent, db*8/w/1e6, rs, dp+dr }'
}

ensure_iface() { iw dev "$AP_IF" info >/dev/null 2>&1 || { log "AP_IF $AP_IF not found (check iw dev)"; return 1; }; }

cmd_calibrate() {
	ensure_iface || exit 1
	echo "calibrating ${CAL_SECONDS}s of NORMAL traffic on $AP_IF (mac=${MAC:-all}) - do NOT attack."
	: > "$TMP"; local n=$((CAL_SECONDS / WIN)) i=0
	while [ $i -lt $n ]; do sample >> "$TMP"; i=$((i+1)); done
	# per-metric mean + population std (cols: retry per tput rssi) -> 8 numbers
	awk '{ for(j=1;j<=4;j++){ s[j]+=$j; q[j]+=$j*$j } }
	     END{ if(NR<1){ print "0 0 0 0 0 0 0 0"; exit }
	          for(j=1;j<=4;j++){ m=s[j]/NR; v=q[j]/NR-m*m; if(v<0)v=0; printf "%.6f %.6f ", m, sqrt(v) } print "" }' "$TMP" > "$STATE"
	rm -f "$TMP"
	log "calibrated baseline (retry/PER/tput/rssi mean+std): $(cat "$STATE")"
	echo "baseline learned: $(cat "$STATE")"
}

cmd_watch() {
	ensure_iface || exit 1
	[ -f "$STATE" ] || log "no baseline - run 'beamwarden calibrate' (detection weak until then)"
	local rm rsd pm psd tm tsd rsm rssd
	read rm rsd pm psd tm tsd rsm rssd < "$STATE" 2>/dev/null
	: ${rm:=0.05} ${rsd:=0.02} ${pm:=0.02} ${psd:=0.02} ${tm:=20} ${tsd:=10} ${rsm:=-60} ${rssd:=5}
	local use_model=0; [ -f "$MODEL" ] && use_model=1
	log "watching $AP_IF (engine=$([ $use_model = 1 ] && echo ML-forest || echo threshold), mac=${MAC:-all})"
	local hits=0 r p t rssi act verdict thr
	while :; do
		set -- $(sample); r=$1 p=$2 t=$3 rssi=$4 act=$5
		if [ "${act:-0}" -lt "$ACTIVE_MIN_PKTS" ]; then
			verdict=0; hits=0        # link idle -> nothing to attack; don't evaluate
		elif [ $use_model = 1 ]; then
			# 8 relative features in model order, then walk the forest
			verdict=$(awk -v r=$r -v p=$p -v t=$t -v rssi=$rssi \
				-v rm=$rm -v rsd=$rsd -v pm=$pm -v psd=$psd -v tm=$tm -v tsd=$tsd -v rsm=$rsm -v rssd=$rssd 'BEGIN{
				e=1e-6; printf "%.6g %.6g %.6g %.6g %.6g %.6g %.6g %.6g\n",
					r/(rm+e),(r-rm)/(rsd+e), p/(pm+e),(p-pm)/(psd+e),
					t/(tm+e),(t-tm)/(tsd+e), rssi/(rsm+e),(rssi-rsm)/(rssd+e) }' | awk -f "$MODEL")
		else
			thr=$(awk -v b=$rm -v m=$RETRY_MULT -v fl=$RETRY_FLOOR 'BEGIN{x=b*m; if(x<fl)x=fl; print x}')
			verdict=$(awk -v r=$r -v thr=$thr 'BEGIN{print (r>thr)?1:0}')
		fi
		if [ "$verdict" = "1" ]; then
			hits=$((hits+1))
			if [ $hits -ge $HITS_TO_ALARM ]; then
				log "ALERT beamforming-attack: retry=$r PER=$p tput=${t}M rssi=$rssi mac=${MAC:-all}"
				[ -x "$ALERT_HOOK" ] && "$ALERT_HOOK" "$r" "$p" &
				hits=0
			fi
		else
			hits=0
		fi
	done
}

cmd_status() {
	echo "AP_IF=$AP_IF  mac=${MAC:-all}  win=${WIN}s  engine=$([ -f "$MODEL" ] && echo ML-forest || echo threshold)"
	if [ -f "$STATE" ]; then echo "baseline (retry/PER/tput/rssi mean+std): $(cat "$STATE")"
	else echo "baseline: UNCALIBRATED - run 'beamwarden calibrate'"; fi
	set -- $(sample); echo "now: retry=$1  PER=$2  tput=${3}M  rssi=$4"
}

case "$1" in
	calibrate) cmd_calibrate ;;
	watch)     cmd_watch ;;
	status)    cmd_status ;;
	*) echo "usage: beamwarden {calibrate|watch|status}"; exit 1 ;;
esac
