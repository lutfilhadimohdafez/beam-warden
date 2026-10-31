#!/bin/sh
# beamwarden - adapter-free beamforming-attack detector for OpenWrt.
#
# PORTABLE BY DESIGN: reads ONLY `iw dev <ap> station dump` - the per-client
# telemetry every OpenWrt router already exposes. No monitor mode, no capture
# adapter, no tcpdump, no python. Runs on any router `iw` runs on.
#
# What it watches: a BeamCraft-style forged-BFI attack misdirects the AP's beam,
# so the victim can't ACK -> the AP RETRANSMITS -> its own tx-retry / tx-fail
# (PER) counters climb, MCS/throughput sag. Those are the station-dump fields.
#
# SELF-CALIBRATING: every network's normal is different (a quiet home != a busy
# hall), so `calibrate` learns THIS network's baseline retry/PER once, and `watch`
# alerts on a sustained spike ABOVE that baseline. Relative, not a hard-coded lab
# number -> transfers to a network it never saw.
#
# HONEST LIMIT (see README): detection reads the attack's EFFECT on the link. When
# the attack is fully covert (strong link, no degradation) the telemetry barely
# moves and detection weakens. Catching the forged frames directly would fix that
# but needs monitor mode, which many routers can't do - hence this telemetry path.
#
# ponytail: one ash script, iw + awk only. No ML runtime on the router; the
#           RandomForest (tools/train_telemetry.py) is trained offline and its
#           decision is distilled to the calibrated relative thresholds below.

CONF=/etc/beamwarden.conf
[ -f "$CONF" ] && . "$CONF"

AP_IF="${AP_IF:-wlan0}"        # the AP interface to watch (e.g. phy1-ap0 / wlan0)
MAC="${MAC:-}"                 # client MAC to protect; empty = aggregate all clients
WIN="${WIN:-2}"               # seconds per detection window
CAL_SECONDS="${CAL_SECONDS:-120}"
RETRY_MULT="${RETRY_MULT:-1.5}"   # alert if retry_rate > baseline * this
PER_MULT="${PER_MULT:-1.5}"       # alert if tx-PER    > baseline * this
HITS_TO_ALARM="${HITS_TO_ALARM:-3}"  # consecutive bad windows before alerting (noise guard)
STATE=/var/run/beamwarden.base
ALERT_HOOK=/etc/beamwarden/on_alert   # optional: your script, args: retry_rate per_rate

log() { logger -t beamwarden "$@"; }

# aggregate tx retries/packets/failed (and mean signal) across the target station(s)
# prints: "<retries> <packets> <failed>"
counters() {
	iw dev "$AP_IF" station dump 2>/dev/null | awk -v mac="$MAC" '
		/^Station/ { s=$2; want=(mac=="" || s==mac) }
		want && /tx retries:/ { r+=$3 }
		want && /tx packets:/ { p+=$3 }
		want && /tx failed:/  { f+=$3 }
		END { printf "%d %d %d\n", r, p, f }'
}

# one window: print "<retry_rate> <per_rate>" (fraction 0..1) over WIN seconds
sample() {
	set -- $(counters); local r1=$1 p1=$2 f1=$3
	sleep "$WIN"
	set -- $(counters); local r2=$1 p2=$2 f2=$3
	awk -v dr=$((r2-r1)) -v dp=$((p2-p1)) -v df=$((f2-f1)) 'BEGIN{
		tot=dp+dr; if(tot<1)tot=1;
		sent=dp+df; if(sent<1)sent=1;
		printf "%.4f %.4f\n", dr/tot, df/sent }'
}

cmd_calibrate() {
	echo "calibrating ${CAL_SECONDS}s of NORMAL traffic on $AP_IF (mac=${MAC:-all})..."
	echo "use the network normally now; do NOT run the attack."
	local n=$((CAL_SECONDS / WIN)) i=0 rsum=0 psum=0
	while [ $i -lt $n ]; do
		set -- $(sample); rsum=$(awk -v a=$rsum -v b=$1 'BEGIN{print a+b}')
		psum=$(awk -v a=$psum -v b=$2 'BEGIN{print a+b}'); i=$((i+1))
	done
	local rb=$(awk -v s=$rsum -v n=$n 'BEGIN{printf "%.4f", (n?s/n:0)}')
	local pb=$(awk -v s=$psum -v n=$n 'BEGIN{printf "%.4f", (n?s/n:0)}')
	echo "$rb $pb" > "$STATE"
	log "calibrated baseline retry=$rb per=$pb (alert at x$RETRY_MULT / x$PER_MULT)"
	echo "baseline learned: retry=$rb  per=$pb  -> alerts above x$RETRY_MULT"
}

cmd_watch() {
	local rb pb
	read rb pb < "$STATE" 2>/dev/null || { rb=0.05; pb=0.02; log "no baseline - run 'beamwarden calibrate'; using weak defaults"; }
	local rth=$(awk -v b=$rb -v m=$RETRY_MULT 'BEGIN{printf "%.4f", b*m}')
	local pth=$(awk -v b=$pb -v m=$PER_MULT 'BEGIN{printf "%.4f", b*m}')
	log "watching $AP_IF: retry>$rth or per>$pth (baseline retry=$rb per=$pb), mac=${MAC:-all}"
	local hits=0
	while :; do
		set -- $(sample); local r=$1 p=$2
		local bad=$(awk -v r=$r -v p=$p -v rt=$rth -v pt=$pth 'BEGIN{print (r>rt||p>pt)?1:0}')
		if [ "$bad" = "1" ]; then
			hits=$((hits+1))
			if [ $hits -ge $HITS_TO_ALARM ]; then
				log "ALERT beamforming-attack: retry=$r (th $rth) per=$p (th $pth) mac=${MAC:-all}"
				[ -x "$ALERT_HOOK" ] && "$ALERT_HOOK" "$r" "$p" &
				hits=0
			fi
		else
			hits=0
		fi
	done
}

cmd_status() {
	echo "AP_IF=$AP_IF mac=${MAC:-all} win=${WIN}s"
	if read rb pb < "$STATE" 2>/dev/null; then echo "baseline: retry=$rb per=$pb (x$RETRY_MULT/x$PER_MULT)"
	else echo "baseline: UNCALIBRATED - run 'beamwarden calibrate'"; fi
	set -- $(sample); echo "now: retry=$1 per=$2"
}

case "$1" in
	calibrate) cmd_calibrate ;;
	watch)     cmd_watch ;;
	status)    cmd_status ;;
	*) echo "usage: beamwarden {calibrate|watch|status}"; exit 1 ;;
esac
