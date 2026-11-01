#!/bin/bash
# Controlled LIVE demo prep for Beam-Warden.
#
# WHY: Wi-Fi RF drifts (RSSI/rate adapt), so a baseline learned minutes ago goes
# stale and normal traffic can look like an attack (link-drift false positive, see
# docs/detector-characterization.md). This script makes the calibrate->attack gap
# ~SECONDS so the baseline matches current conditions -> clean detection.
#
# RUN THIS, then IMMEDIATELY fire the attack when it prints GO.
# ponytail: thin orchestration; the attack itself stays a separate pkexec (needs root).
set -e
cd /home/lutfil/fyp
PHONE=192.168.1.105; PORT=5201
SSHR="sshpass -p admin ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=25 root@192.168.1.1"

echo "### 1/4 checking the phone iperf3 server..."
if ! timeout 5 iperf3 -c $PHONE -p $PORT -t 1 >/dev/null 2>&1; then
  echo "    iperf3 down -> restarting via adb"
  DEV=$(adb devices | awk '/\tdevice$/{print $1; exit}')
  adb -s "$DEV" shell input keyevent 224 >/dev/null 2>&1; sleep 1
  adb -s "$DEV" shell am start -n com.termux/.app.TermuxActivity >/dev/null 2>&1; sleep 2
  adb -s "$DEV" shell input text "iperf3%s-s%s-p%s$PORT" >/dev/null 2>&1
  adb -s "$DEV" shell input keyevent 66 >/dev/null 2>&1; sleep 2
  timeout 5 iperf3 -c $PHONE -p $PORT -t 1 >/dev/null 2>&1 || { echo "    iperf3 STILL down - fix the phone first"; exit 1; }
fi
echo "    iperf3 UP.  current link: $($SSHR 'iw dev phy1-ap0 station dump | grep -m1 signal:' 2>/dev/null)"

echo "### 2/4 FRESH heavy-load calibrate (~20s) - do NOT attack yet..."
iperf3 -c $PHONE -p $PORT -t 26 >/dev/null 2>&1 & IPF=$!
sleep 2
$SSHR 'sed -i "s/^CAL_SECONDS=.*/CAL_SECONDS=20/" /etc/beamwarden.conf; /usr/bin/beamwarden calibrate' 2>&1 | tail -1
kill $IPF 2>/dev/null

echo "### 3/4 starting the ML watcher (fresh baseline)..."
$SSHR '/etc/init.d/beamwarden enable 2>/dev/null; /etc/init.d/beamwarden restart 2>/dev/null; rm -f /tmp/beamwarden.last_alert; sleep 1; echo "    baseline: $(cat /var/run/beamwarden.base)"' 2>&1

echo "### 4/4 ================================================================"
echo "    GO!  Fire the attack NOW (within ~20s, while the baseline is fresh):"
echo ""
echo "      ! pkexec /home/lutfil/fyp/.venv/bin/python /home/lutfil/fyp/tools/obj1_auto.py 550"
echo ""
echo "    Watch: dashboard panel flips ATTACK + Telegram alert from the router."
echo "    (logread -e beamwarden -f  on the router to see it fire)"
echo "================================================================"
