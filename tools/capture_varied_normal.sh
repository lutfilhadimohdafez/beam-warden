#!/bin/bash
# Capture varied-normal telemetry (no attack) across realistic load profiles so the
# detector learns normal's FULL range (fixes the demand-confound false positives).
cd /home/lutfil/fyp
OUT="data/normal_varied_$(date +%Y%m%d_%H%M%S).csv"
PHONE=192.168.1.105; PORT=5201; DUR=45
cap() { .venv/bin/python tools/mt76_capture.py --label normal --condition "$1" --duration "$DUR" --out "$OUT"; }

echo "### idle (no traffic)";        cap idle
echo "### light (~2 Mbps)";          iperf3 -c $PHONE -p $PORT -t $((DUR+5)) -b 2M  >/dev/null 2>&1 & P=$!; cap light;  kill $P 2>/dev/null
echo "### medium (~15 Mbps)";        iperf3 -c $PHONE -p $PORT -t $((DUR+5)) -b 15M >/dev/null 2>&1 & P=$!; cap medium; kill $P 2>/dev/null
echo "### heavy (unlimited)";        iperf3 -c $PHONE -p $PORT -t $((DUR+5))        >/dev/null 2>&1 & P=$!; cap heavy;  kill $P 2>/dev/null
echo "### bursty (3s on / 2s off)";  ( e=$((SECONDS+DUR+5)); while [ $SECONDS -lt $e ]; do iperf3 -c $PHONE -p $PORT -t 3 >/dev/null 2>&1; sleep 2; done ) & P=$!; cap bursty; kill $P 2>/dev/null

echo "=== DONE: $OUT ==="
echo "rows per condition:"; tail -n +2 "$OUT" | cut -d, -f2,3 | sort | uniq -c
echo "VARIED_NORMAL_CSV=$OUT"
