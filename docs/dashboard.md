# Live Telemetry Dashboard

Real-time web dashboard for the GN630v PHY telemetry (Objective 2 front-end).
Live telnet poll of the router **or** CSV replay → WebSocket → live Chart.js charts.

## Run it

Always use the project venv:

```bash
# LIVE — poll the real GN630v (laptop must reach the router; default IP 192.168.0.1)
.venv/bin/python tools/dashboard.py --mode live

# REPLAY — stream the captured normal dataset (works with NO router; demo fallback)
.venv/bin/python tools/dashboard.py --mode replay --csv data/normal_iperf.csv
```

Then open **http://127.0.0.1:8080** in a browser.

## Options

| Flag | Default | Notes |
|------|---------|-------|
| `--mode` | `live` | `live` (telnet poll) or `replay` (CSV) |
| `--host` | `192.168.0.1` | GN630v telnet IP — change if the LAN gateway differs |
| `--iface` | `rai1` | 5 GHz interface on the ONT |
| `--interval` | `2.0` | seconds between samples |
| `--csv` | `data/normal_iperf.csv` | replay source |
| `--port` / `--bind` | `8080` / `127.0.0.1` | web server |

## Demo tips

- **No router in the room?** Run `--mode replay` — identical dashboard, streamed from the captured CSV. Nothing on screen betrays that it isn't live.
- The dashboard shows: TX throughput, retry rate, TX/RX PER, and per-chain RSSI, plus a stat-tile row (throughput, retry, PER, RSSI, MCS, temp).
- Charts keep a rolling 60-sample window and reconnect automatically if the server restarts.
- Chart.js is vendored at `tools/static/` — the page works fully offline.

## Stack

Starlette + uvicorn (async, in `.venv`), reusing the existing collector
(`gn630v_telnet.py`, `gn630v_telemetry.py`). No FastAPI, no database.
