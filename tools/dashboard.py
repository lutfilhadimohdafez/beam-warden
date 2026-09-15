"""Beam Warden live telemetry dashboard backend.

Live telnet poll of the GN630v (or CSV replay) → WebSocket broadcast.
Starlette ASGI + uvicorn, stdlib + starlette only — no FastAPI, no pydantic.

ponytail: one module, one producer task, one broadcast loop. keep it flat.
"""

import argparse
import asyncio
import csv
import json
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path

import joblib
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gn630v_telemetry import compute_deltas, parse_iwpriv_stat
from gn630v_telnet import GN630V
from starlette.applications import Starlette
from starlette.responses import FileResponse
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.staticfiles import StaticFiles
from starlette.websockets import WebSocket

# ── module-level state read by the app ────────────────────────────────────
args: argparse.Namespace  # set in __main__ before uvicorn.run
clients: set[WebSocket] = set()
latest_sample: dict | None = None

_HERE = Path(__file__).resolve().parent

# ── ML anomaly detector (loaded once at import) ────────────────────────────
_MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "detector.joblib"
try:
    DETECTOR: dict | None = joblib.load(_MODEL_PATH)
except Exception:
    DETECTOR = None


def score_sample(msg: dict) -> tuple[float | None, bool]:
    """Return (anomaly_score, is_anomaly) using the trained IsolationForest."""
    if DETECTOR is None:
        return (None, False)
    feats = [[float(msg.get(f, 0) or 0) for f in DETECTOR["features"]]]
    X = DETECTOR["scaler"].transform(np.array(feats))
    score = float(DETECTOR["model"].decision_function(X)[0])
    is_anom = bool(DETECTOR["model"].predict(X)[0] == -1)
    return (score, is_anom)


# ── message builder (shared by live & replay) ─────────────────────────────
def _build_message(
    *,
    mode: str,
    status: str,
    error: str | None,
    throughput_tx_mbps: float,
    throughput_rx_mbps: float,
    retry_rate: float,
    tx_per_pct: float,
    rx_per_pct: float,
    rssi0: int,
    rssi1: int,
    rssi2: int,
    rssi3: int,
    tx_mcs: int | None,
    tx_nss: int | None,
    tx_bw: str | None,
    tx_phymode: str | None,
    temp_c: int,
) -> dict:
    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "mode": mode,
        "status": status,
        "error": error,
        "throughput_tx_mbps": throughput_tx_mbps,
        "throughput_rx_mbps": throughput_rx_mbps,
        "retry_rate": retry_rate,
        "tx_per_pct": tx_per_pct,
        "rx_per_pct": rx_per_pct,
        "rssi0": rssi0,
        "rssi1": rssi1,
        "rssi2": rssi2,
        "rssi3": rssi3,
        "tx_mcs": tx_mcs,
        "tx_nss": tx_nss,
        "tx_bw": tx_bw,
        "tx_phymode": tx_phymode,
        "temp_c": temp_c,
        "anomaly_score": None,
        "is_anomaly": False,
    }


# ── broadcast helper ──────────────────────────────────────────────────────
async def _broadcast(msg: dict) -> None:
    global latest_sample
    latest_sample = msg
    payload = json.dumps(msg)
    dead: list[WebSocket] = []
    for ws in clients:
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        clients.discard(ws)


# ── producer: live mode ───────────────────────────────────────────────────
async def _producer_live() -> None:
    ont = None
    prev: dict | None = None
    prev_t: float | None = None

    while True:
        try:
            if ont is None:
                ont = await asyncio.to_thread(
                    GN630V, args.host, args.user, args.password
                )
                await asyncio.to_thread(ont.__enter__)

            tick = time.time()
            text = await asyncio.to_thread(ont.run, f"iwpriv {args.iface} stat")
            parsed = await asyncio.to_thread(parse_iwpriv_stat, text)
            now = time.time()

            if prev is not None and prev_t is not None:
                dt = now - prev_t
                deltas = compute_deltas(prev, parsed, dt) if dt > 0 else {}
            else:
                deltas = {}

            msg = _build_message(
                mode="live",
                status="ok",
                error=None,
                throughput_tx_mbps=deltas.get("throughput_tx_mbps", 0.0),
                throughput_rx_mbps=deltas.get("throughput_rx_mbps", 0.0),
                retry_rate=deltas.get("retry_rate", 0.0),
                tx_per_pct=parsed["tx_per_pct"],
                rx_per_pct=parsed["rx_per_pct"],
                rssi0=parsed["rssi0"],
                rssi1=parsed["rssi1"],
                rssi2=parsed["rssi2"],
                rssi3=parsed["rssi3"],
                tx_mcs=parsed["tx_mcs"],
                tx_nss=parsed["tx_nss"],
                tx_bw=parsed["tx_bw"],
                tx_phymode=parsed["tx_phymode"],
                temp_c=parsed["temp_c"],
            )
            score, is_anom = score_sample(msg)
            msg["anomaly_score"] = score
            msg["is_anomaly"] = is_anom
            await _broadcast(msg)

            prev = parsed
            prev_t = now
            elapsed = time.time() - tick
            await asyncio.sleep(max(0.0, args.interval - elapsed))

        except Exception as exc:
            # ponytail: emit error, forget session, retry next tick
            err_msg = _build_message(
                mode="live",
                status="error",
                error=str(exc),
                throughput_tx_mbps=0.0,
                throughput_rx_mbps=0.0,
                retry_rate=0.0,
                tx_per_pct=0.0,
                rx_per_pct=0.0,
                rssi0=0,
                rssi1=0,
                rssi2=0,
                rssi3=0,
                tx_mcs=None,
                tx_nss=None,
                tx_bw=None,
                tx_phymode=None,
                temp_c=0,
            )
            await _broadcast(err_msg)
            if ont is not None:
                try:
                    await asyncio.to_thread(ont.__exit__, None, None, None)
                except Exception:
                    pass
                ont = None
            prev = None
            prev_t = None
            await asyncio.sleep(args.interval)


# ── producer: replay mode ─────────────────────────────────────────────────
async def _producer_replay() -> None:
    csv_path = Path(args.csv)
    rows: list[dict] = []
    with csv_path.open(newline="") as f:
        for row in csv.DictReader(f):
            rows.append(row)

    idx = 0
    while True:
        row = rows[idx % len(rows)]
        msg = _build_message(
            mode="replay",
            status="ok",
            error=None,
            throughput_tx_mbps=float(row["throughput_tx_mbps"]),
            throughput_rx_mbps=float(row["throughput_rx_mbps"]),
            retry_rate=float(row["retry_rate"]),
            tx_per_pct=float(row["tx_per_pct"]),
            rx_per_pct=float(row["rx_per_pct"]),
            rssi0=int(float(row["rssi0"])),
            rssi1=int(float(row["rssi1"])),
            rssi2=int(float(row["rssi2"])),
            rssi3=int(float(row["rssi3"])),
            tx_mcs=int(float(row["tx_mcs"])) if row.get("tx_mcs") else None,
            tx_nss=int(float(row["tx_nss"])) if row.get("tx_nss") else None,
            tx_bw=row.get("tx_bw") or None,
            tx_phymode=row.get("tx_phymode") or None,
            temp_c=int(float(row["temp_c"])),
        )
        score, is_anom = score_sample(msg)
        msg["anomaly_score"] = score
        msg["is_anomaly"] = is_anom
        await _broadcast(msg)
        idx += 1
        await asyncio.sleep(args.interval)


# ── lifespan: start/stop the producer (Starlette 1.x API) ─────────────────
@asynccontextmanager
async def _lifespan(app):
    producer = _producer_replay if args.mode == "replay" else _producer_live
    task = asyncio.create_task(producer())
    try:
        yield
    finally:
        task.cancel()


# ── routes ────────────────────────────────────────────────────────────────
async def _homepage(request):
    return FileResponse(_HERE / "dashboard.html")


async def _ws_handler(websocket: WebSocket) -> None:
    await websocket.accept()
    clients.add(websocket)
    if latest_sample is not None:
        await websocket.send_text(json.dumps(latest_sample))
    try:
        while True:
            await websocket.receive_text()  # keep alive; ignore payloads
    except Exception:
        pass
    finally:
        clients.discard(websocket)


# ── app assembly ──────────────────────────────────────────────────────────
app = Starlette(
    routes=[
        Route("/", _homepage),
        Mount("/static", StaticFiles(directory=str(_HERE / "static"))),
        WebSocketRoute("/ws", _ws_handler),
    ],
    lifespan=_lifespan,
)


# ── CLI entry point ───────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    p = argparse.ArgumentParser(
        description="Beam Warden live telemetry dashboard backend"
    )
    p.add_argument("--host", default="192.168.0.1")
    p.add_argument("--user", default="tmadmin")
    p.add_argument("--password", default="REDACTED")
    p.add_argument("--iface", default="rai1")
    p.add_argument("--interval", type=float, default=2.0)
    p.add_argument("--mode", choices=["live", "replay"], default="live")
    p.add_argument("--csv", default="data/normal_iperf.csv")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--bind", default="127.0.0.1")
    args = p.parse_args()

    uvicorn.run(app, host=args.bind, port=args.port, log_level="info")
