"""Beam Warden live telemetry dashboard backend.

Live telnet poll of the GN630v (or CSV replay) → WebSocket broadcast.
Starlette ASGI + uvicorn, stdlib + starlette only — no FastAPI, no pydantic.

ponytail: one module, one producer task, one broadcast loop. keep it flat.
"""

import argparse
import asyncio
import csv
import json
import subprocess
import sys
import threading
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path

import joblib
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gn630v_telemetry import compute_deltas, parse_iwpriv_stat
from gn630v_telnet import GN630V
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, JSONResponse
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.staticfiles import StaticFiles
from starlette.websockets import WebSocket

from tasks import TASK_REGISTRY, resolve_cmd

# ── module-level state read by the app ────────────────────────────────────
args: argparse.Namespace  # set in __main__ before uvicorn.run
clients: set[WebSocket] = set()
latest_sample: dict | None = None

# ── runtime session state ─────────────────────────────────────────────────
_current_task: asyncio.Task | None = None  # currently running producer task

# ── BFI live stream state (optional, set when --bfi-iface is given) ──────
BFI_LATEST: dict = {}  # thread-safe-ish: written by bfi thread, read by producer
_BFI_KEYS = [
    "bfi_phi_mean", "bfi_psi_mean", "bfi_angle_var",
    "bfi_subcarrier_var", "bfi_phi_temporal_var", "bfi_psi_temporal_var",
]
_bfi_thread: threading.Thread | None = None
_bfi_stop: threading.Event | None = None


def _merge_bfi(msg: dict) -> dict:
    """Fold latest BFI features into *msg* (no-op if BFI_LATEST is empty)."""
    if BFI_LATEST:
        for k in _BFI_KEYS:
            if k in BFI_LATEST:
                msg[k] = BFI_LATEST[k]
    return msg

# ── task runner state ─────────────────────────────────────────────────────
# ponytail: localhost-only; this is a local research rig, not a public service.
TASK_STATE: dict[str, dict] = {}  # name -> {"state": idle|running|done|failed, "pid": int|None, "code": int|None}

_HERE = Path(__file__).resolve().parent

# ── ML anomaly detector (loaded once at import) ────────────────────────────
_MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "detector.joblib"
try:
    DETECTOR: dict | None = joblib.load(_MODEL_PATH)
except Exception:
    DETECTOR = None

# ── replay playback state ─────────────────────────────────────────────────
PLAYBACK: dict = {
    "idx": 0,
    "paused": False,
    "rows": [],
    "total": 0,
    "attack_start": -1,
}


# ── calibration + anomaly history ─────────────────────────────────────────
CALIB_BUFFER: list[list[float]] = []  # list of feature vectors
_AUTO_CAPTURE: bool = False
ANOMALY_HISTORY: deque[bool] = deque(maxlen=60)  # last 60 is_anomaly results
_CALIB_CSV = Path(__file__).resolve().parent.parent / "data" / "normal_calib.csv"
_calib_target = 150
_CALIB_MIN = 30
_TRAIN_CMD = [sys.executable, str(Path(__file__).resolve().parent / "train_detector.py")]
_HISTORY_PATH = Path(__file__).resolve().parent.parent / "models" / "training_history.json"


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
        "index": 0,
        "total": 0,
        "playing": True,
        "bfi_phi_mean": None,
        "bfi_psi_mean": None,
        "bfi_angle_var": None,
        "bfi_subcarrier_var": None,
        "bfi_phi_temporal_var": None,
        "bfi_psi_temporal_var": None,
    }


# ── broadcast helper ──────────────────────────────────────────────────────
async def _broadcast(msg: dict) -> None:
    global latest_sample
    latest_sample = msg
    # Track anomaly history for rolling rate
    if msg.get("anomaly_score") is not None:
        ANOMALY_HISTORY.append(bool(msg.get("is_anomaly", False)))
    # Auto-capture: append one sample per broadcast while active
    if _AUTO_CAPTURE and msg.get("anomaly_score") is not None and len(CALIB_BUFFER) < _calib_target:
        feats = DETECTOR["features"] if DETECTOR else [
            "throughput_tx_mbps", "throughput_rx_mbps", "retry_rate",
            "tx_per_pct", "rx_per_pct", "rssi0", "rssi1", "rssi2", "rssi3",
            "tx_mcs", "tx_nss",
        ]
        vec = [float(msg.get(f, 0) or 0) for f in feats]
        CALIB_BUFFER.append(vec)
        _append_calib_csv(feats, vec)
        calib_msg = {"type": "calib", "count": len(CALIB_BUFFER), "target": _calib_target}
        payload_calib = json.dumps(calib_msg)
        dead_calib: list[WebSocket] = []
        for ws in clients:
            try:
                await ws.send_text(payload_calib)
            except Exception:
                dead_calib.append(ws)
        for ws in dead_calib:
            clients.discard(ws)
    payload = json.dumps(msg)
    dead: list[WebSocket] = []
    for ws in clients:
        try:
            await ws.send_text(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        clients.discard(ws)


# ── replay: build+score+broadcast current PLAYBACK row (shared helper) ────
async def _replay_broadcast_current() -> None:
    """Build a message from PLAYBACK.rows[PLAYBACK.idx], score it, broadcast."""
    row = PLAYBACK["rows"][PLAYBACK["idx"]]
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
    msg["raw"] = repr(row)
    score, is_anom = score_sample(msg)
    msg["anomaly_score"] = score
    msg["is_anomaly"] = is_anom
    msg["index"] = PLAYBACK["idx"]
    msg["total"] = PLAYBACK["total"]
    msg["playing"] = not PLAYBACK["paused"]
    await _broadcast(msg)


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
            msg["raw"] = text
            _merge_bfi(msg)
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

    PLAYBACK["rows"] = rows
    PLAYBACK["total"] = len(rows)
    PLAYBACK["attack_start"] = -1
    for i, r in enumerate(rows):
        if r.get("label") == "attack":
            PLAYBACK["attack_start"] = i
            break
    PLAYBACK["idx"] = 0
    PLAYBACK["paused"] = False

    while True:
        await _replay_broadcast_current()
        if not PLAYBACK["paused"]:
            PLAYBACK["idx"] = (PLAYBACK["idx"] + 1) % PLAYBACK["total"]
        await asyncio.sleep(args.interval)


# ── producer: pcap replay (BFI / CSI) ────────────────────────────────────
async def _producer_pcap(pcap_path: str) -> None:
    """Replay a .pcap file by extracting BFI features and streaming them."""
    try:
        from bfi_features import extract_features
    except ImportError:
        err = _build_message(
            mode="replay", status="error", error="bfi_features import failed",
            throughput_tx_mbps=0, throughput_rx_mbps=0, retry_rate=0,
            tx_per_pct=0, rx_per_pct=0, rssi0=0, rssi1=0, rssi2=0, rssi3=0,
            tx_mcs=None, tx_nss=None, tx_bw=None, tx_phymode=None, temp_c=0,
        )
        await _broadcast(err)
        return

    features = await asyncio.to_thread(extract_features, pcap_path)
    if not features:
        err = _build_message(
            mode="replay", status="error", error=f"No BFI frames in {pcap_path}",
            throughput_tx_mbps=0, throughput_rx_mbps=0, retry_rate=0,
            tx_per_pct=0, rx_per_pct=0, rssi0=0, rssi1=0, rssi2=0, rssi3=0,
            tx_mcs=None, tx_nss=None, tx_bw=None, tx_phymode=None, temp_c=0,
        )
        await _broadcast(err)
        return

    PLAYBACK["rows"] = features
    PLAYBACK["total"] = len(features)
    PLAYBACK["attack_start"] = -1
    PLAYBACK["idx"] = 0
    PLAYBACK["paused"] = False

    while True:
        feat = features[PLAYBACK["idx"]]
        msg = _build_message(
            mode="replay", status="ok", error=None,
            throughput_tx_mbps=0, throughput_rx_mbps=0, retry_rate=0,
            tx_per_pct=0, rx_per_pct=0, rssi0=0, rssi1=0, rssi2=0, rssi3=0,
            tx_mcs=None, tx_nss=None, tx_bw=None, tx_phymode=None, temp_c=0,
        )
        msg["raw"] = f"pcap frame {PLAYBACK['idx']}: {', '.join(f'{k}={v:.4f}' for k, v in feat.items() if isinstance(v, (int, float)))}"
        for k in _BFI_KEYS:
            if k in feat:
                msg[k] = feat[k]
        score, is_anom = score_sample(msg)
        msg["anomaly_score"] = score
        msg["is_anomaly"] = is_anom
        msg["index"] = PLAYBACK["idx"]
        msg["total"] = PLAYBACK["total"]
        msg["playing"] = not PLAYBACK["paused"]
        await _broadcast(msg)
        if not PLAYBACK["paused"]:
            PLAYBACK["idx"] = (PLAYBACK["idx"] + 1) % PLAYBACK["total"]
        await asyncio.sleep(args.interval)


# ── task runner: localhost guard ───────────────────────────────────────────
def _is_loopback(request: Request) -> bool:
    """Return True if the request came from a loopback address."""
    host = request.client.host if request.client else ""
    return host in ("127.0.0.1", "::1", "localhost", "testclient")


async def _tasks_endpoint(request: Request) -> JSONResponse:
    """GET /tasks — registry + current per-task state."""
    if not _is_loopback(request):
        return JSONResponse({"error": "localhost only"}, status_code=403)
    out = {}
    for name, entry in TASK_REGISTRY.items():
        st = TASK_STATE.get(name, {"state": "idle", "pid": None, "code": None})
        out[name] = {**entry, **st, "cmd": entry["cmd"]}
    return JSONResponse(out)


async def _run_endpoint(request: Request) -> JSONResponse:
    """POST /run/{name} — spawn task, stream logs over websocket."""
    if not _is_loopback(request):
        return JSONResponse({"error": "localhost only"}, status_code=403)
    name = request.path_params["name"]
    entry = TASK_REGISTRY.get(name)
    if entry is None:
        return JSONResponse({"error": f"unknown task: {name}"}, status_code=404)

    st = TASK_STATE.get(name, {"state": "idle", "pid": None, "code": None})
    if st["state"] == "running":
        return JSONResponse({"error": f"task {name} already running"}, status_code=409)

    # Read shared params from POST body (optional)
    try:
        body = await request.json()
    except Exception:
        body = {}
    params = body if isinstance(body, dict) else {}
    # default a run-id (empty {run} → "_air.pcap"); ensure the capture dir exists
    if not params.get("run"):
        params["run"] = time.strftime("%Y%m%d_%H%M%S")
    (Path(__file__).resolve().parent.parent / "results" / "sessions").mkdir(parents=True, exist_ok=True)

    cmd = resolve_cmd(name, params)
    if cmd is None:
        return JSONResponse({"error": "failed to resolve command"}, status_code=500)

    TASK_STATE[name] = {"state": "running", "pid": None, "code": None}

    asyncio.create_task(_run_task(name, cmd, entry["privileged"]))
    return JSONResponse({"ok": True, "task": name, "cmd": cmd})


async def _run_task(name: str, cmd: list[str], privileged: bool) -> None:
    """Spawn subprocess, stream stdout/stderr to all WS clients."""
    # ponytail: pkexec wrapper for privileged tasks (ported from attack_gui)
    if privileged:
        proc_cmd = ["pkexec"] + cmd
    else:
        proc_cmd = cmd

    proc = await asyncio.create_subprocess_exec(
        *proc_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    TASK_STATE[name]["pid"] = proc.pid

    async def _read_stream(stream, label: str):
        while True:
            line = await stream.readline()
            if not line:
                break
            text = line.decode("utf-8", errors="replace").rstrip("\n")
            msg = {"type": "log", "task": name, "stream": label, "line": text}
            await _broadcast(msg)

    await asyncio.gather(
        _read_stream(proc.stdout, "out"),
        _read_stream(proc.stderr, "err"),
    )
    code = await proc.wait()
    state = "done" if code == 0 else "failed"
    TASK_STATE[name] = {"state": state, "pid": None, "code": code}
    status_msg = {"type": "status", "task": name, "state": state, "code": code}
    await _broadcast(status_msg)


async def _stop_endpoint(request: Request) -> JSONResponse:
    """POST /stop/{name} — kill a running task."""
    if not _is_loopback(request):
        return JSONResponse({"error": "localhost only"}, status_code=403)
    name = request.path_params["name"]
    entry = TASK_REGISTRY.get(name)
    if entry is None:
        return JSONResponse({"error": f"unknown task: {name}"}, status_code=404)

    st = TASK_STATE.get(name, {"state": "idle", "pid": None, "code": None})
    if st["state"] != "running":
        return JSONResponse({"error": f"task {name} not running"}, status_code=409)

    # ponytail: root-kill for privileged tasks (ported from attack_gui)
    if entry["privileged"]:
        try:
            subprocess.run(
                ["pkexec", "pkill", "-INT", "-f", cmd_pattern(name, entry)],
                timeout=20,
            )
        except Exception:
            pass
    else:
        pid = st.get("pid")
        if pid:
            try:
                import signal as _signal
                import os
                os.kill(pid, _signal.SIGTERM)
            except Exception:
                pass

    return JSONResponse({"ok": True, "task": name})


def cmd_pattern(name: str, entry: dict) -> str:
    """Build a pkill-safe regex for the task's command."""
    cmd = entry["cmd"]
    # Use the first non-shell argument as the pattern
    for c in cmd:
        if c not in ("sh", "-c", "python"):
            return f"^{c}"
    return f"^{cmd[0]}"


# ── runtime session endpoints ─────────────────────────────────────────────
async def _replay_files_endpoint(request: Request) -> JSONResponse:
    """GET /replay-files — list .csv and .pcap files in data/."""
    if not _is_loopback(request):
        return JSONResponse({"error": "localhost only"}, status_code=403)
    data_dir = Path(__file__).resolve().parent.parent / "data"
    files = []
    if data_dir.is_dir():
        for ext in ("*.csv", "*.pcap"):
            for f in sorted(data_dir.glob(ext)):
                files.append(f.name)
    return JSONResponse(files)


async def _session_endpoint(request: Request) -> JSONResponse:
    """POST /session — cancel current producer and start a new one."""
    global _current_task
    if not _is_loopback(request):
        return JSONResponse({"error": "localhost only"}, status_code=403)
    try:
        body = await request.json()
    except Exception:
        body = {}
    source = body.get("source", "")
    if source not in ("replay", "live", "pcap"):
        return JSONResponse({"error": "source must be replay|live|pcap"}, status_code=400)

    # Cancel existing producer
    if _current_task is not None and not _current_task.done():
        _current_task.cancel()
        try:
            await _current_task
        except (asyncio.CancelledError, Exception):
            pass
        _current_task = None

    # Stop BFI stream on every session switch
    _stop_bfi()

    # Reset playback state
    PLAYBACK["rows"] = []
    PLAYBACK["total"] = 0
    PLAYBACK["attack_start"] = -1
    PLAYBACK["idx"] = 0
    PLAYBACK["paused"] = False

    if source == "replay":
        file = body.get("file", "")
        if not file:
            return JSONResponse({"error": "file required for replay"}, status_code=400)
        csv_path = Path(__file__).resolve().parent.parent / "data" / file
        if not csv_path.is_file():
            return JSONResponse({"error": f"file not found: {file}"}, status_code=404)
        args.mode = "replay"
        args.csv = str(csv_path)
        _current_task = asyncio.create_task(_producer_replay())

    elif source == "pcap":
        file = body.get("file", "")
        if not file:
            return JSONResponse({"error": "file required for pcap"}, status_code=400)
        pcap_path = Path(__file__).resolve().parent.parent / "data" / file
        if not pcap_path.is_file():
            return JSONResponse({"error": f"file not found: {file}"}, status_code=404)
        args.mode = "replay"
        _current_task = asyncio.create_task(_producer_pcap(str(pcap_path)))

    elif source == "live":
        args.mode = "live"
        args.host = body.get("host", args.host)
        args.user = body.get("user", args.user)
        args.password = body.get("password", args.password)
        args.iface = body.get("iface", args.iface)
        bfi_iface = body.get("bfi_iface", "").strip()
        if bfi_iface:
            _start_bfi(bfi_iface)
        _current_task = asyncio.create_task(_producer_live())

    # Broadcast session info
    detail = source
    if source in ("replay", "pcap"):
        detail = f"{source}: {body.get('file', '')}"
    elif source == "live":
        detail = f"live: {args.host}@{args.iface}"
        if getattr(args, "bfi_iface", None):
            detail += f" +bfi:{args.bfi_iface}"
    session_msg = {"type": "session", "source": source, "detail": detail}
    await _broadcast(session_msg)

    return JSONResponse({"ok": True, "source": source})


# ── calibration helpers ───────────────────────────────────────────────────
def _append_calib_csv(features: list[str], vec: list[float]) -> None:
    """Append a single calibration sample to data/normal_calib.csv."""
    write_header = not _CALIB_CSV.is_file()
    with _CALIB_CSV.open("a", newline="") as f:
        w = csv.writer(f)
        if write_header:
            w.writerow(features)
        w.writerow([f"{v}" for v in vec])


def _reload_detector() -> dict | None:
    """Reload the DETECTOR global from disk. Returns new DETECTOR or None."""
    global DETECTOR
    try:
        DETECTOR = joblib.load(_MODEL_PATH)
    except Exception:
        DETECTOR = None
    return DETECTOR


def _read_normal_profile() -> dict | None:
    """Read per-feature mean/min/max from data/normal_iperf.csv."""
    ref = Path(__file__).resolve().parent.parent / "data" / "normal_iperf.csv"
    if not ref.is_file():
        return None
    features = [
        "throughput_tx_mbps", "throughput_rx_mbps", "retry_rate",
        "tx_per_pct", "rx_per_pct", "rssi0", "rssi1", "rssi2", "rssi3",
        "tx_mcs", "tx_nss",
    ]
    data: dict[str, list[float]] = {f: [] for f in features}
    with ref.open(newline="") as f:
        for row in csv.DictReader(f):
            for feat in features:
                try:
                    data[feat].append(float(row.get(feat, 0) or 0))
                except (ValueError, TypeError):
                    pass
    profile = {}
    for feat in features:
        vals = data[feat]
        if vals:
            profile[feat] = {
                "mean": round(sum(vals) / len(vals), 4),
                "min": round(min(vals), 4),
                "max": round(max(vals), 4),
            }
        else:
            profile[feat] = {"mean": 0, "min": 0, "max": 0}
    return profile


# ── training history helpers ─────────────────────────────────────────────
def _load_training_history() -> list[dict]:
    """Load training history from JSON file. Returns empty list if missing."""
    if not _HISTORY_PATH.is_file():
        return []
    try:
        with _HISTORY_PATH.open() as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_training_history(entries: list[dict]) -> None:
    """Save training history list to JSON file."""
    _HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _HISTORY_PATH.open("w") as f:
        json.dump(entries, f, indent=2)


def _seed_training_history() -> None:
    """Seed initial model entry if history is empty. Best-effort."""
    if _load_training_history():
        return
    if DETECTOR is None:
        return
    profile = _read_normal_profile()
    n_samples = 0
    ref = Path(__file__).resolve().parent.parent / "data" / "normal_iperf.csv"
    if ref.is_file():
        try:
            with ref.open(newline="") as f:
                n_samples = sum(1 for _ in csv.reader(f)) - 1
        except Exception:
            pass
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "n_samples": n_samples,
        "source": "file:normal_iperf.csv",
        "interval_s": 2.0,
        "features": DETECTOR.get("features", []),
        "training_fpr": None,
        "feature_profile": profile or {},
        "model_params": {
            "n_estimators": 200,
            "contamination": DETECTOR["model"].contamination if DETECTOR else None,
        },
        "note": "initial model (seeded on dashboard load)",
    }
    _save_training_history([entry])


# ── model status endpoint ─────────────────────────────────────────────────
async def _model_status(request: Request) -> JSONResponse:
    if not _is_loopback(request):
        return JSONResponse({"error": "localhost only"}, status_code=403)
    features = DETECTOR["features"] if DETECTOR else []
    n_samples = len(CALIB_BUFFER)
    if DETECTOR is not None:
        try:
            ref = Path(__file__).resolve().parent.parent / "data" / "normal_iperf.csv"
            with ref.open(newline="") as f:
                n_samples = sum(1 for _ in csv.reader(f)) - 1  # minus header
        except Exception:
            pass
    contamination = DETECTOR["model"].contamination if DETECTOR else None
    profile = _read_normal_profile()
    total = len(ANOMALY_HISTORY)
    anomalies = sum(1 for v in ANOMALY_HISTORY if v)
    anomaly_rate = anomalies / total if total > 0 else 0.0
    return JSONResponse({
        "model_loaded": DETECTOR is not None,
        "features": features,
        "n_samples": n_samples,
        "contamination": contamination,
        "normal_profile": profile,
        "anomaly_rate": round(anomaly_rate, 4),
        "match_rate": round(1.0 - anomaly_rate, 4),
        "calib_count": len(CALIB_BUFFER),
        "calib_target": _calib_target,
        "auto_capture": _AUTO_CAPTURE,
    })


# ── calibration endpoints ─────────────────────────────────────────────────
async def _calibrate_capture(request: Request) -> JSONResponse:
    if not _is_loopback(request):
        return JSONResponse({"error": "localhost only"}, status_code=403)
    if latest_sample is None:
        return JSONResponse({"error": "no live sample yet"}, status_code=400)
    if len(CALIB_BUFFER) >= _calib_target:
        return JSONResponse({"error": "buffer full", "count": len(CALIB_BUFFER), "target": _calib_target}, status_code=400)
    features = DETECTOR["features"] if DETECTOR else [
        "throughput_tx_mbps", "throughput_rx_mbps", "retry_rate",
        "tx_per_pct", "rx_per_pct", "rssi0", "rssi1", "rssi2", "rssi3",
        "tx_mcs", "tx_nss",
    ]
    vec = [float(latest_sample.get(f, 0) or 0) for f in features]
    CALIB_BUFFER.append(vec)
    _append_calib_csv(features, vec)
    return JSONResponse({"count": len(CALIB_BUFFER), "target": _calib_target})


async def _calibrate_reset(request: Request) -> JSONResponse:
    if not _is_loopback(request):
        return JSONResponse({"error": "localhost only"}, status_code=403)
    global _AUTO_CAPTURE
    CALIB_BUFFER.clear()
    _AUTO_CAPTURE = False
    try:
        _CALIB_CSV.unlink(missing_ok=True)
    except Exception:
        pass
    return JSONResponse({"ok": True, "count": 0, "target": _calib_target})


async def _calibrate_train(request: Request) -> JSONResponse:
    if not _is_loopback(request):
        return JSONResponse({"error": "localhost only"}, status_code=403)
    if len(CALIB_BUFFER) < _CALIB_MIN:
        return JSONResponse({"error": f"need >= {_CALIB_MIN} samples, have {len(CALIB_BUFFER)}"}, status_code=400)
    if not _CALIB_CSV.is_file():
        return JSONResponse({"error": "calibration CSV not found"}, status_code=500)
    # Run train_detector on the calibration CSV
    cmd = _TRAIN_CMD + ["--csv", str(_CALIB_CSV), "--out", str(_MODEL_PATH)]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            return JSONResponse({"error": f"train failed: {stderr.decode()[:500]}"}, status_code=500)
    except Exception as exc:
        return JSONResponse({"error": f"train exec error: {exc}"}, status_code=500)
    # Reload model in-process
    det = _reload_detector()
    if det is None:
        return JSONResponse({"error": "model reload failed after training"}, status_code=500)
    # Compute training FPR from the output
    fpr_str = ""
    fpr_val = None
    for line in stdout.decode().splitlines():
        if "false-positive" in line.lower():
            fpr_str = line.strip()
            # try to extract numeric fpr
            try:
                import re as _re
                m = _re.search(r"(\d+\.\d+)", fpr_str)
                if m:
                    fpr_val = float(m.group(1))
            except Exception:
                pass
            break
    # Log training history
    profile = _read_normal_profile()
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()),
        "n_samples": len(CALIB_BUFFER),
        "source": "calibration",
        "interval_s": args.interval,
        "features": det.get("features", []),
        "training_fpr": fpr_val,
        "feature_profile": profile or {},
        "model_params": {
            "n_estimators": 200,
            "contamination": det["model"].contamination if det else None,
        },
        "note": "",
    }
    history = _load_training_history()
    history.append(entry)
    _save_training_history(history)
    return JSONResponse({"ok": True, "fpr": fpr_str, "n_samples": len(CALIB_BUFFER)})


async def _calibrate_auto(request: Request) -> JSONResponse:
    if not _is_loopback(request):
        return JSONResponse({"error": "localhost only"}, status_code=403)
    global _AUTO_CAPTURE
    try:
        body = await request.json()
    except Exception:
        body = {}
    enable = body.get("enable", not _AUTO_CAPTURE)
    _AUTO_CAPTURE = bool(enable)
    return JSONResponse({"auto_capture": _AUTO_CAPTURE, "count": len(CALIB_BUFFER), "target": _calib_target})


async def _calibrate_target(request: Request) -> JSONResponse:
    """POST /calibrate/target — set calibration target N for this run."""
    global _calib_target
    if not _is_loopback(request):
        return JSONResponse({"error": "localhost only"}, status_code=403)
    try:
        body = await request.json()
    except Exception:
        body = {}
    n = body.get("n")
    if not isinstance(n, (int, float)) or int(n) < _CALIB_MIN:
        return JSONResponse({"error": f"n must be integer >= {_CALIB_MIN}"}, status_code=400)
    _calib_target = int(n)
    return JSONResponse({"ok": True, "target": _calib_target})


async def _training_history(request: Request) -> JSONResponse:
    """GET /training-history — list past training runs, newest first."""
    if not _is_loopback(request):
        return JSONResponse({"error": "localhost only"}, status_code=403)
    entries = _load_training_history()
    entries.sort(key=lambda e: e.get("ts", ""), reverse=True)
    return JSONResponse(entries)


# ── BFI live stream thread ────────────────────────────────────────────────
def _bfi_stream_thread(iface: str, window: int, stop_event: threading.Event) -> None:
    """Background thread: run bfi_features.stream_features and update BFI_LATEST."""
    try:
        from bfi_features import stream_features
    except ImportError:
        print("[BFI] bfi_features import failed — BFI stream disabled", file=sys.stderr)
        return
    try:
        for feat in stream_features(iface, duration=0, window=window, stop_event=stop_event):
            for k in _BFI_KEYS:
                if k in feat:
                    BFI_LATEST[k] = feat[k]
    except Exception as exc:
        print(f"[BFI] stream error: {exc}", file=sys.stderr)


def _stop_bfi() -> None:
    """Stop the running BFI stream thread (no-op if none running)."""
    global _bfi_thread, _bfi_stop
    if _bfi_thread is not None and _bfi_thread.is_alive():
        if _bfi_stop is not None:
            _bfi_stop.set()
        _bfi_thread.join(timeout=2)
    _bfi_thread = None
    _bfi_stop = None
    BFI_LATEST.clear()


def _start_bfi(iface: str) -> None:
    """Start a BFI stream thread for *iface* (stops any existing one first)."""
    global _bfi_thread, _bfi_stop
    _stop_bfi()
    args.bfi_iface = iface
    _bfi_stop = threading.Event()
    _bfi_thread = threading.Thread(
        target=_bfi_stream_thread,
        args=(iface, 10, _bfi_stop),
        daemon=True,
    )
    _bfi_thread.start()


# ── lifespan: start/stop the producer (Starlette 1.x API) ─────────────────
@asynccontextmanager
async def _lifespan(app):
    global _current_task
    _seed_training_history()
    if args.mode == "replay":
        _current_task = asyncio.create_task(_producer_replay())
    elif args.mode == "live":
        _current_task = asyncio.create_task(_producer_live())

    # Optionally start BFI stream (PARALLEL to iwpriv poll)
    if getattr(args, "bfi_iface", None):
        _start_bfi(args.bfi_iface)

    try:
        yield
    finally:
        _stop_bfi()
        if _current_task is not None:
            _current_task.cancel()


# ── routes ────────────────────────────────────────────────────────────────
async def _homepage(request):
    return FileResponse(_HERE / "dashboard.html")


async def _ml_page(request):
    return FileResponse(_HERE / "ml.html")


async def _ws_handler(websocket: WebSocket) -> None:
    await websocket.accept()
    clients.add(websocket)
    total = PLAYBACK["total"] if args.mode == "replay" else 0
    attack_start = PLAYBACK["attack_start"] if args.mode == "replay" else -1
    meta = {
        "type": "meta",
        "mode": args.mode or "idle",
        "total": total,
        "attack_start": attack_start,
        "interval": args.interval,
    }
    await websocket.send_text(json.dumps(meta))
    if latest_sample is not None:
        await websocket.send_text(json.dumps(latest_sample))
    try:
        while True:
            raw = await websocket.receive_text()
            try:
                cmd = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(cmd, dict):
                continue
            if args.mode != "replay":
                continue
            c = cmd.get("cmd")
            if c == "pause":
                PLAYBACK["paused"] = True
            elif c == "play":
                PLAYBACK["paused"] = False
            elif c == "step":
                d = cmd.get("dir", 1)
                if d not in (1, -1):
                    d = 1
                PLAYBACK["paused"] = True
                if PLAYBACK["total"] > 0:
                    PLAYBACK["idx"] = (PLAYBACK["idx"] + d) % PLAYBACK["total"]
                    await _replay_broadcast_current()
            elif c == "seek":
                n = cmd.get("index")
                if isinstance(n, (int, float)):
                    n = int(n)
                    if PLAYBACK["total"] > 0:
                        PLAYBACK["idx"] = max(0, min(n, PLAYBACK["total"] - 1))
                        await _replay_broadcast_current()
    except Exception:
        pass
    finally:
        clients.discard(websocket)


# ── app assembly ──────────────────────────────────────────────────────────
app = Starlette(
    routes=[
        Route("/", _homepage),
        Route("/ml", _ml_page),
        Route("/tasks", _tasks_endpoint),
        Route("/replay-files", _replay_files_endpoint),
        Route("/session", _session_endpoint, methods=["POST"]),
        Route("/run/{name}", _run_endpoint, methods=["POST"]),
        Route("/stop/{name}", _stop_endpoint, methods=["POST"]),
        Route("/model-status", _model_status),
        Route("/calibrate/capture", _calibrate_capture, methods=["POST"]),
        Route("/calibrate/reset", _calibrate_reset, methods=["POST"]),
        Route("/calibrate/train", _calibrate_train, methods=["POST"]),
        Route("/calibrate/auto", _calibrate_auto, methods=["POST"]),
        Route("/calibrate/target", _calibrate_target, methods=["POST"]),
        Route("/training-history", _training_history),
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
    p.add_argument("--mode", choices=["live", "replay"], default=None)
    p.add_argument("--csv", default="data/normal_iperf.csv")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--bind", default="127.0.0.1")
    p.add_argument("--bfi-iface", default=None,
                    help="Monitor iface for live BFI stream (optional, parallel to telemetry)")
    args = p.parse_args()

    uvicorn.run(app, host=args.bind, port=args.port, log_level="info")
