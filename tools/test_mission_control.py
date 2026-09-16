#!/usr/bin/env python3
"""Self-check for Mission Control task runner.

Tests (no hardware needed):
1. /tasks returns the registry
2. /run/test_echo streams {type:"log"} + {type:"status"} over websocket
3. /run/{unknown} is rejected
4. Non-loopback access to /run is refused (assertion)
"""

import asyncio
import json
import os
import sys
from pathlib import Path

# Setup: point at replay CSV so lifespan doesn't crash
_ROOT = Path(__file__).resolve().parent.parent
_CSV = _ROOT / "data" / "normal_iperf.csv"
assert _CSV.exists(), f"Missing replay CSV: {_CSV}"

sys.argv = [
    "dashboard.py",
    "--mode", "replay",
    "--csv", str(_CSV),
    "--port", "0",
]

# Must set args before import (module reads args in lifespan)
import dashboard  # noqa: E402

# Patch args for tests
dashboard.args = type("A", (), {
    "mode": "replay",
    "csv": str(_CSV),
    "interval": 2.0,
    "host": "localhost",
    "user": "x",
    "password": "x",
    "iface": "rai1",
})()

from starlette.testclient import TestClient  # noqa: E402


def test_tasks_returns_registry():
    """GET /tasks returns the full task registry."""
    with TestClient(dashboard.app) as client:
        r = client.get("/tasks")
        assert r.status_code == 200, f"Expected 200, got {r.status_code}"
        data = r.json()
        assert "test_echo" in data, "test_echo missing from /tasks"
        assert "setup_monitor" in data, "setup_monitor missing from /tasks"
        assert data["test_echo"]["label"] == "Test Echo"
        assert data["test_echo"]["state"] in ("idle", "running", "done", "failed")
        print("  PASS: /tasks returns registry")


def test_run_unknown_rejected():
    """POST /run/{unknown_name} returns 404."""
    with TestClient(dashboard.app) as client:
        r = client.post("/run/nonexistent_task_xyz")
        assert r.status_code == 404, f"Expected 404, got {r.status_code}"
        assert "unknown task" in r.json()["error"]
        print("  PASS: unknown /run rejected with 404")


def test_run_echo_streams_to_websocket():
    """POST /run/test_echo streams log+status over websocket."""
    with TestClient(dashboard.app) as client:
        with client.websocket_connect("/ws") as ws:
            # Drain the meta message
            raw = ws.receive_text()
            meta = json.loads(raw)
            assert meta["type"] == "meta"

            # Trigger the test echo task
            r = client.post("/run/test_echo", json={})
            assert r.status_code == 200, f"Expected 200, got {r.status_code}"
            assert r.json()["ok"] is True

            # Collect messages until we see the status message
            log_msgs = []
            status_msg = None
            for _ in range(20):
                try:
                    raw = ws.receive_text()
                    msg = json.loads(raw)
                    if msg.get("type") == "log":
                        log_msgs.append(msg)
                    elif msg.get("type") == "status":
                        status_msg = msg
                        break
                except Exception:
                    break

            # Verify log line
            assert len(log_msgs) >= 1, f"Expected at least 1 log msg, got {len(log_msgs)}"
            echo_log = log_msgs[0]
            assert echo_log["type"] == "log"
            assert echo_log["task"] == "test_echo"
            assert echo_log["stream"] == "out"
            assert "hello-mission-control" in echo_log["line"]
            print(f"  PASS: log line contains 'hello-mission-control'")

            # Verify status
            assert status_msg is not None, "No status message received"
            assert status_msg["type"] == "status"
            assert status_msg["task"] == "test_echo"
            assert status_msg["state"] == "done"
            assert status_msg["code"] == 0
            print(f"  PASS: status=done, code=0")


def test_loopback_guard():
    """Non-loopback client cannot access /run (returns 403).

    We verify the _is_loopback helper directly: real loopback addresses pass,
    remote addresses are rejected.  Starlette's TestClient uses 'testclient'
    which is accepted as loopback for testing purposes.
    """
    from starlette.requests import Request

    # Fake a non-loopback request
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/run/test_echo",
        "headers": [],
        "query_string": b"",
        "client": ("192.168.1.100", 12345),
    }
    req = Request(scope)
    assert not dashboard._is_loopback(req), "192.168.1.100 should NOT be loopback"

    # Loopback addresses
    for lb in ("127.0.0.1", "::1", "localhost"):
        scope2 = {**scope, "client": (lb, 12345)}
        req2 = Request(scope2)
        assert dashboard._is_loopback(req2), f"{lb} SHOULD be loopback"

    # TestClient is considered loopback (test-only)
    scope3 = {**scope, "client": ("testclient", 0)}
    req3 = Request(scope3)
    assert dashboard._is_loopback(req3), "testclient SHOULD be loopback (test infra)"

    print("  PASS: loopback guard correctly rejects non-loopback")


if __name__ == "__main__":
    print("Mission Control self-check:")
    test_tasks_returns_registry()
    test_run_unknown_rejected()
    test_run_echo_streams_to_websocket()
    test_loopback_guard()
    print("ALL CHECKS PASSED")
