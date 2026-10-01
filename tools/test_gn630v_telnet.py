#!/usr/bin/env python3
"""Assert-based tests for gn630v_telnet.GN630V.run() — no framework, no network."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gn630v_telnet import GN630V


class _FakeSock:
    """Stub socket: recv() yields canned chunks, then EOF (b'')."""
    def __init__(self, replies):
        self._replies = list(replies)
        self.sent = []

    def sendall(self, data):
        self.sent.append(data)

    def settimeout(self, _t):
        pass

    def recv(self, _n):
        return self._replies.pop(0) if self._replies else b""


def _session(replies):
    ont = GN630V.__new__(GN630V)  # bypass __enter__/connect
    ont.sock = _FakeSock(replies)
    return ont


def test_run_returns_output_on_live_session():
    ont = _session([b"Rssi: -41 -43\r\nMZQEND\r\nroot@XiaoQiang:~#"])
    out = ont.run("iwpriv wl0 stat")
    assert "Rssi: -41 -43" in out, out
    assert "MZQEND" not in out  # marker stripped
    print("test_run_returns_output_on_live_session OK")


def test_run_raises_on_dead_link():
    # recv immediately returns EOF → no marker ever arrives → disconnect.
    # This is the dashboard-freeze bug: without the guard, run() returned ""
    # and the producer parsed it as healthy "ok" forever.
    ont = _session([])
    raised = False
    try:
        ont.run("iwpriv wl0 stat", timeout=0.3)
    except ConnectionError:
        raised = True
    assert raised, "run() must raise ConnectionError when the end marker never arrives"
    print("test_run_raises_on_dead_link OK")


if __name__ == "__main__":
    test_run_returns_output_on_live_session()
    test_run_raises_on_dead_link()
    print("all OK")
