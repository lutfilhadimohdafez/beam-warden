#!/usr/bin/env python3
"""Minimal telnet transport for the Skyworth GN630v ONT console.

The GN630v runs BusyBox with telnetd on port 23 and drops `tmadmin` into a
root `/bin/sh`. Its `iwpriv <if> stat` output is the Objective-2 telemetry
source (see docs/hardware/gn630v-uart-recon.md).

ponytail: raw socket instead of a telnet library — telnetlib was removed in
Python 3.13, and all we need is IAC option refusal + line I/O.
"""
import socket
import time

IAC, DONT, DO, WONT, WILL = 255, 254, 253, 252, 251


def _negotiate(sock: socket.socket, data: bytes) -> bytes:
    """Refuse all telnet IAC options, return the clean payload bytes."""
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == IAC and i + 2 < len(data):
            cmd, opt = data[i + 1], data[i + 2]
            if cmd == DO:
                sock.sendall(bytes([IAC, WONT, opt]))
            elif cmd == WILL:
                sock.sendall(bytes([IAC, DONT, opt]))
            i += 3
            continue
        out.append(b)
        i += 1
    return bytes(out)


def _recv_until(sock: socket.socket, tokens, timeout: float) -> bytes:
    buf = bytearray()
    end = time.time() + timeout
    sock.settimeout(0.5)
    while time.time() < end:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += _negotiate(sock, chunk)
            if any(t in bytes(buf) for t in tokens):
                return bytes(buf)
        except socket.timeout:
            if any(t in bytes(buf) for t in tokens):
                return bytes(buf)
    return bytes(buf)


class GN630V:
    """Telnet session to the ONT. Use as a context manager; call run() per command.

    The box echoes input, so run() brackets each command with a marker whose
    typed form (`echo MZ""QEND`) differs from its printed form (`MZQEND`),
    letting us read past the echoed line to the real output.
    """

    def __init__(self, host="192.168.0.1", user="tmadmin", password="REDACTED",
                 port=23, timeout=6.0):
        self.host, self.port = host, port
        self.user, self.password = user.encode(), password.encode()
        self.timeout = timeout
        self.sock = None

    def __enter__(self):
        self.sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        _recv_until(self.sock, [b"login:", b"ogin:"], self.timeout)
        self.sock.sendall(self.user + b"\r\n")
        _recv_until(self.sock, [b"assword:"], self.timeout)
        self.sock.sendall(self.password + b"\r\n")
        _recv_until(self.sock, [b"#", b"$"], self.timeout)
        return self

    def run(self, cmd: str, timeout: float = 12.0) -> str:
        """Send one shell line, return its stdout (echoed lines/markers stripped)."""
        self.sock.sendall(cmd.encode() + b"\r\n")
        time.sleep(0.2)
        self.sock.sendall(b'echo MZ""QEND\r\n')
        out = _recv_until(self.sock, [b"MZQEND"], timeout).decode("utf-8", "replace")
        if "MZQEND" not in out:
            # The end marker always round-trips on a live session. Its absence
            # means the link dropped or the session hung — a half-open TCP sends
            # no RST, so sendall buffers and recv just times out with no error.
            # Raise so callers surface a disconnect instead of silently parsing
            # empty output as healthy "ok" data (the dashboard-freeze bug).
            # ponytail: detection latency = this timeout (default 12s); lower it
            #           per-call if you need a faster disconnect signal.
            raise ConnectionError(
                f"router unresponsive (no reply to '{cmd}' within {timeout}s) — link down?"
            )
        lines = [
            l for l in out.splitlines()
            if l.strip() not in (cmd.strip(), 'echo MZ""QEND', "MZQEND")
            and 'MZ""QEND' not in l and l.strip() != "MZQEND"
        ]
        return "\n".join(lines).strip()

    def __exit__(self, *exc):
        try:
            self.sock.sendall(b"exit\r\n")
            self.sock.close()
        except OSError:
            pass


if __name__ == "__main__":  # smoke test against a live box
    import sys
    with GN630V() as ont:
        for c in sys.argv[1:] or ["iwpriv rai1 stat"]:
            print(ont.run(c))
