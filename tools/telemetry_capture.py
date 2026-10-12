#!/usr/bin/env python3
"""Poll a router's `iw station dump` over SSH or telnet and log RSSI/MCS/throughput/retry
telemetry per connected client to CSV — the dataset for Objective 2.

ponytail: shells out to the system `ssh` binary (already used throughout this
project) instead of adding paramiko as a new dependency.

`--selfcheck` runs the canned telnet extraction self-check and exits.
"""
import argparse
import csv
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

STATION_RE = re.compile(r"^Station ([0-9A-Fa-f:]{17})")
RATE_MCS_RE = re.compile(r"([\d.]+) MBit/s.*?MCS (\d+)")
LEAD_INT_RE = re.compile(r"-?\d+")

CSV_FIELDS = [
    "timestamp", "label", "mac", "rssi_dbm", "rssi_avg_dbm",
    "tx_mcs", "rx_mcs", "tx_rate_mbps", "rx_rate_mbps",
    "throughput_tx_mbps", "throughput_rx_mbps",
    "tx_packets_delta", "tx_retries_delta", "retry_rate",
]


def parse_station_dump(text: str) -> list[dict]:
    """Parse `iw dev <iface> station dump` output into one dict per client."""
    stations = []
    current: dict | None = None
    for line in text.splitlines():
        m = STATION_RE.match(line)
        if m:
            current = {"mac": m.group(1)}
            stations.append(current)
            continue
        if current is None or ":" not in line:
            continue
        key, _, value = line.strip().partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "signal":
            current["rssi_dbm"] = int(LEAD_INT_RE.match(value).group())
        elif key == "signal avg":
            current["rssi_avg_dbm"] = int(LEAD_INT_RE.match(value).group())
        elif key == "rx bytes":
            current["rx_bytes"] = int(value)
        elif key == "tx bytes":
            current["tx_bytes"] = int(value)
        elif key == "tx packets":
            current["tx_packets"] = int(value)
        elif key == "tx retries":
            current["tx_retries"] = int(value)
        elif key == "tx bitrate":
            rm = RATE_MCS_RE.search(value)
            if rm:
                current["tx_rate_mbps"] = float(rm.group(1))
                current["tx_mcs"] = int(rm.group(2))
        elif key == "rx bitrate":
            rm = RATE_MCS_RE.search(value)
            if rm:
                current["rx_rate_mbps"] = float(rm.group(1))
                current["rx_mcs"] = int(rm.group(2))
    return stations


def compute_deltas(prev: dict, curr: dict, dt: float) -> dict:
    """Throughput + retry rate between two snapshots of the same client, dt seconds apart."""
    tx_bytes_d = max(0, curr["tx_bytes"] - prev["tx_bytes"])
    rx_bytes_d = max(0, curr["rx_bytes"] - prev["rx_bytes"])
    tx_packets_d = max(0, curr["tx_packets"] - prev["tx_packets"])
    tx_retries_d = max(0, curr["tx_retries"] - prev["tx_retries"])
    return {
        "throughput_tx_mbps": round(tx_bytes_d * 8 / 1e6 / dt, 3),
        "throughput_rx_mbps": round(rx_bytes_d * 8 / 1e6 / dt, 3),
        "tx_packets_delta": tx_packets_d,
        "tx_retries_delta": tx_retries_d,
        "retry_rate": round(tx_retries_d / tx_packets_d, 4) if tx_packets_d else 0.0,
    }


def ssh_station_dump(host: str, user: str, iface: str) -> str:
    try:
        result = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", f"{user}@{host}",
             f"iw dev {iface} station dump"],
            capture_output=True, text=True, timeout=10,
        )
    except subprocess.TimeoutExpired:
        print("ssh timed out", file=sys.stderr)
        return ""
    if result.returncode != 0:
        print(f"ssh failed: {result.stderr.strip()}", file=sys.stderr)
        return ""
    return result.stdout


IAC, DONT, DO, WONT, WILL = 255, 254, 253, 252, 251
PROMPT_LINE_RE = re.compile(r"^\S*[#$>]\s*$")


def _telnet_negotiate(sock: socket.socket, data: bytes) -> bytes:
    """Refuse all telnet IAC options (DO->WONT, WILL->DONT), return clean bytes."""
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


def _telnet_recv_until(sock: socket.socket, tokens: list[bytes], timeout: float) -> bytes | None:
    """Read until a token appears; None on timeout, bytes on token or EOF."""
    buf = bytearray()
    end = time.time() + timeout
    sock.settimeout(0.5)
    while time.time() < end:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                return bytes(buf)
            buf += _telnet_negotiate(sock, chunk)
            if any(t in bytes(buf) for t in tokens):
                return bytes(buf)
        except socket.timeout:
            if any(t in bytes(buf) for t in tokens):
                return bytes(buf)
    return None


def extract_telnet_output(raw: str, cmd: str) -> str:
    """Reduce a telnet transcript to one command's stdout.

    Cuts the login banner through the echoed command line and the trailing
    shell prompt. Pure so demo() can feed it a canned session without a socket.
    """
    lines = raw.replace("\x00", "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    start = 0
    for i, line in enumerate(lines):
        if cmd in line:
            start = i + 1
            break
    end = len(lines)
    while end > start and (not lines[end - 1].strip()
                           or PROMPT_LINE_RE.match(lines[end - 1].strip())):
        end -= 1
    return "\n".join(lines[start:end]).strip()


def telnet_station_dump(host: str, user: str, password: str, iface: str,
                        port: int = 23, timeout: float = 10) -> str:
    """Poll `iw dev <iface> station dump` over telnet (password auth), return its stdout."""
    # ponytail: raw-socket telnet ceiling — stdlib socket + IAC refusal only
    # (telnetlib is gone in Python 3.13+), sized for busybox/dropbear-less
    # XiaoQiang logins. Fixed prompt shapes and shell echo are assumed; if
    # firmware prompts vary, upgrade to a real telnet lib instead of growing
    # the prompt tokens here.
    cmd = f"iw dev {iface} station dump"
    login_t = [b"login:", b"ogin:", b"Username"]
    password_t = [b"assword"]
    shell_t = [b"#", b"$", b">"]
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        print(f"telnet connect failed: {e}", file=sys.stderr)
        return ""
    try:
        def expect(tokens: list[bytes], failure: str) -> bytes:
            buf = _telnet_recv_until(sock, tokens, timeout)
            if buf is None or not any(t in buf for t in tokens):
                raise TimeoutError(failure)
            return buf

        expect(login_t, "no login prompt")
        sock.sendall(user.encode() + b"\r\n")
        expect(password_t, "no password prompt")
        sock.sendall(password.encode() + b"\r\n")
        expect(shell_t, "no shell prompt")
        sock.sendall(cmd.encode() + b"\r\n")
        raw = _telnet_recv_until(sock, shell_t, timeout)
        if raw is None:
            raise TimeoutError("command output timed out")
    except OSError as e:
        print(f"telnet failed: {e}", file=sys.stderr)
        return ""
    finally:
        try:
            sock.sendall(b"exit\r\n")
        except OSError:
            pass
        sock.close()
    return extract_telnet_output(raw.decode("utf-8", "replace"), cmd)


def run(args: argparse.Namespace) -> None:
    out_path = Path(args.out)
    is_new = not out_path.exists()
    prev: dict[str, tuple[float, dict]] = {}
    deadline = time.time() + args.duration if args.duration else None

    with out_path.open("a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if is_new:
            writer.writeheader()
            f.flush()

        print(f"Logging to {out_path} (label={args.label}, interval={args.interval}s). Ctrl+C to stop.")
        try:
            while deadline is None or time.time() < deadline:
                tick_start = time.time()
                if args.transport == "telnet":
                    raw = telnet_station_dump(args.host, args.user, args.password, args.iface)
                else:
                    raw = ssh_station_dump(args.host, args.user, args.iface)
                stations = parse_station_dump(raw)
                now = time.time()
                for st in stations:
                    mac = st["mac"]
                    if mac in prev:
                        prev_t, prev_st = prev[mac]
                        dt = now - prev_t
                        if dt > 0:
                            row = {
                                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(now)),
                                "label": args.label,
                                "mac": mac,
                                "rssi_dbm": st.get("rssi_dbm"),
                                "rssi_avg_dbm": st.get("rssi_avg_dbm"),
                                "tx_mcs": st.get("tx_mcs"),
                                "rx_mcs": st.get("rx_mcs"),
                                "tx_rate_mbps": st.get("tx_rate_mbps"),
                                "rx_rate_mbps": st.get("rx_rate_mbps"),
                                **compute_deltas(prev_st, st, dt),
                            }
                            writer.writerow(row)
                            f.flush()
                            print(f"  {mac}  rssi={row['rssi_dbm']}dBm  "
                                  f"tput_tx={row['throughput_tx_mbps']}Mbps  retry={row['retry_rate']}")
                    prev[mac] = (now, st)
                elapsed = time.time() - tick_start
                time.sleep(max(0.0, args.interval - elapsed))
        except KeyboardInterrupt:
            print("\nStopped.")


SELFCHECK_SESSION = (
    b"Welcome to XiaoQiang\r\n"
    b"\r\n"
    b"XiaoQiang login: root\r\n"
    b"Password: \r\n"
    b"BusyBox v1.24.1 built-in shell (ash)\r\n"
    b"root@XiaoQiang:~# iw dev wlan0 station dump\r\n"
    b"Station a8:d4:e0:8f:01:3c (on wlan0)\r\n"
    b"\tsignal:  \t-35 [-35, -35] dBm\r\n"
    b"\ttx bitrate:\t144.4 MBit/s MCS 15 short GI\r\n"
    b"\trx bitrate:\t86.7 MBit/s VHT-MCS 8 short GI VHT-NSS 1\r\n"
    b"Station 00:1d:43:20:16:6a (on wlan0)\r\n"
    b"\tsignal:  \t-60 dBm\r\n"
    b"\ttx bitrate:\t78.0 MBit/s MCS 12\r\n"
    b"root@XiaoQiang:~# "
)


def demo() -> None:
    """Self-check: canned telnet session through the extraction the socket path uses."""
    cmd = "iw dev wlan0 station dump"
    out = extract_telnet_output(SELFCHECK_SESSION.decode("utf-8", "replace"), cmd)
    assert "Station a8:d4:e0:8f:01:3c (on wlan0)" in out
    assert "Station 00:1d:43:20:16:6a (on wlan0)" in out
    assert "tx bitrate" in out
    assert "Welcome" not in out
    assert "BusyBox" not in out
    assert "login:" not in out
    assert "Password" not in out
    assert cmd not in out
    assert "root@XiaoQiang" not in out
    assert not any(PROMPT_LINE_RE.match(l.strip()) for l in out.splitlines())
    stations = parse_station_dump(out)
    assert len(stations) == 2
    assert stations[0]["rssi_dbm"] == -35 and stations[1]["tx_mcs"] == 12
    print("selfcheck OK")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", required=True, help="Router SSH host/IP")
    p.add_argument("--user", default="root", help="SSH user (default: root)")
    p.add_argument("--iface", required=True, help="Wireless interface, e.g. wlan0")
    p.add_argument("--transport", choices=["ssh", "telnet"], default="ssh",
                   help="How to reach the router (default: ssh)")
    p.add_argument("--password", default=os.environ.get("BW_ROUTER_PASSWORD", ""),
                   help="Telnet password (telnet only; default: env BW_ROUTER_PASSWORD)")
    p.add_argument("--label", required=True, choices=["normal", "attack"],
                    help="Tags every row — run once per state to build the comparison dataset")
    p.add_argument("--interval", type=float, default=2.0, help="Seconds between polls (default: 2)")
    p.add_argument("--duration", type=float, default=None, help="Stop after N seconds (default: run until Ctrl+C)")
    p.add_argument("--out", default="telemetry.csv", help="CSV output path (appends if it exists)")
    run(p.parse_args())


if __name__ == "__main__":
    if "--selfcheck" in sys.argv:
        demo()
    else:
        main()
