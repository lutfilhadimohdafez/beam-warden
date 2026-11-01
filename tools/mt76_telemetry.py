#!/usr/bin/env python3
"""mt76 / OpenWrt telemetry adapter for Beam-Warden.

The dashboard was built for stock MediaTek/Ralink routers: telnet + `iwpriv
<if> stat` (see gn630v_telnet.py / gn630v_telemetry.py). The ImmortalWrt AC2100
runs the OPEN mt76 driver — no iwpriv — so telemetry comes from SSH +
`iw dev <if> station dump`. This module provides a drop-in SSH transport
(SSHConn) with the SAME interface as GN630V, and a parser that returns the SAME
dict schema as parse_iwpriv_stat, so the dashboard loop is transport-agnostic.

ponytail: stdlib + `sshpass` subprocess only — NO paramiko / no new pip deps.
Connection reuse is an SSH ControlMaster socket (one handshake per session).
"""
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

# Same key set the dashboard consumes (mirrors parse_iwpriv_stat in
# gn630v_telemetry.py). Keys with no mt76 source keep their neutral default.
_DEFAULTS: dict = {
    # None = this source has no temperature sensor (mt76 station dump) → the
    # dashboard renders "N/A". iwpriv rigs (GN630v/AX3200) set a real value.
    "temp_c": None,
    "tx_success": 0, "tx_fail": 0, "tx_per_pct": 0.0,
    "rx_success": 0, "rx_crc": 0, "rx_per_pct": 0.0,
    "rssi0": 0, "rssi1": 0, "rssi2": 0, "rssi3": 0,
    "tx_nss": None, "tx_mcs": None, "tx_bw": None, "tx_gi": None,
    "tx_phymode": None, "tx_coding": None,
    "rx_nss": None, "rx_mcs": None, "rx_bw": None, "rx_gi": None,
    "rx_phymode": None, "rx_coding": None,
    "packets_sent": 0, "packets_recv": 0,
    "bytes_sent": 0, "bytes_recv": 0,
}

# "signal:  -54 [-62, -58, -63, -58] dBm"  -> combined + per-chain list
_SIGNAL_RE = re.compile(r"^\s*signal:\s*(-?\d+)\s*\[([^\]]+)\]")
# "tx bitrate: 433.3 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 1"
# The bandwidth token (e.g. "80MHz") is OMITTED at 20MHz on mt76 — real AC2100
# line is "VHT-MCS 8 short GI VHT-NSS 1" — so it must be optional, or the whole
# rate (MCS/NSS/phymode) fails to parse and the dashboard tile shows nothing.
_RATE_RE = re.compile(
    r"(VHT|HE|HT)-MCS\s+(\d+)(?:\s+(\d+MHz))?(?:\s+(short|long)\s+GI)?"
    r"(?:.*?(?:VHT|HE|HT)-NSS\s+(\d+))?"
)
_INT_RE = {
    "rx bytes": "bytes_recv", "tx bytes": "bytes_sent",
    "rx packets": "packets_recv", "tx packets": "packets_sent",
}


def _parse_rate(line: str) -> dict:
    """Parse one 'tx/rx bitrate:' line -> {mcs,nss,bw,gi,phymode}."""
    m = _RATE_RE.search(line)
    if not m:
        return {}
    phymode, mcs, bw, gi, nss = m.groups()
    return {
        "phymode": phymode,
        "mcs": int(mcs),
        "bw": bw,
        "gi": f"{gi} GI" if gi else "",
        # VHT/HE carry NSS explicitly; HT folds it into the MCS index -> default 1.
        "nss": int(nss) if nss else 1,
    }


def parse_iw_station_dump(text: str, mac: str = "") -> dict:
    """Parse `iw dev <if> station dump` (first station block) into the flat dict
    the dashboard expects. Unavailable fields keep neutral defaults.
    """
    blocks = re.split(r'(?=^Station\s)', text, flags=re.MULTILINE)
    stations = [b for b in blocks if b.startswith('Station ')]
    if stations:
        if mac:
            stations = [b for b in stations if b.split()[1].lower() == mac.lower()]
            if not stations:
                raise ValueError('Protected station is not associated')
        text = stations[0]
    d = dict(_DEFAULTS)
    tx_failed = 0          # the real 'tx failed' (dropped-after-retries) counter
    rx_drop_misc = 0
    for raw in text.splitlines():
        line = raw.strip()

        m = _SIGNAL_RE.match(raw)
        if m and "avg" not in line:          # use instantaneous signal, not avg
            chains = [c.strip() for c in m.group(2).split(",")]
            for i in range(4):
                try:
                    d[f"rssi{i}"] = int(chains[i])
                except (IndexError, ValueError):
                    d[f"rssi{i}"] = 0
            continue

        if line.startswith("tx bitrate:"):
            r = _parse_rate(line)
            if r:
                d.update(tx_mcs=r["mcs"], tx_nss=r["nss"], tx_bw=r["bw"],
                         tx_gi=r["gi"], tx_phymode=r["phymode"])
            continue
        if line.startswith("rx bitrate:"):
            r = _parse_rate(line)
            if r:
                d.update(rx_mcs=r["mcs"], rx_nss=r["nss"], rx_bw=r["bw"],
                         rx_gi=r["gi"], rx_phymode=r["phymode"])
            continue

        if line.startswith("tx retries:"):
            d["tx_fail"] = _tail_int(line)      # retries drive retry_rate
            continue
        if line.startswith("tx failed:"):
            tx_failed = _tail_int(line)
            continue
        if line.startswith("rx drop misc:"):
            rx_drop_misc = _tail_int(line)
            continue

        for key, field in _INT_RE.items():
            if line.startswith(key + ":"):
                d[field] = _tail_int(line)
                break

    # retry_rate (via compute_deltas) wants tx_fail/tx_success -> retries/packets.
    d["tx_success"] = d["packets_sent"]
    d["tx_failed"] = tx_failed
    # snapshot PER from the true failed/drop counters
    if d["packets_sent"]:
        d["tx_per_pct"] = round(100.0 * tx_failed / d["packets_sent"], 3)
    if d["packets_recv"]:
        d["rx_per_pct"] = round(100.0 * rx_drop_misc / d["packets_recv"], 3)
    # temp_c: mt76 station dump has no temperature. TODO: hwmon/debugfs if present.
    return d


def window_metrics(prev, curr, elapsed):
    """Interval telemetry v2: same failure fraction used by the router watcher.

    Preserve raw failures so new data can be re-derived. Old cumulative CSVs
    must remain distinguishable from this schema.
    """
    if elapsed <= 0:
        raise ValueError('Sampling interval must be positive')
    keys = ('bytes_sent', 'bytes_recv', 'packets_sent', 'packets_recv', 'tx_fail', 'tx_failed')
    delta = {k: curr[k] - prev[k] for k in keys}
    if any(v < 0 for v in delta.values()):
        raise ValueError('Station counters reset; discard this interval')
    dp, dr, df = delta['packets_sent'], delta['tx_fail'], delta['tx_failed']
    return {'feature_schema': 'interval-v2', 'sample_seconds': elapsed,
            'throughput_tx_mbps': delta['bytes_sent'] * 8 / elapsed / 1e6,
            'throughput_rx_mbps': delta['bytes_recv'] * 8 / elapsed / 1e6,
            'retry_rate': dr / max(1, dp + dr),
            'tx_per_pct': 100 * df / max(1, dp + df),
            'tx_failure_fraction': df / max(1, dp + df),
            'active_attempts': dp + dr, 'tx_failed': curr['tx_failed']}


def _tail_int(line: str) -> int:
    """Last integer on a 'key: <int> ...' line (0 if none)."""
    m = re.search(r"(-?\d+)", line.split(":", 1)[-1])
    return int(m.group(1)) if m else 0


class SSHConn:
    """SSH session to an OpenWrt box. Same interface as GN630V: context manager
    + run(cmd)->stdout, raising ConnectionError on a dead link so the dashboard's
    existing disconnect handling fires.

    ponytail: one SSH ControlMaster socket reused for every run() (no re-handshake
              per poll). Fallback would be a fresh `ssh` per call.
    """

    def __init__(self, host, user, password, port=22, timeout=6.0):
        self.host, self.port = host, int(port)
        self.user, self.password = user, password
        self.timeout = float(timeout)
        self._ctldir = None
        self._ctl = None

    @property
    def _target(self) -> str:
        return f"{self.user}@{self.host}"

    def __enter__(self):
        self._ctldir = tempfile.mkdtemp(prefix="bw-ssh-")
        self._ctl = str(Path(self._ctldir) / "ctl")
        cmd = [
            "sshpass", "-p", self.password, "ssh",
            "-M", "-S", self._ctl,
            "-o", "ControlPersist=120",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"ConnectTimeout={int(self.timeout)}",
            "-fN", "-p", str(self.port), self._target,
        ]
        r = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=self.timeout + 5)
        if r.returncode != 0:
            self.__exit__()
            raise ConnectionError(
                f"ssh master to {self._target} failed: "
                f"{(r.stderr or r.stdout).strip() or 'unknown error'}"
            )
        return self

    def run(self, cmd: str, timeout: float = 12.0) -> str:
        ssh = [
            "sshpass", "-p", self.password, "ssh",
            "-S", self._ctl, "-p", str(self.port), self._target, cmd,
        ]
        try:
            r = subprocess.run(ssh, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise ConnectionError(
                f"router unresponsive (no reply to '{cmd}' within {timeout}s) — link down?"
            )
        if r.returncode != 0:
            raise ConnectionError(
                f"ssh '{cmd}' to {self._target} failed (rc={r.returncode}): "
                f"{r.stderr.strip() or 'link down?'}"
            )
        return r.stdout.strip()

    def __exit__(self, *exc):
        try:
            if self._ctl:
                subprocess.run(["ssh", "-S", self._ctl, "-O", "exit", self._target],
                               capture_output=True, timeout=5)
        except Exception:
            pass
        if self._ctldir:
            shutil.rmtree(self._ctldir, ignore_errors=True)
        self._ctl = self._ctldir = None


_SAMPLE = """Station 16:0f:02:1d:91:42 (on phy1-ap0)
\tauthorized:\tyes
\trx bytes:\t4174231
\trx packets:\t11429
\ttx bytes:\t8498259
\ttx packets:\t7021
\ttx retries:\t203
\ttx failed:\t2
\trx drop misc:\t0
\tsignal:  \t-54 [-62, -58, -63, -58] dBm
\tsignal avg:\t-57 [-64, -61, -67, -60] dBm
\ttx bitrate:\t433.3 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 1
\trx bitrate:\t433.3 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 1
\texpected throughput:\t283.355Mbps
"""


def demo() -> None:
    d = parse_iw_station_dump(_SAMPLE)
    assert d["rssi0"] == -62 and d["rssi3"] == -58, d
    assert d["tx_mcs"] == 9 and d["tx_nss"] == 1, d
    assert d["tx_bw"] == "80MHz" and d["tx_phymode"] == "VHT", d
    assert d["packets_sent"] == 7021 and d["packets_recv"] == 11429, d
    assert d["bytes_sent"] == 8498259 and d["bytes_recv"] == 4174231, d
    assert d["tx_fail"] == 203 and d["tx_success"] == 7021, d  # retries drive retry_rate
    assert d["tx_per_pct"] == round(100.0 * 2 / 7021, 3), d
    # real AC2100 20MHz line OMITS the bandwidth token — must still parse MCS/NSS
    d20 = parse_iw_station_dump(
        "\ttx bitrate:\t86.7 MBit/s VHT-MCS 8 short GI VHT-NSS 1\n")
    assert d20["tx_mcs"] == 8 and d20["tx_nss"] == 1 and d20["tx_bw"] is None, d20
    print("OK")


if __name__ == "__main__":
    demo()
