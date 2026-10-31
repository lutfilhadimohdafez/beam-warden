"""Rig-specific config loader — keeps creds/IDs OUT of source.

Reads rig.conf (gitignored; copy rig.conf.example). Values fall back to generic,
non-secret defaults so a fresh checkout still imports. Any key is also overridable
by a BW_<KEY> environment variable, so nobody has to edit source to run on their
own router. ponytail: plain key=val, stdlib only.
"""
import os
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent

# generic, NON-SECRET fallbacks (so imports never break on a clean clone)
_DEFAULTS = {
    "ROUTER_HOST": "192.168.1.1", "ROUTER_USER": "root", "ROUTER_PASS": "",
    "ROUTER_AP_IFACE": "phy1-ap0", "ROUTER_AP_BSSID": "", "ROUTER_CHANNEL": "36",
    "VICTIM_MAC": "", "VICTIM_IP": "",
    "PHONE_USER": "", "PHONE_PORT": "8022", "PHONE_PASS": "",
    "FWLAB_HOST": "", "FWLAB_USER": "", "FWLAB_PASS": "",
}


def _load():
    cfg = dict(_DEFAULTS)
    p = _ROOT / "rig.conf"
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip()
    for k in cfg:                       # BW_<KEY> env overrides everything
        cfg[k] = os.environ.get("BW_" + k, cfg[k])
    return cfg


RIG = _load()


def get(key, default=""):
    return RIG.get(key, default)


if __name__ == "__main__":  # quick self-check: prints config with secrets masked
    for k, v in RIG.items():
        shown = ("***" if v else "(unset)") if "PASS" in k else (v or "(unset)")
        print(f"{k}={shown}")
