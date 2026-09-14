#!/usr/bin/env python3
"""GUI control panel for the BeamCraft SU beamforming-spoofing attack.

Builds CLI commands for main_su (which now accepts --iface, --ap, --victim,
--alpha, --type, --offset, --pcap).  No source-patching — just compile and run.
"""
import subprocess
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, scrolledtext, ttk

HERE = Path(__file__).resolve().parent
BEAMCRAFT_AE = HERE.parent / "BeamCraft_AE"
SRC = BEAMCRAFT_AE / "main_su.cpp"
BIN = BEAMCRAFT_AE / "main_su"
PCAP_DEFAULT = HERE.parent / "data" / "bfi_he_capture.pcap"

MAC_RE = __import__("re").compile(r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}")


# ── hardware helpers ──────────────────────────────────────────────────

def parse_iw_dev(text: str) -> list[dict]:
    """Parse `iw dev` into [{phy, iface, mac, type}, ...]."""
    import re
    entries: list[dict] = []
    phy = None
    cur: dict | None = None
    for line in text.splitlines():
        m = re.match(r"phy#(\d+)", line)
        if m:
            phy = f"phy{m.group(1)}"
            continue
        m = re.match(r"\tInterface (\S+)", line)
        if m:
            cur = {"phy": phy, "iface": m.group(1), "mac": "", "type": ""}
            entries.append(cur)
            continue
        if cur is None:
            continue
        m = re.match(r"\t\taddr (\S+)", line)
        if m:
            cur["mac"] = m.group(1)
        m = re.match(r"\t\ttype (\S+)", line)
        if m:
            cur["type"] = m.group(1)
    return entries


def phy_supports_monitor(phy_info: str) -> bool:
    idx = phy_info.find("Supported interface modes:")
    if idx == -1:
        return False
    section = phy_info[idx:]
    end = section.find("\nBand ")
    if end != -1:
        section = section[:end]
    return "* monitor" in section


def driver_for_iface(iface: str) -> str:
    try:
        return Path(f"/sys/class/net/{iface}/device/driver").resolve().name
    except OSError:
        return "unknown"


def iface_has_ip(iface: str) -> bool:
    out = subprocess.run(
        ["ip", "-o", "-4", "addr", "show", iface],
        capture_output=True, text=True,
    ).stdout
    return bool(out.strip())


def scan_hardware() -> list[dict]:
    """Return list of WiFi interfaces with driver, monitor cap, IP status."""
    iwdev = subprocess.run(["iw", "dev"], capture_output=True, text=True).stdout
    results: list[dict] = []
    for entry in parse_iw_dev(iwdev):
        phy_info = subprocess.run(
            ["iw", "phy", entry["phy"], "info"],
            capture_output=True, text=True,
        ).stdout
        entry["monitor_capable"] = phy_supports_monitor(phy_info)
        entry["driver"] = driver_for_iface(entry["iface"])
        entry["has_ip"] = iface_has_ip(entry["iface"])
        results.append(entry)
    return results


# ── monitor setup script ─────────────────────────────────────────────

MONITOR_SETUP_SCRIPT = """\
set -e
systemctl stop NetworkManager iwd
PHY=$(for p in /sys/class/ieee80211/phy*; do \
  [ "$(basename $(readlink -f $p/device/driver))" = mt7921u ] && basename $p; done)
[ -n "$PHY" ] || { echo "ERROR: mt7921u phy not found"; exit 1; }
iw dev mon0 del 2>/dev/null; iw dev wlan1 del 2>/dev/null
iw phy $PHY interface add mon0 type monitor
ip link set mon0 up
iw dev mon0 set channel {channel}
echo "--- mon0 info ---"
iw dev mon0 info | grep -E 'type|channel'
"""


# ── GUI ───────────────────────────────────────────────────────────────

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("BeamCraft — Attack Control Panel")
        self.geometry("820x720")
        self.proc: subprocess.Popen | None = None
        self._build_ui()

    # ── layout ────────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        # 1) HARDWARE
        f1 = ttk.LabelFrame(self, text="1  HARDWARE", padding=8)
        f1.pack(fill="x", padx=10, pady=(10, 4))
        ttk.Button(f1, text="Scan adapters", command=self._scan).grid(
            row=0, column=0, sticky="w",
        )
        self.hw_list = tk.Listbox(f1, height=4)
        self.hw_list.grid(row=1, column=0, columnspan=2, sticky="ew", pady=4)
        f1.columnconfigure(1, weight=1)

        # 2) MONITOR SETUP
        f2 = ttk.LabelFrame(self, text="2  MONITOR SETUP (privileged — drops WiFi internet)", padding=8)
        f2.pack(fill="x", padx=10, pady=4)
        r = ttk.Frame(f2)
        r.pack(fill="x")
        ttk.Label(r, text="Channel:").pack(side="left")
        self.mon_ch = tk.StringVar(value="48")
        ttk.Entry(r, textvariable=self.mon_ch, width=6).pack(side="left", padx=4)
        ttk.Button(r, text="Set up monitor (mon0)", command=self._setup_monitor).pack(
            side="left", padx=8,
        )
        ttk.Button(r, text="Restore WiFi", command=self._restore_wifi).pack(side="left")

        # 3) ATTACK CONFIG
        f3 = ttk.LabelFrame(self, text="3  ATTACK CONFIG", padding=8)
        f3.pack(fill="x", padx=10, pady=4)
        self.var_ap = self._cfg_row(f3, 0, "AP BSSID", "fe:7a:58:92:b6:31")
        self.var_victim = self._cfg_row(f3, 1, "Victim MAC", "d2:93:e5:7c:20:71")
        self.var_channel = self._cfg_row(f3, 2, "Channel", "48")
        self.var_alpha = self._cfg_row(f3, 3, "Alpha (0=none, 1=full)", "1.0")
        self.var_offset = self._cfg_row(f3, 4, "Offset", "33")
        self.var_type = self._cfg_row(f3, 5, "Type (hex)", "0xe0")
        self.var_iface = self._cfg_row(f3, 6, "Interface", "mon0")

        # 4) ACTIONS
        f4 = ttk.LabelFrame(self, text="4  ACTIONS", padding=8)
        f4.pack(fill="x", padx=10, pady=4)
        ttk.Button(f4, text="Compile", command=self._compile).pack(side="left", padx=4)
        ttk.Button(f4, text="Validate decode (pcap)", command=self._validate).pack(
            side="left", padx=4,
        )
        self.run_btn = ttk.Button(f4, text="Run attack", command=self._toggle_run)
        self.run_btn.pack(side="left", padx=4)

        # 5) LOG
        self.log = scrolledtext.ScrolledText(
            self, height=18, bg="black", fg="#0f0", insertbackground="#0f0",
        )
        self.log.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self._scan()

    # ── helpers ───────────────────────────────────────────────────────

    def _cfg_row(self, parent: ttk.Frame, r: int, label: str, default: str) -> tk.StringVar:
        ttk.Label(parent, text=label).grid(row=r, column=0, sticky="w", pady=2)
        var = tk.StringVar(value=default)
        ttk.Entry(parent, textvariable=var, width=32).grid(row=r, column=1, sticky="w", padx=4)
        return var

    def println(self, msg: str) -> None:
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.update_idletasks()

    def _pump(self) -> None:
        """Poll subprocess stdout and push lines into the log (non-blocking)."""
        if self.proc is None or self.proc.stdout is None:
            return
        line = self.proc.stdout.readline()
        if line:
            self.println(line.rstrip())
        if self.proc.poll() is None:
            self.after(50, self._pump)
        else:
            # drain remaining
            for rest in self.proc.stdout:
                self.println(rest.rstrip())
            self.println(f"[process exited with code {self.proc.returncode}]")
            self.proc = None
            self.run_btn.config(text="Run attack")

    # ── 1) hardware scan ─────────────────────────────────────────────

    def _scan(self) -> None:
        self.hw_list.delete(0, "end")
        try:
            hw = scan_hardware()
        except Exception as exc:
            self.println(f"Scan failed: {exc}")
            return
        for e in hw:
            tag = "monitor-capable" if e["monitor_capable"] else "NO monitor"
            ip = "  [internet]" if e["has_ip"] else ""
            alfa = "  << Alfa" if e["driver"] == "mt7921u" else ""
            self.hw_list.insert(
                "end", f"{e['iface']}  ({e['driver']}, {tag}){ip}{alfa}"
            )
        self.println(f"Scan: {len(hw)} WiFi interface(s) found.")

    # ── 2) monitor setup ─────────────────────────────────────────────

    def _setup_monitor(self) -> None:
        ch = self.mon_ch.get().strip()
        if not ch.isdigit():
            self.println("Channel must be a number.")
            return
        script = MONITOR_SETUP_SCRIPT.format(channel=ch)
        self.println(f"Setting up mon0 on channel {ch} (pkexec prompt)...")
        self.println("WARNING: this drops WiFi internet until you click Restore WiFi.")
        try:
            r = subprocess.run(
                ["pkexec", "sh", "-c", script],
                capture_output=True, text=True, timeout=60,
            )
            if r.stdout:
                self.println(r.stdout.rstrip())
            if r.stderr:
                self.println(r.stderr.rstrip())
            self.println("Monitor setup done." if r.returncode == 0 else "FAILED.")
        except subprocess.TimeoutExpired:
            self.println("Timed out waiting for pkexec.")
        except Exception as exc:
            self.println(f"Error: {exc}")

    def _restore_wifi(self) -> None:
        self.println("Restoring NetworkManager...")
        try:
            subprocess.run(
                ["pkexec", "systemctl", "start", "NetworkManager"],
                capture_output=True, text=True, timeout=30,
            )
            self.println("WiFi restored.")
        except Exception as exc:
            self.println(f"Error: {exc}")

    # ── 3) compile ───────────────────────────────────────────────────

    def _compile(self) -> None:
        self.println("Compiling main_su.cpp ...")
        cmd = [
            "g++", str(SRC), "-o", str(BIN),
            "-I/usr/include/eigen3/", "-L/usr/lib", "-lpcap", "-pthread", "-O3",
        ]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.stdout:
            self.println(r.stdout.rstrip())
        if r.stderr:
            self.println(r.stderr.rstrip())
        self.println("Compile OK." if r.returncode == 0 else "COMPILE FAILED.")

    # ── 4a) validate decode ──────────────────────────────────────────

    def _validate(self) -> None:
        pcap = filedialog.askopenfilename(
            title="Select pcap for decode validation",
            initialdir=str(PCAP_DEFAULT.parent) if PCAP_DEFAULT.parent.exists() else ".",
            initialfile=PCAP_DEFAULT.name if PCAP_DEFAULT.exists() else "",
            filetypes=[("pcap files", "*.pcap"), ("all files", "*")],
        )
        if not pcap:
            return
        ap = self.var_ap.get().strip()
        victim = self.var_victim.get().strip()
        cmd = [str(BIN), "--pcap", pcap, "--ap", ap, "--victim", victim]
        self.println(f"Validate decode: {' '.join(cmd)}")
        try:
            r = subprocess.run(
                ["pkexec"] + cmd,
                capture_output=True, text=True, timeout=60,
            )
            if r.stdout:
                self.println(r.stdout.rstrip())
            if r.stderr:
                self.println(r.stderr.rstrip())
            self.println(
                "Validation done." if r.returncode == 0
                else f"Validation exited with code {r.returncode}."
            )
        except subprocess.TimeoutExpired:
            self.println("Timed out.")
        except Exception as exc:
            self.println(f"Error: {exc}")

    # ── 4b) run / stop attack ────────────────────────────────────────

    def _toggle_run(self) -> None:
        if self.proc is not None:
            self._stop()
            return
        if not BIN.exists():
            self.println("Binary not found — click Compile first.")
            return
        cmd = [
            str(BIN),
            "--iface", self.var_iface.get().strip(),
            "--ap", self.var_ap.get().strip(),
            "--victim", self.var_victim.get().strip(),
            "--alpha", self.var_alpha.get().strip(),
            "--type", self.var_type.get().strip(),
            "--offset", self.var_offset.get().strip(),
        ]
        self.println(f"Launching: {' '.join(cmd)}")
        try:
            self.proc = subprocess.Popen(
                ["pkexec"] + cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            self.run_btn.config(text="Stop")
            self._pump()
        except Exception as exc:
            self.println(f"Failed to start: {exc}")

    def _stop(self) -> None:
        self.println("Stopping attack process...")
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
            self.proc = None
        self.run_btn.config(text="Run attack")
        self.println("Stopped. If it lingers: sudo pkill main_su")


if __name__ == "__main__":
    App().mainloop()
