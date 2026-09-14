#!/usr/bin/env python3
"""BeamCraft Attack GUI — polished Tkinter control panel for beamforming-spoofing attack."""

import os
import re
import signal
import subprocess
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import scrolledtext

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
BINARY = "/home/lutfil/fyp/BeamCraft_AE/main_su"

DEFAULTS = {
    "iface": "mon0",
    "ap": "fe:7a:58:92:b6:31",
    "victim": "d2:93:e5:7c:20:71",
    "channel": "48",
    "alpha": "1.0",
    "offset": "33",
    "type": "0xe0",
}


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("BeamCraft — Attack Control Panel")
        self.geometry("820x920")
        self.minsize(740, 780)
        self.configure(bg="#1e1e1e")
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.attack_proc = None
        self.attack_running = False
        self.monitor_output = ""
        self.attack_output_lines: list[str] = []
        self.frame_count = 0
        self.attack_start: float | None = None
        self.attack_end: float | None = None

        self._build_ui()

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        bg = "#1e1e1e"
        fg = "#d4d4d4"
        entry_bg = "#2d2d2d"
        accent = "#4fc3f7"

        # ---- Status bar
        status_frame = tk.Frame(self, bg="#111", padx=10, pady=6)
        status_frame.pack(fill="x")
        self.status_dot = tk.Canvas(status_frame, width=14, height=14,
                                    bg="#111", highlightthickness=0)
        self.status_dot.pack(side="left")
        self._dot_id = self.status_dot.create_oval(2, 2, 12, 12, fill="#888", outline="")
        self.status_label = tk.Label(status_frame, text="Idle", font=("Consolas", 11, "bold"),
                                     bg="#111", fg=fg)
        self.status_label.pack(side="left", padx=8)

        # ---- Step 1: Monitor mode
        step1 = tk.LabelFrame(self, text=" ① Monitor Mode ", font=("Consolas", 10, "bold"),
                              bg=bg, fg=accent, padx=10, pady=6)
        step1.pack(fill="x", padx=10, pady=(10, 4))

        btn_row = tk.Frame(step1, bg=bg)
        btn_row.pack(fill="x")

        self.btn_monitor = tk.Button(btn_row, text="① Set up monitor mode",
                                     font=("Consolas", 10, "bold"), bg="#2a5a2a", fg="white",
                                     activebackground="#3a7a3a", relief="flat", padx=12, pady=4,
                                     command=self._setup_monitor)
        self.btn_monitor.pack(side="left")

        self.btn_scan = tk.Button(btn_row, text="Scan adapters", font=("Consolas", 9),
                                  bg="#333", fg=fg, activebackground="#444", relief="flat",
                                  padx=8, pady=2, command=self._scan_adapters)
        self.btn_scan.pack(side="left", padx=(10, 0))

        tk.Label(step1, text="WiFi internet will be down until Restore WiFi.",
                 font=("Consolas", 8), bg=bg, fg="#999").pack(anchor="w", pady=(4, 0))

        # ---- Config
        cfg = tk.LabelFrame(self, text=" Configuration ", font=("Consolas", 10, "bold"),
                            bg=bg, fg=accent, padx=10, pady=6)
        cfg.pack(fill="x", padx=10, pady=4)

        self.cfg_vars: dict[str, tk.StringVar] = {}
        fields = [
            ("iface", "Interface"),
            ("ap", "AP BSSID"),
            ("victim", "Victim MAC"),
            ("channel", "Channel"),
            ("alpha", "Alpha"),
            ("offset", "Offset"),
            ("type", "Type"),
        ]
        grid = tk.Frame(cfg, bg=bg)
        grid.pack(fill="x")
        for i, (key, label) in enumerate(fields):
            tk.Label(grid, text=label + ":", font=("Consolas", 9), bg=bg, fg=fg,
                     anchor="e").grid(row=i, column=0, sticky="e", padx=(0, 6), pady=1)
            var = tk.StringVar(value=DEFAULTS[key])
            self.cfg_vars[key] = var
            e = tk.Entry(grid, textvariable=var, font=("Consolas", 9), bg=entry_bg, fg="white",
                         insertbackground="white", relief="flat", width=28)
            e.grid(row=i, column=1, sticky="w", pady=1)

        tk.Label(cfg, text="Alpha 1.0 = max disruption, 0 = off",
                 font=("Consolas", 8), bg=bg, fg="#999").pack(anchor="w", pady=(6, 0))

        # ---- Step 2: Attack
        step2 = tk.LabelFrame(self, text=" ② Attack ", font=("Consolas", 10, "bold"),
                              bg=bg, fg="#ef5350", padx=10, pady=6)
        step2.pack(fill="x", padx=10, pady=4)

        self.btn_attack = tk.Button(step2, text="② Fire attack", font=("Consolas", 10, "bold"),
                                    bg="#5a2a2a", fg="white", activebackground="#7a3a3a",
                                    relief="flat", padx=12, pady=4,
                                    command=self._toggle_attack)
        self.btn_attack.pack(side="left")

        self.attack_info = tk.Label(step2, text="", font=("Consolas", 9), bg=bg, fg="#aaa")
        self.attack_info.pack(side="left", padx=12)

        # ---- Observations
        obs = tk.LabelFrame(self, text=" Observations (for report) ",
                            font=("Consolas", 10, "bold"), bg=bg, fg=accent, padx=10, pady=6)
        obs.pack(fill="x", padx=10, pady=4)

        row_obs = tk.Frame(obs, bg=bg)
        row_obs.pack(fill="x")
        tk.Label(row_obs, text="Baseline (Mbps):", font=("Consolas", 9), bg=bg, fg=fg).pack(
            side="left")
        self.var_base = tk.StringVar()
        tk.Entry(row_obs, textvariable=self.var_base, font=("Consolas", 9), bg=entry_bg,
                 fg="white", insertbackground="white", relief="flat", width=8).pack(
            side="left", padx=(4, 14))
        tk.Label(row_obs, text="Under-attack (Mbps):", font=("Consolas", 9), bg=bg, fg=fg).pack(
            side="left")
        self.var_attack_tp = tk.StringVar()
        tk.Entry(row_obs, textvariable=self.var_attack_tp, font=("Consolas", 9), bg=entry_bg,
                 fg="white", insertbackground="white", relief="flat", width=8).pack(
            side="left", padx=(4, 14))
        self.lbl_drop = tk.Label(row_obs, text="Drop: —", font=("Consolas", 9, "bold"),
                                 bg=bg, fg="#fdd835")
        self.lbl_drop.pack(side="left", padx=(10, 0))
        self.var_base.trace_add("write", self._update_drop)
        self.var_attack_tp.trace_add("write", self._update_drop)

        tk.Label(obs, text="Notes:", font=("Consolas", 9), bg=bg, fg=fg, anchor="w").pack(
            anchor="w", pady=(4, 0))
        self.txt_notes = tk.Text(obs, height=3, font=("Consolas", 9), bg=entry_bg, fg="white",
                                 insertbackground="white", relief="flat", wrap="word")
        self.txt_notes.pack(fill="x", pady=(2, 0))

        # ---- Step 3: Restore
        step3 = tk.Frame(self, bg=bg)
        step3.pack(fill="x", padx=10, pady=4)
        self.btn_restore = tk.Button(step3, text="③ Restore WiFi + Save report",
                                     font=("Consolas", 10, "bold"), bg="#2a4a6a", fg="white",
                                     activebackground="#3a5a7a", relief="flat", padx=12, pady=4,
                                     command=self._restore_wifi)
        self.btn_restore.pack(side="left")

        # ---- Log pane
        log_frame = tk.LabelFrame(self, text=" Log ", font=("Consolas", 10, "bold"),
                                  bg=bg, fg=accent, padx=6, pady=4)
        log_frame.pack(fill="both", expand=True, padx=10, pady=(4, 10))
        self.log = scrolledtext.ScrolledText(log_frame, height=12, font=("Consolas", 9),
                                             bg="#0c0c0c", fg="#00ff41", insertbackground="#00ff41",
                                             relief="flat", wrap="word", state="disabled")
        self.log.pack(fill="both", expand=True)

    # ------------------------------------------------------------------ Helpers
    def println(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.configure(state="normal")
        self.log.insert("end", f"[{ts}] {msg}\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _set_status(self, text: str, color: str):
        self.status_label.configure(text=text)
        self.status_dot.itemconfig(self._dot_id, fill=color)

    def _update_drop(self, *_):
        try:
            b = float(self.var_base.get())
            a = float(self.var_attack_tp.get())
            if b > 0:
                drop = (b - a) / b * 100
                self.lbl_drop.configure(text=f"Drop: {drop:.1f}%")
                return
        except ValueError:
            pass
        self.lbl_drop.configure(text="Drop: —")

    def _cfg(self, key: str) -> str:
        return self.cfg_vars[key].get().strip()

    def _run_privileged(self, cmd: str, on_done=None):
        """Run a privileged command in a background thread, call on_done(output) on completion."""
        def _worker():
            try:
                proc = subprocess.run(
                    ["pkexec", "sh", "-c", cmd],
                    capture_output=True, text=True, timeout=120,
                )
                output = proc.stdout + proc.stderr
            except subprocess.TimeoutExpired:
                output = "[TIMEOUT] Command timed out after 120 s"
            except Exception as exc:
                output = f"[ERROR] {exc}"
            self.after(0, lambda: (on_done or self._default_priv_done)(output))
        threading.Thread(target=_worker, daemon=True).start()

    def _default_priv_done(self, output: str):
        self.println(output.strip())

    # --------------------------------------------------------------- Scan
    def _scan_adapters(self):
        self.println("Scanning adapters…")
        def _worker():
            try:
                out = subprocess.check_output(["iw", "dev"], text=True, stderr=subprocess.STDOUT)
            except Exception as exc:
                out = str(exc)
            self.after(0, lambda: self.println(out.strip()))
        threading.Thread(target=_worker, daemon=True).start()

    # -------------------------------------------------------- Monitor mode
    def _setup_monitor(self):
        ch = self._cfg("channel")
        iface = self._cfg("iface")
        cmd = (
            "systemctl stop NetworkManager iwd; "
            "PHY=$(for p in /sys/class/ieee80211/phy*; do "
            "[ \"$(basename $(readlink -f $p/device/driver))\" = mt7921u ] && basename $p; done); "
            f"iw dev {iface} del 2>/dev/null; iw dev wlan1 del 2>/dev/null; "
            f"iw phy $PHY interface add {iface} type monitor; "
            f"ip link set {iface} up; "
            f"iw dev {iface} set channel {ch}; "
            f"iw dev {iface} info | grep -E 'type|channel'"
        )
        self._set_status("Setting up monitor…", "#fdd835")
        self.btn_monitor.configure(state="disabled")
        self.println(f"Running monitor-mode setup (channel {ch})…")

        def _done(output: str):
            self.monitor_output = output
            self.println(output.strip())
            self._set_status("Monitor up", "#66bb6a")
            self.btn_monitor.configure(state="normal")

        self._run_privileged(cmd, on_done=_done)

    # -------------------------------------------------------- Attack start
    def _toggle_attack(self):
        if self.attack_running:
            self._stop_attack()
        else:
            self._fire_attack()

    def _fire_attack(self):
        args = [
            BINARY,
            "--iface", self._cfg("iface"),
            "--ap", self._cfg("ap"),
            "--victim", self._cfg("victim"),
            "--alpha", self._cfg("alpha"),
            "--type", self._cfg("type"),
            "--offset", self._cfg("offset"),
        ]
        self.println(f"Launching: {' '.join(args)}")
        self.attack_output_lines.clear()
        self.frame_count = 0
        self.attack_start = time.time()
        self.attack_end = None

        try:
            self.attack_proc = subprocess.Popen(
                ["pkexec"] + args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
        except Exception as exc:
            self.println(f"[ERROR] Failed to start attack: {exc}")
            return

        self.attack_running = True
        self.btn_attack.configure(text="■ Stop", bg="#8a1a1a")
        self._set_status("ATTACKING", "#ef5350")
        self._poll_attack_output()

    def _poll_attack_output(self):
        """Non-blocking poll of main_su stdout via self.after()."""
        if not self.attack_running or self.attack_proc is None:
            return
        line = self.attack_proc.stdout.readline()
        if line:
            stripped = line.rstrip("\n")
            self.attack_output_lines.append(stripped)
            self.frame_count += 1
            self.println(stripped)
        elapsed = time.time() - self.attack_start if self.attack_start else 0
        self.attack_info.configure(
            text=f"Frames: {self.frame_count}  |  Elapsed: {elapsed:.0f}s"
        )
        if self.attack_proc.poll() is not None:
            # Process ended on its own
            self._finalise_attack()
            return
        self.after(50, self._poll_attack_output)

    def _stop_attack(self):
        if self.attack_proc and self.attack_proc.poll() is None:
            self.attack_proc.terminate()
            try:
                self.attack_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.attack_proc.kill()
        self._finalise_attack()

    def _finalise_attack(self):
        self.attack_running = False
        self.attack_end = time.time()
        self.btn_attack.configure(text="② Fire attack", bg="#5a2a2a")
        self._set_status("Idle", "#888")
        duration = (self.attack_end - self.attack_start) if self.attack_start else 0
        self.attack_info.configure(
            text=f"Done — {self.frame_count} frames in {duration:.1f}s"
        )
        self.println(f"Attack finished. {self.frame_count} frames in {duration:.1f}s.")
        self._save_report(auto=True)

    # -------------------------------------------------------- Restore WiFi
    def _restore_wifi(self):
        self._save_report(auto=False)
        self._set_status("Restoring WiFi…", "#fdd835")
        self.println("Restoring WiFi (starting NetworkManager)…")

        def _done(output: str):
            self.println(output.strip())
            self._set_status("Idle", "#888")
            self.println("WiFi restored.")

        self._run_privileged("systemctl start NetworkManager", on_done=_done)

    # -------------------------------------------------------- Report
    def _save_report(self, auto: bool = False):
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = RESULTS_DIR / f"attack_report_{ts}.txt"

        duration = 0.0
        if self.attack_start:
            end = self.attack_end or time.time()
            duration = end - self.attack_start

        cfg_lines = "\n".join(
            f"  {k:>10s} : {self._cfg(k)}" for k in DEFAULTS
        )

        base_tp = self.var_base.get().strip()
        att_tp = self.var_attack_tp.get().strip()
        drop_pct = "—"
        try:
            b, a = float(base_tp), float(att_tp)
            if b > 0:
                drop_pct = f"{(b - a) / b * 100:.1f}%"
        except ValueError:
            pass

        notes = self.txt_notes.get("1.0", "end").strip()
        tail = "\n".join(self.attack_output_lines[-200:])

        report = f"""\
{'='*60}
Beam Warden — Attack Run Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{'='*60}

--- Configuration ---
{cfg_lines}

--- Monitor Setup Output ---
{self.monitor_output.strip() or '(none)'}

--- Attack Timing ---
  Start    : {datetime.fromtimestamp(self.attack_start).strftime('%H:%M:%S') if self.attack_start else '—'}
  End      : {datetime.fromtimestamp(self.attack_end).strftime('%H:%M:%S') if self.attack_end else '—'}
  Duration : {duration:.1f} s

--- Frames ---
  Processed / injected : {self.frame_count}

--- Observations ---
  Baseline throughput       : {base_tp or '—'} Mbps
  Under-attack throughput   : {att_tp or '—'} Mbps
  Drop                      : {drop_pct}
  Notes:
{notes or '(none)'}

--- main_su output (last {min(200, len(self.attack_output_lines))} lines) ---
{tail or '(no output captured)'}
{'='*60}
"""
        path.write_text(report)
        label = "Auto-saved" if auto else "Saved"
        self.println(f"{label} report → {path}")

    # -------------------------------------------------------- Cleanup
    def _on_close(self):
        if self.attack_running:
            self._stop_attack()
        self.destroy()


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
