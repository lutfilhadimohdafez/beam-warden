#!/usr/bin/env python3
"""Guided exhibition run. Invoked by the dashboard task runner under pkexec.

Uses rig.conf, a fresh loaded baseline, and the existing bounded OBJ1 harness.
BW_DEMO lines carry progress/evidence to the dashboard; normal output is retained.
"""
import argparse
import json
import math
import os
from pathlib import Path
import re
import shlex
import signal
import shutil
import subprocess
import sys
import threading
import time

from rig import RIG
from mt76_telemetry import SSHConn

ROOT = Path(__file__).resolve().parent.parent


def progress(stage, message, **extra):
    print('BW_DEMO ' + json.dumps(dict(stage=stage, message=message, **extra)), flush=True)


def checked(conn, command, timeout=15):
    return conn.run(command, timeout=timeout)


def describe_power(info):
    match = re.search(r'\btxpower\s+(-?\d+(?:\.\d+)?)\s+dBm', info)
    return f'{float(match.group(1)):g} dBm' if match else 'not reported by the driver'


def prepare_power(conn, radio, iface, power):
    """Prefer the requested power, but calibrate unchanged hardware if unsupported.

    The AC2100 has rejected this operation before; a requested value is not
    evidence of applied power. Transport/authentication and other errors remain
    fatal. Return whether a successful setting needs cleanup.
    """
    try:
        checked(conn, f'iw phy {radio} set txpower fixed {power}')
    except ConnectionError as exc:
        if not re.search(r'command failed:\s*(?:Operation )?[Nn]ot supported\s*\(-(122|95)\)', str(exc)):
            raise
        info = checked(conn, f'iw dev {iface} info')
        progress('preparing',
                 f'Fixed TX power is unsupported; leaving AP power unchanged '
                 f'(reported: {describe_power(info)}). Learning a fresh baseline at '
                 'the current power. Attack effects and alerts are not guaranteed.',
                 requested_power_mbm=power, reported_power=describe_power(info), power_changed=False)
        return False
    return True


def valid_baseline(text):
    try:
        values = [float(x) for x in text.split()]
        return len(values) == 8 and all(math.isfinite(x) for x in values) and values[4] > 0
    except ValueError:
        return False


def calibrate_loaded(conn):
    # The calibrator prints human-readable progress, including "baseline learned:"
    # on the final line. Validate the state actually consumed by the watcher.
    checked(conn, "sed 's/^CAL_SECONDS=.*/CAL_SECONDS=20/' /usr/bin/beamwarden | sh -s calibrate", timeout=45)
    baseline = checked(conn, 'cat /var/run/beamwarden.base')
    if not valid_baseline(baseline):
        raise RuntimeError('Calibration did not produce a valid loaded baseline')
    return baseline


def experiment_command(mon, output):
    return [sys.executable, '-u', str(ROOT / 'tools/obj1_run.py'),
            '--no-phone-start', '--monitor-ready', '--mon', mon, '--out', str(output),
            '--baseline', '12', '--burst-secs', '12',
            '--ramp-bursts', '1', '--settle-bursts', '1']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--power', type=int, default=550, help='Preferred AP TX power in mBm; unsupported settings leave power unchanged')
    parser.add_argument('--mon', default='mon0')
    a = parser.parse_args()
    if not 0 <= a.power <= 2000 or not re.fullmatch(r'[A-Za-z0-9_-]{1,15}', a.mon):
        parser.error('power must be 0–2000 mBm and monitor must be an interface name')
    if os.geteuid() != 0:
        parser.error('Run via the dashboard (pkexec) or as root')
    for key in ('ROUTER_HOST', 'ROUTER_USER', 'ROUTER_AP_IFACE', 'VICTIM_IP', 'VICTIM_MAC', 'ROUTER_AP_BSSID'):
        if not RIG.get(key):
            parser.error(f'{key} is missing from rig.conf')
    for key in ('ROUTER_AP_IFACE', 'ROUTER_CHANNEL', 'VICTIM_MAC', 'ROUTER_AP_BSSID'):
        if not re.fullmatch(r'[A-Za-z0-9_.:-]+', RIG[key]):
            parser.error(f'invalid {key} in rig.conf')

    def interrupted(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    child = load = None
    power_changed = False
    output_csv = None
    watcher_stopped = False
    watcher_started = False
    adapter_phy = None
    conn = None
    observer_stop = threading.Event()
    observer = None
    alert_seen = threading.Event()
    result = 1
    try:
        progress('checking', 'Checking router, protected client and phone traffic server…', alert=False)
        conn = SSHConn(RIG['ROUTER_HOST'], RIG['ROUTER_USER'], RIG['ROUTER_PASS'])
        conn.__enter__()
        iface = shlex.quote(RIG['ROUTER_AP_IFACE'])
        info = checked(conn, f'iw dev {iface} info')
        phy = re.search(r'\bwiphy\s+(\d+)', info)
        if not phy:
            raise RuntimeError('Could not identify the AP radio')
        checked(conn, 'test -x /usr/bin/beamwarden && test -x /etc/init.d/beamwarden && test -s /etc/beamwarden/model.awk')
        configured = checked(conn, ". /etc/beamwarden.conf; printf '%s\\n%s\\n' \"$AP_IF\" \"${MAC:-}\"").splitlines()
        if not configured or configured[0] != RIG['ROUTER_AP_IFACE'] or (len(configured) > 1 and configured[1] and configured[1].lower() != RIG['VICTIM_MAC'].lower()):
            raise RuntimeError('Router detector AP_IF/MAC does not match rig.conf; correct /etc/beamwarden.conf before retrying')
        stations = checked(conn, f'iw dev {iface} station dump')
        if RIG['VICTIM_MAC'].lower() not in stations.lower():
            raise RuntimeError('Protected phone is not associated with the configured AP')
        probe = subprocess.run(['iperf3', '-c', RIG['VICTIM_IP'], '-p', '5201', '-t', '1'],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        if probe.returncode:
            raise RuntimeError('Phone traffic server unavailable. Open Termux on the phone and run: iperf3 -s')
        # Set power BEFORE learning the baseline, to avoid calibrating one RF condition
        # and demonstrating another. Never sweep power against a stale baseline.
        progress('preparing', f'Requesting demo power {a.power / 100:g} dBm; preparing the attack adapter…')
        power_changed = prepare_power(conn, f'phy{phy.group(1)}', iface, a.power)
        if power_changed:
            info = checked(conn, f'iw dev {iface} info')
            progress('preparing', f'Power command accepted. Driver reports {describe_power(info)}; '
                     'calibration will use these actual RF conditions.',
                     requested_power_mbm=a.power, reported_power=describe_power(info), power_changed=True)
        from aba_mt76 import monitor_up
        from aba_measure import ensure_attack_dead
        ensure_attack_dead()
        checked(conn, '/etc/init.d/beamwarden stop')
        watcher_stopped = True
        # Override only the running script's CAL_SECONDS assignment. The installed
        # config, credentials and alert settings remain untouched.
        progress('calibrating', 'Learning 20 seconds of normal traffic. Keep the phone still; no attack is running.')
        load = subprocess.Popen(['iperf3', '-c', RIG['VICTIM_IP'], '-p', '5201', '-t', '60'],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(2)
        calibration = calibrate_loaded(conn)
        if load.poll() is not None:
            raise RuntimeError('Traffic stopped during calibration; start the phone server and retry')
        load.terminate(); load.wait(timeout=5); load = None
        # Do not spend the adapter's healthy capture window on calibration.
        progress('preparing', 'Baseline saved. Preparing the adapter immediately before the experiment…')
        adapter_phy = monitor_up(a.mon, RIG['ROUTER_CHANNEL'])
        old_alerts = set(checked(conn, 'logread -e beamwarden | tail -n 80').splitlines())
        checked(conn, '/etc/init.d/beamwarden restart')
        checked(conn, '/etc/init.d/beamwarden running')
        watcher_started = True
        progress('ready', 'Fresh baseline learned. Starting measured baseline and bounded attack bursts automatically.')

        def observe():
            try:
                with SSHConn(RIG['ROUTER_HOST'], RIG['ROUTER_USER'], RIG['ROUTER_PASS']) as watch:
                    while not observer_stop.is_set():
                        for line in watch.run('logread -e beamwarden | tail -n 80').splitlines():
                            if line not in old_alerts and 'ALERT beamforming-attack:' in line:
                                old_alerts.add(line)
                                alert_seen.set()
                                progress('running', 'The router logged an attack alert. Check Telegram for delivery.', alert=True, router_alert=line)
                        observer_stop.wait(3)
            except Exception:
                progress('running', 'Router alert log is unavailable; see experiment output. Telegram delivery is not verified.')
        observer = threading.Thread(target=observe, daemon=True)
        observer.start()
        dest = ROOT / 'results/sessions' / time.strftime('demo_%Y%m%d_%H%M%S.csv')
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.with_suffix('.baseline.json').write_text(json.dumps({
            'feature_schema': 'interval-v2',
            'baseline': [float(v) for v in calibration.split()],
            'calibration': 'separate preceding loaded normal traffic',
            'ap_info': info,
        }, indent=2))
        progress('running', 'Recording 12 seconds of normal traffic, then two 12-second attack bursts. Short runs limit adapter exposure; an alert is not guaranteed.', csv=str(dest.relative_to(ROOT)))
        child = subprocess.Popen(experiment_command(a.mon, dest), start_new_session=True)
        try:
            code = child.wait(timeout=60)
        except subprocess.TimeoutExpired:
            raise RuntimeError('Experiment exceeded the 60-second limit; stopping it and restoring the adapter')
        if code:
            raise RuntimeError(f'Experiment failed (exit {code}); see the live console')
        # Allow the final watcher window/log poll to finish before reporting evidence.
        observer_stop.wait(4)
        output_csv = str(dest.relative_to(ROOT))
        progress('finishing', 'Experiment finished; cleaning up the demo…')
        result = 0
    except KeyboardInterrupt:
        progress('stopping', 'Stopping the experiment and restoring AP power…')
        result = 130
    except Exception as exc:
        progress('failed', str(exc))
    finally:
        observer_stop.set()
        if child is not None and child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=4)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=3)
        if load is not None and load.poll() is None:
            load.terminate()
            load.wait(timeout=5)
        if conn is not None:
            try:
                if power_changed or adapter_phy is not None:
                    from aba_measure import ensure_attack_dead
                    ensure_attack_dead()
                if power_changed:
                    checked(conn, f'iw phy phy{phy.group(1)} set txpower auto')
                if watcher_stopped and (power_changed or not watcher_started):
                    # Returning to auto power changes RF conditions. Do not leave
                    # the watcher scoring against the temporary demo baseline.
                    checked(conn, '/etc/init.d/beamwarden stop')
            except Exception as exc:
                progress('failed', f'Cleanup needs attention: {exc}')
                result = 1
            conn.__exit__()
        if adapter_phy:
            # The experiment normally tears down its adapter. Also handle a stop
            # or failure before that harness reaches its own cleanup.
            check = subprocess.run(['iw', 'dev', a.mon, 'info'], capture_output=True)
            if check.returncode == 0:
                subprocess.run(['iw', 'dev', a.mon, 'del'], capture_output=True)
                subprocess.run(['iw', 'phy', adapter_phy, 'interface', 'add', 'wlan1', 'type', 'managed'], capture_output=True)
                if shutil.which('nmcli'):
                    subprocess.run(['nmcli', 'device', 'set', 'wlan1', 'managed', 'yes'], capture_output=True)
        if observer is not None:
            observer.join(timeout=2)
        if result == 130:
            progress('stopped', 'Demo stopped. Attack terminated and cleanup attempted.')
    if result == 0:
        power_summary = 'AP power restored to auto' if power_changed else 'AP power left unchanged'
        detector_summary = ('detector stopped because power changed; prepare again for a fresh baseline'
                            if power_changed else 'detector remains running with the fresh baseline')
        progress('complete', ('Run finished. Router alert observed.' if alert_seen.is_set() else
                 'Run finished without a confirmed router alert. Review the charts and phone position.') +
                 f' {power_summary}; {detector_summary}.',
                 alert=alert_seen.is_set(), csv=output_csv)
    return result


if __name__ == '__main__':
    sys.exit(main())
