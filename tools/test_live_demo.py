"""Regression checks for demo orchestration and dashboard evidence (no hardware)."""
import asyncio
import json
import re
import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import dashboard as d
import live_demo
from mt76_telemetry import parse_iw_station_dump
from starlette.requests import Request


def request(body=None, path='/run/live_demo', name='live_demo', host='127.0.0.1'):
    async def receive():
        return {'type': 'http.request', 'body': json.dumps(body or {}).encode()}
    return Request({'type':'http', 'method':'POST', 'path':path,
                    'client':(host,123), 'headers':[], 'path_params':{'name':name}}, receive)


def setup_function():
    d.TASK_STATE.clear()
    d.LAST_SESSION = {'type':'session','source':'live','detail':'test'}
    d.args = SimpleNamespace(mode='live', driver='mt76', host=d.RIG['ROUTER_HOST'],
                             user=d.RIG['ROUTER_USER'], iface=d.RIG['ROUTER_AP_IFACE'],
                             interval=2.0)  # match real argparse args (shared global; other tests read it)


def test_baseline_validation_rejects_unloaded_and_invalid_data():
    assert live_demo.valid_baseline('0.1 0.01 0.02 0.01 30 2 -70 1')
    for text in ('', '0 0 0 0 0 0 0 0', 'nan 1 1 1 30 1 1 1', '1 2'):
        assert not live_demo.valid_baseline(text)


def test_calibration_uses_persisted_state_not_human_readable_stdout():
    baseline = '0.1 0.01 0.02 0.01 30 2 -70 1'
    conn = Mock()
    conn.run.side_effect = ['calibrating 20s…\nbaseline learned: ' + baseline, baseline]
    assert live_demo.calibrate_loaded(conn) == baseline
    assert conn.run.call_args.args[0] == 'cat /var/run/beamwarden.base'


def test_calibration_rejects_invalid_saved_state_despite_successful_output():
    conn = Mock()
    conn.run.side_effect = ['baseline learned: 0.1 0.01 0.02 0.01 30 2 -70 1', '0 0 0 0 0 0 0 0']
    with pytest.raises(RuntimeError, match='valid loaded baseline'):
        live_demo.calibrate_loaded(conn)


def test_guided_experiment_has_short_total_capture_budget():
    cmd = live_demo.experiment_command('mon0', '/tmp/demo.csv')
    value = lambda key: int(cmd[cmd.index(key) + 1])
    seconds = value('--baseline') + value('--burst-secs') * (value('--ramp-bursts') + value('--settle-bursts'))
    assert seconds == 36


@pytest.mark.parametrize('phone_ssh', [None, 'ssh test-phone'])
def test_teardown_preserves_borrowed_phone_server(phone_ssh):
    import aba_mt76
    with patch.object(aba_mt76, 'ensure_attack_dead'), patch.object(aba_mt76, 'sh') as shell:
        aba_mt76.teardown('phy2', None, phone_ssh)
    commands = [call.args[0] for call in shell.call_args_list]
    assert any('pkill iperf3' in command for command in commands) is bool(phone_ssh)


@pytest.mark.parametrize('error', [
    "ssh 'iw phy phy1 set txpower fixed 550' failed (rc=134): command failed: Not supported (-122)",
    'command failed: Operation not supported (-95)',
])
def test_unsupported_power_keeps_current_conditions_and_reports_actual_power(error):
    conn=Mock()
    conn.run.side_effect=[ConnectionError(error), 'wiphy 1\n txpower 24.00 dBm']
    with patch.object(live_demo,'progress') as report:
        assert live_demo.prepare_power(conn,'phy1','phy1-ap0',550) is False
    assert report.call_args.kwargs['reported_power']=='24 dBm'
    assert report.call_args.kwargs['power_changed'] is False
    assert 'not guaranteed' in report.call_args.args[1]


@pytest.mark.parametrize('error', [
    'Connection timed out', 'Permission denied', 'command failed: Invalid argument (-22)',
    'failed (rc=134): aborted',
])
def test_other_power_errors_remain_fatal(error):
    conn=Mock();conn.run.side_effect=ConnectionError(error)
    with pytest.raises(ConnectionError,match=re.escape(error)):
        live_demo.prepare_power(conn,'phy1','phy1-ap0',550)
    assert conn.run.call_count==1


@pytest.mark.parametrize('returncode,stderr,unsupported',[
    (134,'command failed: Not supported (-122)',True),
    (255,'Connection timed out',False),
    (255,'Permission denied',False),
    (22,'command failed: Invalid argument (-22)',False),
])
def test_power_preparation_through_real_ssh_transport(returncode,stderr,unsupported):
    # Exercise SSHConn.run's real error conversion; mock only the SSH process.
    conn=live_demo.SSHConn('192.0.2.1','root','test-only')
    conn._ctl='/tmp/test-demo-ssh-ctl'
    replies=[SimpleNamespace(returncode=returncode,stderr=stderr,stdout=''),
             SimpleNamespace(returncode=0,stderr='',stdout='wiphy 1\ntxpower 24.00 dBm')]
    with patch('mt76_telemetry.subprocess.run',side_effect=replies) as ssh, patch.object(live_demo,'progress') as report:
        if unsupported:
            assert live_demo.prepare_power(conn,'phy1','phy1-ap0',550) is False
            assert report.call_args.kwargs['reported_power']=='24 dBm'
            assert ssh.call_count==2
        else:
            with pytest.raises(ConnectionError):
                live_demo.prepare_power(conn,'phy1','phy1-ap0',550)
            assert ssh.call_count==1


def test_live_demo_rejects_bad_inputs_before_spawning():
    for body in ({'demo_power':'550; touch /tmp/no'}, {'demo_power':-1}, {'mon':'mon0;id'}):
        with patch.object(d.asyncio,'create_task') as spawn:
            assert asyncio.run(d._run_endpoint(request(body))).status_code == 400
            spawn.assert_not_called()


def test_live_demo_requires_matching_live_router():
    d.LAST_SESSION['source']='replay'
    assert asyncio.run(d._run_endpoint(request())).status_code == 409
    d.LAST_SESSION['source']='live'
    d.args.host='different-router'
    assert asyncio.run(d._run_endpoint(request())).status_code == 409
    assert asyncio.run(d._run_endpoint(request(host='192.168.1.10'))).status_code == 403


def test_demo_locks_radio_and_session_changes():
    d.TASK_STATE['live_demo']={'state':'running','pid':42,'code':None}
    assert asyncio.run(d._run_endpoint(request(name='start_attack'))).status_code == 409
    assert asyncio.run(d._session_endpoint(request({'source':'replay'}))).status_code == 409
    assert asyncio.run(d._session_stop(request())).status_code == 409
    assert asyncio.run(d._monitor_setup(request())).status_code == 409
    assert asyncio.run(d._shutdown(request())).status_code == 409


def test_packet_gate_and_baseline_refresh():
    conn=Mock()
    conn.run.side_effect=['0.1 0.01 0.02 0.01 30 2 -70 1\n3000',
                          '0.2 0.02 0.03 0.01 20 3 -65 2\n3000']
    with patch.object(d.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='1')) as awk:
        assert d._telemetry_verdict(.2,.02,5,[-70],conn,4000)=='attack'
        assert d._telemetry_verdict(.2,.02,50,[-70],conn,100)=='idle'
        assert d._RIG_BASELINE[0]==.2
        assert awk.call_count == 1


def test_bad_model_output_is_not_normal():
    conn=Mock()
    conn.run.return_value='0.1 0.01 0.02 0.01 30 2 -70 1\n3000'
    with patch.object(d.subprocess,'run',return_value=SimpleNamespace(returncode=2,stdout='')):
        assert d._telemetry_verdict(.2,.02,30,[-70],conn,4000) is None


@pytest.mark.parametrize('reason,verdict,hits,alarm,state', [
    ('below_activity_gate','0',0,0,'idle'), ('scored','0',0,0,'normal'),
    ('scored','1',2,0,'suspect'), ('scored','1',3,1,'attack'),
    ('model_error','invalid',0,0,'error'),
])
def test_panel_reads_actual_router_gate_and_persistence(reason,verdict,hits,alarm,state):
    conn = Mock()
    conn.run.return_value = f'running\n1000\n2\n999,0.2,0.01,30,-70,4000,{reason},{verdict},{hits},{alarm},1'
    assert d._router_detector_state(conn)['state'] == state


@pytest.mark.parametrize('text,state', [
    ('stopped\n1000\n2','stopped'), ('running\n1000\n2','unavailable'),
    ('running\n1000\n2\n900,0.2,0.01,30,-70,4000,scored,0,0,0,1','stale'),
])
def test_old_or_missing_trace_is_not_reported_as_normal(text,state):
    conn=Mock(); conn.run.return_value=text
    assert d._router_detector_state(conn)['state']==state


def test_true_failed_counter_available_for_window_per():
    parsed=parse_iw_station_dump('tx packets: 100\ntx retries: 30\ntx failed: 2\n')
    assert parsed['tx_failed']==2
    assert parsed['tx_fail']==30


def test_spawn_failure_clears_running_state():
    d.TASK_STATE['live_demo']={'state':'running','pid':None,'code':None}
    with patch.object(d.asyncio,'create_subprocess_exec',new=AsyncMock(side_effect=FileNotFoundError('pkexec unavailable'))), patch.object(d,'_broadcast',new=AsyncMock()):
        asyncio.run(d._run_task('live_demo',['missing'],True))
    assert d.TASK_STATE['live_demo']['state']=='failed'
    assert d.DEMO_PROGRESS['stage']=='failed'


@pytest.mark.parametrize('unsupported_power',[False,True])
def test_cancellation_during_calibration_restores_power_and_service(unsupported_power):
    conn=MagicMock()
    def run(command, timeout=12):
        if unsupported_power and command.endswith('set txpower fixed 550'):
            raise ConnectionError('command failed: Not supported (-122)')
        if command.startswith('iw dev') and command.endswith(' info'):
            return 'wiphy 1'
        if 'printf' in command and 'AP_IF' in command and 'cp /etc' not in command:
            return live_demo.RIG['ROUTER_AP_IFACE']+'\n'
        if command.endswith('station dump'):
            return 'Station '+live_demo.RIG['VICTIM_MAC']
        if command.startswith("sed 's/^CAL_SECONDS="):
            raise KeyboardInterrupt
        return ''
    conn.run.side_effect=run
    load=Mock()
    load.poll.return_value=None
    with patch('sys.argv',['live_demo.py']), patch.object(live_demo.os,'geteuid',return_value=0), patch.object(live_demo,'SSHConn',return_value=conn), patch.object(live_demo.subprocess,'run',return_value=SimpleNamespace(returncode=0)), patch.object(live_demo.subprocess,'Popen',return_value=load), patch.object(live_demo.time,'sleep'), patch('aba_mt76.monitor_up'), patch('aba_measure.ensure_attack_dead'), patch.object(live_demo,'progress'):
        assert live_demo.main()==130
    commands=[c.args[0] for c in conn.run.call_args_list]
    assert ('iw phy phy1 set txpower auto' in commands) is (not unsupported_power)
    assert commands.count('/etc/init.d/beamwarden stop') == 2
    load.terminate.assert_called_once()


@pytest.mark.parametrize('unsupported_power',[False,True])
def test_completed_run_keeps_no_alert_honest_and_restores_power(unsupported_power):
    conn=MagicMock()
    def run(command, timeout=12):
        if unsupported_power and command.endswith('set txpower fixed 550'):
            raise ConnectionError('command failed: Not supported (-122)')
        if command.startswith('iw dev') and command.endswith(' info'):
            return 'wiphy 1'
        if 'printf' in command and 'AP_IF' in command:
            return live_demo.RIG['ROUTER_AP_IFACE']+'\n'
        if command.endswith('station dump'):
            return 'Station '+live_demo.RIG['VICTIM_MAC']
        if command.startswith("sed 's/^CAL_SECONDS="):
            return 'baseline learned: 0.1 0.01 0.02 0.01 30 2 -70 1'
        if command == 'cat /var/run/beamwarden.base':
            return '0.1 0.01 0.02 0.01 30 2 -70 1'
        return ''
    conn.run.side_effect=run
    load=Mock(); load.poll.return_value=None
    experiment=Mock(); experiment.wait.return_value=0; experiment.poll.return_value=0
    with patch('sys.argv',['live_demo.py']), patch.object(live_demo.os,'geteuid',return_value=0), patch.object(live_demo,'SSHConn',return_value=conn), patch.object(live_demo.subprocess,'run',return_value=SimpleNamespace(returncode=1)), patch.object(live_demo.subprocess,'Popen',side_effect=[load,experiment]), patch.object(live_demo.time,'sleep'), patch.object(live_demo.signal,'signal'), patch('aba_mt76.monitor_up',return_value='phy2'), patch('aba_measure.ensure_attack_dead'), patch.object(live_demo.threading,'Thread'), patch.object(live_demo.threading,'Event') as event, patch.object(live_demo,'progress') as report:
        # Probe succeeds; cleanup query reports no remaining monitor interface.
        with patch.object(live_demo.subprocess,'run',side_effect=[SimpleNamespace(returncode=0),SimpleNamespace(returncode=1)]):
            event.return_value.is_set.return_value=False
            assert live_demo.main()==0
    final=report.call_args
    assert final.args[0]=='complete'
    assert final.kwargs['alert'] is False
    assert 'without a confirmed router alert' in final.args[1]
    commands=[c.args[0] for c in conn.run.call_args_list]
    assert ('iw phy phy1 set txpower auto' in commands) is (not unsupported_power)
    assert ('AP power left unchanged' in final.args[1]) is unsupported_power
    assert commands.count('/etc/init.d/beamwarden stop') == (1 if unsupported_power else 2)
    assert ('detector remains running' in final.args[1]) is unsupported_power
    experiment.wait.assert_called_once_with(timeout=60)


def test_http_page_and_demo_start_with_mocked_worker():
    import httpx
    from pathlib import Path
    page=Path(d.__file__).with_name('dashboard.html').read_text()
    command_center=page.index('id="tab-command-center"')
    assert page.index('id="demoStart"') > command_center
    assert 'id="demoStart"' not in page[:command_center]
    async def worker(name, cmd, privileged):
        assert name=='live_demo' and privileged
        assert cmd[-1]=='550'
        d.TASK_STATE[name]={'state':'done','pid':None,'code':0}
    async def check():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=d.app),base_url='http://localhost') as client:
            assert (await client.get('/tasks')).json()['live_demo']['label']=='Guided Live Demo'
            response=await client.post('/run/live_demo',json={'mon':'mon0','demo_power':550})
            assert response.status_code==200 and response.json()['ok']
            await asyncio.sleep(0)
            assert d.TASK_STATE['live_demo']['state']=='done'
    with patch.object(d,'_run_task',side_effect=worker):
        asyncio.run(check())
