"""Fault-injection regressions for management, retries and polling isolation."""
from collections import Counter
from contextlib import ExitStack
import datetime
import json
from pathlib import Path
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal_auto as engine
import portal_luci as api
import portal_openwrt as port


class Clock:
    def __init__(self):
        self.now = 0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class Child:
    pid = 4321

    def __init__(self, ignore_term=False):
        self.returncode = None
        self.ignore_term = ignore_term
        self.signals = []
        self.waits = []
        self.killed = False

    def poll(self):
        return self.returncode

    def send_signal(self, sig):
        self.signals.append(sig)
        if not self.ignore_term:
            self.returncode = -sig

    def kill(self):
        self.killed = True
        self.returncode = -signal.SIGKILL

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if self.returncode is None:
            raise subprocess.TimeoutExpired('synthetic child', timeout)
        return self.returncode


class ReliabilityTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        for module, name, path in ((port, 'RUNTIME', self.root/'run'),
                                    (port, 'PERSIST', self.root/'etc'),
                                    (port, 'SYSNET', self.root/'net'),
                                    (port, 'HANDLE', self.root/'handle'),
                                    (port, 'ENGINE_LOCK', self.root/'engine.lock'),
                                    (port, 'CONFIG_FILE', self.root/'uci'),
                                    (api, 'JOBS', self.root/'jobs')):
            self.stack.enter_context(patch.object(module, name, path))
        for path in (port.RUNTIME, port.PERSIST, port.SYSNET, api.JOBS):
            path.mkdir()
        self.settings = port.Settings('br-lan', '10.0.0.250/24', '10.0.0.100', '10.0.0.101')
        self.stack.enter_context(patch.object(api, 'process_identity', return_value='synthetic'))
        self.clock = Clock()

    def job(self, action='start', **values):
        requests = {'start': {'autostart': 0}, 'profile': {'profile': '100'}}
        value = dict(id='a'*32, action=action, request=requests.get(action, {}), state='queued')
        value.update(values)
        port.atomic(api.JOBS/'job.json', value)
        return value['id']

    def stop(self, job_id, orphan=None):
        api.update_job(job_id, cleanup_attempted=True, cleanup_complete=True, cleanup_required=False)

    def clock_patches(self):
        self.stack.enter_context(patch.object(api.time, 'monotonic', self.clock.monotonic))
        self.stack.enter_context(patch.object(api.time, 'sleep', self.clock.sleep))

    def start_prerequisites(self):
        port.atomic(port.PERSIST / 'auto-config.json', {
            'network': self.settings.engine(), 'profile': self.settings.profile,
            'ps5_mac': '02:00:00:00:00:02', 'portal_mac': '02:00:00:00:00:03'})
        self.stack.enter_context(patch.object(port.Settings, 'load', return_value=self.settings))
        self.stack.enter_context(patch.object(api, 'checked'))

    def test_task_record_failure_terminates_and_reaps_a_real_child(self):
        job_id = self.job()
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
        def finish():
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
        self.addCleanup(finish)
        with patch.object(api.subprocess, 'Popen', return_value=child):
            with patch.object(api, 'update_job', side_effect=OSError('job storage unavailable')):
                with self.assertRaisesRegex(OSError, 'job storage unavailable'):
                    api.run_child(job_id, [api.CLI, 'doctor'])
        self.assertIsNotNone(child.poll())

    def test_child_timeout_kills_an_unresponsive_child_and_clears_identity(self):
        job_id = self.job('stop')
        child = Child(ignore_term=True)
        self.clock_patches()
        with patch.object(api.subprocess, 'Popen', return_value=child):
            with self.assertRaisesRegex(RuntimeError, '操作执行超时'):
                api.run_child(job_id, [api.SERVICE, 'stop'], deadline=1)
        self.assertTrue(child.killed)
        self.assertEqual(child.signals, [signal.SIGTERM])
        self.assertEqual(child.waits, [5, 5])
        self.assertIsNone(api.optional(api.JOBS/'job.json')['child_pid'])

    def test_cancelled_child_has_a_bounded_recovery_wait(self):
        job_id = self.job('trial')
        (api.JOBS/('cancel.'+job_id)).touch()
        child = Child(ignore_term=True)
        with patch.object(api.subprocess, 'Popen', return_value=child):
            api.run_child(job_id, [api.CLI, 'try', '--seconds', '90'], cancellable=True)
        self.assertTrue(child.killed)
        self.assertEqual(child.waits, [90, 5])

    def test_worker_registration_failure_terminates_the_waiting_worker(self):
        child = Child()
        real_atomic = port.atomic
        def atomic(path, value):
            if value.get('pid') == child.pid and value.get('state') == 'queued':
                raise OSError('worker registration unavailable')
            return real_atomic(path, value)
        with patch.object(api.subprocess, 'Popen', return_value=child), patch.object(port, 'atomic', side_effect=atomic):
            with self.assertRaisesRegex(OSError, 'worker registration unavailable'):
                api.dispatch('doctor', {})
        self.assertEqual(child.signals, [signal.SIGTERM])
        self.assertEqual(api.current_job()['state'], 'failed')
        self.assertFalse(api.current_job()['busy'])

    def test_failed_stop_retains_the_original_orphan_for_another_stop_retry(self):
        orphan = {'pid': 8765, 'identity': 'synthetic', 'action': 'trial'}
        self.job('stop', state='failed', orphan=orphan)
        with self.assertRaisesRegex(RuntimeError, '先点击停止'):
            api.dispatch('repair', {})
        with patch.object(api.subprocess, 'Popen', return_value=Child()):
            self.assertTrue(api.dispatch('stop', {})['ok'])
        self.assertEqual(api.optional(api.JOBS/'job.json')['orphan'], orphan)

    def test_start_timeout_stops_the_requested_service_before_finishing(self):
        job_id = self.job()
        self.start_prerequisites()
        self.clock_patches()
        with patch.object(api, 'START_TIMEOUT', 1), patch.object(api, 'run_child') as child:
            with patch.object(api, 'managed_state', return_value={'running': False}):
                with patch.object(api, 'stop_service', side_effect=self.stop) as stop:
                    self.assertEqual(api.worker(job_id), 1)
        self.assertEqual(child.call_args.kwargs['deadline'], 1)
        stop.assert_called_once_with(job_id)
        saved = api.current_job()
        self.assertIn('启动超时', saved['error'])
        self.assertFalse(saved['busy'])

    def test_start_deadline_includes_the_init_request(self):
        job_id = self.job()
        self.start_prerequisites()
        self.clock_patches()
        def request(*args, **kwargs):
            self.clock.now += 2
        with patch.object(api, 'START_TIMEOUT', 1), patch.object(api, 'run_child', side_effect=request):
            with patch.object(api, 'managed_state') as state, patch.object(api, 'stop_service', side_effect=self.stop):
                self.assertEqual(api.worker(job_id), 1)
        state.assert_not_called()

    def test_cancel_interleaved_with_start_error_still_stops_the_service(self):
        job_id = self.job()
        self.start_prerequisites()
        def state():
            (api.JOBS/('cancel.'+job_id)).touch()
            raise OSError('namespace status unavailable')
        with patch.object(api, 'run_child'), patch.object(api, 'managed_state', side_effect=state):
            with patch.object(api, 'stop_service', side_effect=self.stop) as stop:
                self.assertEqual(api.worker(job_id), 1)
        stop.assert_called_once_with(job_id)
        self.assertIn('namespace status unavailable', api.current_job()['error'])
        self.assertFalse((api.JOBS/('cancel.'+job_id)).exists())

    def test_lost_job_ownership_keeps_the_new_management_action_untouched(self):
        job_id = self.job()
        self.start_prerequisites()
        def child(*args, **kwargs):
            port.atomic(api.JOBS/'job.json', {'id': 'b'*32, 'action': 'start', 'state': 'running',
                        'request': {'autostart': 0}, 'cleanup_required': True})
            raise RuntimeError('Job ownership changed')
        with patch.object(api, 'run_child', side_effect=child), patch.object(api, 'stop_service') as stop:
            self.assertEqual(api.worker(job_id), 1)
        stop.assert_not_called()
        self.assertEqual(api.optional(api.JOBS/'job.json')['id'], 'b'*32)

    def test_cancelled_baseline_error_invalidates_both_receipts(self):
        job_id = self.job('baseline')
        (api.JOBS/('cancel.'+job_id)).touch()
        (port.PERSIST/'baseline.json').write_text('{}')
        (port.RUNTIME/'auto-baseline.json').write_text('{}')
        with patch.object(api, 'run_child', side_effect=OSError('capture unavailable')):
            with patch.object(api, 'stop_service', side_effect=self.stop) as stop:
                self.assertEqual(api.worker(job_id), 1)
        stop.assert_called_once_with(job_id)
        self.assertFalse((port.PERSIST/'baseline.json').exists())
        self.assertFalse((port.RUNTIME/'auto-baseline.json').exists())

    def test_original_and_cleanup_errors_are_preserved_and_repair_can_be_retried(self):
        job_id = self.job()
        self.start_prerequisites()
        with patch.object(api, 'run_child', side_effect=RuntimeError('start failed')):
            with patch.object(api, 'stop_service', side_effect=RuntimeError('cleanup failed')):
                self.assertEqual(api.worker(job_id), 1)
        saved = api.current_job()
        self.assertEqual(saved['error'], 'start failed')
        self.assertEqual(saved['cleanup_error'], 'cleanup failed')
        self.assertFalse(saved['busy'])  # The test worker PID is still alive here.
        child = Child()
        with patch.object(api.subprocess, 'Popen', return_value=child):
            self.assertTrue(api.dispatch('repair', {})['ok'])

    def test_cleanup_failure_finishes_once_and_releases_the_busy_state(self):
        job_id = self.job('stop')
        requests = []
        def child(_id, argv, **kwargs):
            requests.append(argv)
            if argv == [api.CLI, 'repair']:
                (api.JOBS/('cancel.'+job_id)).touch()
                raise RuntimeError('namespace deletion failed')
        with patch.object(api, 'run_child', side_effect=child), patch.object(api, 'controller_idle', return_value=True):
            with patch.object(port, 'pids', return_value=[]):
                self.assertEqual(api.worker(job_id), 1)
        self.assertEqual(requests, [[api.SERVICE, 'stop'], [api.CLI, 'repair']])
        saved = api.current_job()
        self.assertEqual(saved['state'], 'failed')
        self.assertEqual(saved['cleanup_error'], 'namespace deletion failed')
        self.assertFalse(saved['busy'])
        self.assertFalse(saved['stopping'])

    def test_stop_wait_has_a_deadline_and_preserves_retry_state(self):
        job_id = self.job('stop')
        self.clock_patches()
        with patch.object(api, 'STOP_TIMEOUT', 1), patch.object(api, 'run_child') as child:
            with patch.object(api, 'controller_idle', return_value=False):
                self.assertEqual(api.worker(job_id), 1)
        self.assertEqual(child.call_count, 1)
        self.assertFalse(api.current_job()['busy'])
        self.assertIn('退出超时', api.current_job()['cleanup_error'])

    def test_controller_lock_io_error_fails_promptly(self):
        with patch.object(port, 'exclusive', side_effect=OSError('lock unavailable')):
            with self.assertRaisesRegex(OSError, 'lock unavailable'):
                api.controller_idle()

    def test_cancel_marker_unlink_failure_keeps_a_terminal_job_retryable(self):
        job_id = self.job('doctor')
        cancel = api.JOBS/('cancel.'+job_id)
        cancel.touch()
        original = Path.unlink
        def unlink(path, *args, **kwargs):
            if path == cancel:
                raise OSError('cancel marker storage unavailable')
            return original(path, *args, **kwargs)
        with patch.object(api, 'run_child'), patch.object(api, 'stop_service', side_effect=self.stop):
            with patch.object(Path, 'unlink', unlink):
                self.assertEqual(api.worker(job_id), 0)
        self.assertTrue(cancel.exists())
        self.assertFalse(api.current_job()['busy'])
        self.assertFalse(api.current_job()['stopping'])

    def test_failed_rollback_start_is_cleaned_up_and_preserves_both_errors(self):
        job_id = self.job('profile')
        self.start_prerequisites()
        starts = []
        def child(_id, argv, **kwargs):
            if argv == [api.SERVICE, 'start']:
                starts.append(argv)
                raise RuntimeError('new start failed' if len(starts) == 1 else 'rollback start failed')
        with patch.object(port, 'command', return_value=subprocess.CompletedProcess([], 0, '', '')):
            with patch.object(api, 'run_child', side_effect=child), patch.object(api, 'stop_service', side_effect=self.stop) as stop:
                self.assertEqual(api.worker(job_id), 1)
        self.assertEqual(stop.call_count, 3)
        saved = api.current_job()
        self.assertEqual(saved['error'], 'new start failed')
        self.assertEqual(saved['rollback_error'], 'rollback start failed')
        self.assertFalse(saved['busy'])


# Polling uses the same filesystem fixture, with an independent TestCase class.
class PollingTests(unittest.TestCase):
    setUp = ReliabilityTests.setUp
    job = ReliabilityTests.job

    def configure(self):
        self.config = {'network': self.settings.engine(), 'profile': '65',
                       'ps5_mac': '02:00:00:00:00:02', 'portal_mac': '02:00:00:00:00:03'}
        port.atomic(port.PERSIST/'auto-config.json', self.config)
        port.atomic(port.PERSIST/'baseline.json', {'port_fingerprint': port.port_fingerprint(self.settings),
                    'upstream': {'fingerprint': engine.fingerprint(self.config), 'forwarded_out': 10, 'restored': True}})
        port.HANDLE.touch()
        port.CONFIG_FILE.write_text('synthetic UCI config')
        (port.SYSNET/'br-lan'/'bridge').mkdir(parents=True)
        port.atomic(port.RUNTIME/'engine.json', {'pid': 123, 'identity': 'synthetic', 'generation': 'test',
                    'mode': 'active', 'started_monotonic': time.monotonic()})
        port.atomic(port.RUNTIME/'engine-ready.json', {'pid': 123, 'generation': 'test', 'ready': True})
        port.atomic(port.RUNTIME/'status.json', {'pid': 123, 'state': 'running',
                    'time': datetime.datetime.now(datetime.timezone.utc).isoformat()})
        self.calls = []
        values = dict(port.asdict(self.settings), enabled='1')
        def command(*args, **kwargs):
            self.calls.append(args)
            if args == ('uci', '-q', 'show', 'ps_accel.main'):
                text = '\n'.join('ps_accel.main.'+key+'='+shlex.quote(value) for key, value in values.items())
            elif args == ('ip', 'netns', 'pids', port.NS):
                text = '123\n'
            elif args == (api.SERVICE, 'enabled'):
                text = ''
            else:
                raise AssertionError('Unexpected command: '+repr(args))
            return subprocess.CompletedProcess(args, 0, text, '')
        self.stack.enter_context(patch.object(port, 'command', side_effect=command))

    def test_status_polls_one_command_and_reads_no_config_fingerprints_or_logs(self):
        self.configure()
        with patch.object(engine, 'fingerprint') as fingerprint, patch.object(api, 'tail') as tail:
            with patch.object(port, 'uci_values') as uci:
                result = api.status()
        self.assertTrue(result['running'])
        self.assertEqual(self.calls, [('ip', 'netns', 'pids', port.NS)])
        for function in (fingerprint, tail, uci):
            function.assert_not_called()
        for key in ('config', 'log', 'events', 'environment'):
            self.assertNotIn(key, result)

    def test_details_reuses_one_uci_read_and_one_engine_fingerprint(self):
        self.configure()
        with patch.object(engine, 'fingerprint', wraps=engine.fingerprint) as fingerprint:
            result = api.details()
        self.assertTrue(result['baseline_valid'])
        self.assertTrue(result['autostart'])
        self.assertEqual(result['config'], port.asdict(self.settings))
        self.assertEqual(dict(Counter(call[0] for call in self.calls)), {'uci': 1, api.SERVICE: 1})
        self.assertEqual(fingerprint.call_count, 1)

    def test_process_query_error_returns_a_recoverable_status(self):
        port.HANDLE.touch()
        self.job('stop', state='failed', error='cleanup failed')
        with patch.object(port, 'pids', side_effect=subprocess.TimeoutExpired('ip', 2)):
            result = api.status()
        self.assertTrue(result['ok'])
        self.assertFalse(result['state_known'])
        self.assertTrue(result['cleanup_pending'])
        self.assertTrue(result['recovery_required'])
        self.assertTrue(result['status_warnings'])
        self.assertFalse(result['job']['busy'])

    def test_namespace_removal_race_returns_an_empty_process_list(self):
        port.HANDLE.touch()
        def command(*args, **kwargs):
            port.HANDLE.unlink()
            raise subprocess.CalledProcessError(1, args)
        with patch.object(port, 'command', side_effect=command):
            self.assertEqual(port.pids(), [])

    def test_logs_reads_only_the_selected_file_and_caps_its_size(self):
        (api.JOBS/'job.log').write_text('a'*50000)
        (port.RUNTIME/'events.log').write_text('b'*50000)
        with patch.object(api, 'tail', wraps=api.tail) as tail:
            result = api.dispatch('logs', {'kind': 'events'})
        tail.assert_called_once_with(port.RUNTIME/'events.log')
        self.assertEqual(result['text'], 'b'*12000)
        for kind in ('../job.log', '', None, ['log']):
            with self.assertRaises(ValueError):
                api.validate('logs', {'kind': kind})

    def test_uci_section_decodes_quoted_values_without_executing_them(self):
        payload = "ps_accel.main='ps_accel'\nps_accel.main.bridge='br-lan'\nps_accel.main.address='$(touch marker)'\n"
        with patch.object(port, 'command', return_value=subprocess.CompletedProcess([], 0, payload, '')) as command:
            values = port.uci_values()
        self.assertEqual(values['address'], '$(touch marker)')
        self.assertEqual(command.call_count, 1)

    def test_code_change_invalidates_details_revision_and_the_full_start_gate(self):
        copied = self.root/'code'
        copied.mkdir()
        for name in port.FINGERPRINT_FILES:
            (copied/name).write_bytes((engine.ROOT/name).read_bytes())
        with patch.object(engine, 'ROOT', copied), patch.object(port, 'APP', copied):
            self.configure()
            receipt = api.details()
            self.assertTrue(receipt['baseline_valid'])
            (copied/'protocol.py').write_bytes((copied/'protocol.py').read_bytes()+b'\n# changed code\n')
            self.assertNotEqual(receipt['details_revision'], port.configuration_revision())
            with self.assertRaisesRegex(RuntimeError, 'different code/configuration'):
                port.verify_baseline(self.settings)

    def test_details_config_failure_stays_readable_and_reports_its_error(self):
        with patch.object(port, 'uci_values', side_effect=OSError('UCI unavailable')):
            result = api.details()
        self.assertTrue(result['ok'])
        self.assertFalse(result['baseline_valid'])
        self.assertIn('UCI unavailable', result['details_warnings'])


if __name__ == '__main__':
    unittest.main()
