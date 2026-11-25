import datetime
import json
import logging
from pathlib import Path
import signal
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from scapy.all import Ether, IP, UDP, Raw

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal_auto as engine
import portal_auto_platform as net
import portal_luci as api
import portal_openwrt as port
from telemetry import Telemetry
from test_probe import fixture
from test_telemetry import wait_until


class ForwardingIsolationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.state = {'config': {'interface': 'relay0', 'ps5_ip': net.PS5, 'portal_ip': net.PORTAL},
                      'own_mac': '02:00:00:00:00:01', 'ps5_mac': '02:00:00:00:00:02',
                      'portal_mac': '02:00:00:00:00:03'}
        self.config = {'network': self.state['config'], 'profile': '65',
                       'ps5_mac': self.state['ps5_mac'], 'portal_mac': self.state['portal_mac']}
        self.addCleanup(engine.LOG.setLevel, engine.LOG.level)
        engine.LOG.setLevel(logging.INFO)
        self.addCleanup(setattr, engine.probe, 'network', engine.probe.network)
        self.addCleanup(setattr, engine.probe, 'PATCH_DELTA', engine.probe.PATCH_DELTA)

    def run_relay(self, ready_for_packets, recorders):
        payload, *_ = fixture()
        frame = bytes(Ether(src=self.state['portal_mac'], dst=self.state['own_mac']) /
                      IP(src=net.PORTAL, dst=net.PS5) / UDP(dport=9296) / Raw(payload))
        handlers, received = {}, 0
        guard = MagicMock(pid=456)
        guard.poll.return_value = None
        guard.stdout.readline.return_value = b'GUARD_READY\n'

        def wait_for_guard(timeout=None):
            (self.root / 'recovery-required').unlink(missing_ok=True)
            return 0

        guard.wait.side_effect = wait_for_guard

        def receive(_socket):
            nonlocal received
            if received == 0:
                self.assertTrue(ready_for_packets())
            if received == 40:
                handlers[signal.SIGTERM](signal.SIGTERM, None)
                return None
            received += 1
            return frame

        def recorder(runtime):
            value = Telemetry(runtime)
            recorders.append(value)
            return value

        with (
            patch.object(net, 'state_for', return_value=self.state),
            patch.object(net, 'Lock') as lock,
            patch.object(net, 'open_socket'),
            patch.object(net, 'receive', side_effect=receive),
            patch.object(net, 'send') as send,
            patch.object(engine.subprocess, 'Popen', return_value=guard),
            patch.object(engine.signal, 'signal', side_effect=lambda sig, fn: handlers.update({sig: fn})),
            patch.object(engine, 'Telemetry', side_effect=recorder),
        ):
            counts = engine.run(self.config, self.root, generation='new-launch', require_baseline=False)
        self.assertEqual(counts['forwarded_out'], 40)
        self.assertEqual(counts['unique_modified_startups'], 1)
        forwarded = [call.args[1] for call in send.call_args_list if isinstance(call.args[1], bytes)]
        self.assertEqual(len(forwarded), 40)
        self.assertNotEqual(forwarded[0][14:], frame[14:])
        lock.return_value.close.assert_called_once()
        self.assertTrue(lock.return_value.close.call_args.kwargs['repaired'])
        self.assertEqual(json.loads((self.root / 'engine-ready.json').read_text())['generation'], 'new-launch')

    def test_log_and_status_write_errors_preserve_forwarding_and_recovery(self):
        recorders = []
        with (
            patch.object(Telemetry, 'write_status', side_effect=OSError('status storage unavailable')),
            patch.object(Telemetry, 'write_events', side_effect=OSError('log storage unavailable')),
        ):
            self.run_relay(lambda: wait_until(lambda: recorders[0].health()['write_errors'] > 0), recorders)
        self.assertGreaterEqual(recorders[0].health()['write_errors'], 2)
        self.assertFalse((self.root / 'recovery-required').exists())

    def test_quality_collection_failure_preserves_forwarding_and_recovery(self):
        recorders = []
        with patch.object(engine.StreamQuality, 'observe_frame', side_effect=RuntimeError('quality unavailable')) as collect:
            self.run_relay(lambda: True, recorders)
        collect.assert_called_once()
        self.assertFalse((self.root / 'recovery-required').exists())

    def test_quality_snapshot_failure_preserves_forwarding_and_recovery(self):
        recorders = []
        with patch.object(engine.StreamQuality, 'snapshot', side_effect=RuntimeError('quality snapshot unavailable')) as collect:
            self.run_relay(lambda: True, recorders)
        collect.assert_called_once()
        self.assertFalse((self.root / 'recovery-required').exists())

    def test_passive_feedback_preserves_payload_and_authentication_bytes(self):
        from test_stream_quality import feedback
        quality = engine.StreamQuality()
        for index, payload in enumerate((feedback(), feedback() + b'unknown-layout')):
            frame = bytes(Ether(src=self.state['portal_mac'], dst=self.state['own_mac']) /
                          IP(src=net.PORTAL, dst=net.PS5) / UDP(sport=50000, dport=9296) / Raw(payload))
            with patch.object(engine.probe, 'network', net):
                forwarded, observed, direction, changed = engine.outbound(frame, self.state)
            self.assertFalse(changed)
            self.assertEqual(direction, 'out')
            self.assertEqual(forwarded[14:], frame[14:])
            self.assertEqual(observed, payload)
            quality.observe_frame(frame, observed, index)
        self.assertEqual(quality.snapshot(1.1, '65')['unknown_feedback'], 1)
        self.assertFalse(quality.snapshot(1.1, '65')['request_observed'])
        payload, *_ = fixture()
        frame = bytes(Ether(src=self.state['portal_mac'], dst=self.state['own_mac']) /
                      IP(src=net.PORTAL, dst=net.PS5) / UDP(sport=50000, dport=9296) / Raw(payload))
        with patch.object(engine.probe, 'network', net):
            _, observed, _, changed = engine.outbound(frame, self.state)
        self.assertTrue(changed)
        quality.observe_frame(frame, observed, 2, changed)
        self.assertTrue(quality.snapshot(2.1, '65')['request_observed'])

    def test_linux_receive_statistics_is_optional_and_returns_deltas(self):
        import struct
        sock = MagicMock()
        sock.ins.getsockopt.side_effect = [struct.pack('=II', 10, 2), struct.pack('=II', 5, 0), OSError('unsupported')]
        with patch.object(net.sys, 'platform', 'linux'):
            self.assertEqual(net.receive_statistics(sock), (10, 2))
            self.assertEqual(net.receive_statistics(sock), (5, 0))
            self.assertIsNone(net.receive_statistics(sock))
        sock.ins.getsockopt.assert_called_with(263, 6, 8)

    def test_blocked_diagnostic_io_preserves_forwarding_and_bounded_shutdown(self):
        entered, release = threading.Event(), threading.Event()
        recorders = []

        def blocked(_self, _payload):
            entered.set()
            release.wait(5)

        with patch.object(Telemetry, 'write_status', blocked):
            try:
                start = time.monotonic()
                self.run_relay(lambda: entered.wait(2), recorders)
                self.assertLess(time.monotonic() - start, 2)
                self.assertTrue(recorders[0].thread.is_alive())
            finally:
                release.set()
                for recorder in recorders:
                    recorder.thread.join(timeout=2)
        self.assertFalse((self.root / 'recovery-required').exists())

    def run_guardian(self, recorders, timeline):
        engine.atomic_json(self.root / 'restore-state.json', self.state)
        (self.root / 'recovery-required').touch()

        def recorder(runtime):
            value = Telemetry(runtime)
            recorders.append(value)
            return value

        with (
            patch.object(net, 'Lock') as lock,
            patch.object(net, 'Parent'),
            patch.object(net, 'configure'),
            patch.object(net, 'open_socket'),
            patch.object(engine.signal, 'signal'),
            patch.object(engine, 'pipe_reader', side_effect=lambda pipe, messages: messages.put(False)),
            patch.object(engine, 'restore_peer', side_effect=lambda state: timeline.append('repair') or []),
            patch.object(engine, 'Telemetry', side_effect=recorder),
        ):
            lock.return_value.close.side_effect = lambda *args, **kwargs: timeline.append('unlock')
            result = engine.guardian(self.root, 123)
        self.assertEqual(result, 0)
        self.assertFalse((self.root / 'recovery-required').exists())

    def test_blocked_recovery_report_releases_control_state_before_writing(self):
        entered, release = threading.Event(), threading.Event()
        timeline, recorders = [], []

        def blocked(_self, _payload):
            timeline.append('report')
            entered.set()
            release.wait(5)

        with patch.object(Telemetry, 'write_recovery', blocked):
            try:
                self.run_guardian(recorders, timeline)
                self.assertTrue(entered.wait(2))
                self.assertEqual(timeline, ['repair', 'unlock', 'report'])
                self.assertTrue(recorders[0].thread.is_alive())
            finally:
                release.set()
                for recorder in recorders:
                    recorder.thread.join(timeout=2)

    def test_failed_recovery_report_preserves_successful_network_recovery(self):
        recorders, timeline = [], []
        with patch.object(Telemetry, 'write_recovery', side_effect=OSError('diagnostic storage unavailable')):
            self.run_guardian(recorders, timeline)
        self.assertEqual(timeline, ['repair', 'unlock'])
        self.assertEqual(recorders[0].health()['write_errors'], 1)


class ManagedServiceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for module, name in ((api, 'JOBS'), (port, 'RUNTIME'), (port, 'PERSIST'),
                             (port, 'SYSNET'), (port, 'ENGINE_LOCK')):
            value = self.root / name.lower()
            p = patch.object(module, name, value)
            p.start()
            self.addCleanup(p.stop)
            if name != 'ENGINE_LOCK':
                value.mkdir()
        self.settings = port.Settings('br-lan', '10.0.0.250/24', '10.0.0.100', '10.0.0.101')
        self.metadata = {'pid': 123, 'identity': '12345', 'generation': 'current-launch',
                         'started_monotonic': time.monotonic() - 10, 'mode': 'active'}
        port.atomic(port.RUNTIME / 'engine.json', self.metadata)
        port.atomic(port.RUNTIME / 'engine-ready.json', {'pid': 123, 'generation': 'current-launch', 'ready': True})
        for target, name, replacement in (
            (api, 'process_identity', lambda pid: '12345'),
            (port, 'pids', lambda: [123]),
            (port, 'uci_get', lambda key, default='': port.asdict(self.settings).get(key, default)),
            (port, 'command', lambda *args, **kwargs: MagicMock(returncode=0, stdout='')),
            (port, 'baseline_state', lambda: {'valid': True, 'reason': '校验通过'}),
        ):
            p = patch.object(target, name, replacement)
            p.start()
            self.addCleanup(p.stop)

    def job(self, **values):
        job = {'id': 'a' * 32, 'action': 'profile', 'request': {'profile': '100'},
               'state': 'queued', 'pid': 123, 'identity': '12345'}
        job.update(values)
        port.atomic(api.JOBS / 'job.json', job)
        return job

    def test_ready_service_remains_running_when_snapshots_are_stale_or_unreadable(self):
        reports = [None, '[]', '{broken', json.dumps({'state': 'running', 'pid': 123,
                   'time': '2000-01-01T00:00:00+00:00', 'counts': {'forwarded_out': 42}})]
        for report in reports:
            with self.subTest(report=report):
                path = port.RUNTIME / 'status.json'
                if report is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_text(report)
                state = api.status()
                self.assertTrue(state['running'])
                self.assertFalse(state['observability']['status_fresh'])
                self.assertIsNone(state['sample_time'])
                self.assertEqual(state['counts'], {})
                self.assertGreaterEqual(state['uptime_seconds'], 10)

    def test_pid_reuse_cannot_be_overridden_by_fresh_diagnostics(self):
        port.atomic(port.RUNTIME / 'status.json', {'state': 'running', 'pid': 123,
                    'time': datetime.datetime.now(datetime.timezone.utc).isoformat()})
        with patch.object(api, 'process_identity', return_value='reused-pid'):
            self.assertFalse(api.status()['running'])

    def test_readiness_requires_the_current_launch_and_namespace_process(self):
        for ready in ({}, {'pid': 123, 'generation': 'old-launch', 'ready': True},
                      {'pid': 123, 'generation': 'current-launch', 'ready': False},
                      {'pid': 999, 'generation': 'current-launch', 'ready': True}):
            with self.subTest(ready=ready):
                port.atomic(port.RUNTIME / 'engine-ready.json', ready)
                self.assertFalse(api.managed_state()['running'])
        port.atomic(port.RUNTIME / 'engine-ready.json', {'pid': 123, 'generation': 'current-launch', 'ready': True})
        with patch.object(port, 'pids', return_value=[]):
            self.assertFalse(api.managed_state()['running'])

    def test_start_waits_for_operational_readiness_independently_of_diagnostics(self):
        self.job(action='start', request={'autostart': 0})
        with (
            patch.object(api, 'run_child') as child,
            patch.object(api, 'managed_state', side_effect=[{'running': False}, {'running': True}]),
            patch.object(api, 'status', side_effect=OSError('diagnostics unavailable')) as diagnostics,
            patch.object(api, 'cancelled', return_value=False),
            patch.object(api.time, 'sleep'),
        ):
            api.start_managed_service('a' * 32)
        self.assertEqual(child.call_args.args, ('a' * 32, [api.SERVICE, 'start']))
        self.assertIn('deadline', child.call_args.kwargs)
        diagnostics.assert_not_called()

    def test_running_profile_change_recovers_then_restarts_and_preserves_boot_preference(self):
        job = self.job()
        events = []
        with (
            patch.object(port.Settings, 'load', return_value=self.settings),
            patch.object(api, 'stop_service', side_effect=lambda *args: events.append('stop')),
            patch.object(api, 'run_child', side_effect=lambda job_id, argv: events.append(argv[-1])),
            patch.object(api, 'start_managed_service', side_effect=lambda *args: events.append('start')),
            patch.object(api, 'checked') as boot_settings,
        ):
            self.assertEqual(api.worker(job['id']), 0)
        self.assertEqual(events, ['stop', '100', 'start'])
        boot_settings.assert_not_called()
        saved = api.optional(api.JOBS / 'job.json')
        self.assertTrue(saved['restarted'])
        self.assertEqual(saved['applied_profile'], '100')
        self.assertEqual(saved['state'], 'complete')

    def test_stopped_profile_change_saves_without_starting_a_service(self):
        job = self.job()
        with (
            patch.object(port.Settings, 'load', return_value=self.settings),
            patch.object(port, 'command', return_value=MagicMock(returncode=1)),
            patch.object(api, 'run_child') as save,
            patch.object(api, 'stop_service') as stop,
            patch.object(api, 'start_managed_service') as start,
        ):
            self.assertEqual(api.worker(job['id']), 0)
        save.assert_called_once_with(job['id'], [api.CLI, 'profile', '--profile', '100'])
        stop.assert_not_called()
        start.assert_not_called()
        self.assertFalse(api.optional(api.JOBS / 'job.json')['restarted'])

    def test_duplicate_profile_request_preserves_running_service(self):
        job = self.job(request={'profile': '65'})
        with (
            patch.object(port.Settings, 'load', return_value=self.settings),
            patch.object(port, 'command') as command,
            patch.object(api, 'run_child') as child,
            patch.object(api, 'stop_service') as stop,
            patch.object(api, 'start_managed_service') as start,
        ):
            self.assertEqual(api.worker(job['id']), 0)
        command.assert_not_called()
        child.assert_not_called()
        stop.assert_not_called()
        start.assert_not_called()

    def test_failed_new_start_rolls_back_and_reports_the_original_error(self):
        job = self.job()
        events = []

        def start(job_id):
            events.append('start')
            if events.count('start') == 1:
                raise RuntimeError('new profile failed to start')

        with (
            patch.object(port.Settings, 'load', return_value=self.settings),
            patch.object(api, 'stop_service', side_effect=lambda *args: events.append('stop')),
            patch.object(api, 'run_child', side_effect=lambda job_id, argv: events.append(argv[-1])),
            patch.object(api, 'start_managed_service', side_effect=start),
        ):
            self.assertEqual(api.worker(job['id']), 1)
        self.assertEqual(events, ['stop', '100', 'start', 'stop', '65', 'start'])
        saved = api.optional(api.JOBS / 'job.json')
        self.assertTrue(saved['rolled_back'])
        self.assertEqual(saved['applied_profile'], '65')
        self.assertIn('new profile failed', saved['error'])

    def test_failed_rollback_retains_visible_recovery_error(self):
        job = self.job()
        with (
            patch.object(port.Settings, 'load', return_value=self.settings),
            patch.object(api, 'stop_service', side_effect=[None, RuntimeError('recovery pending')]),
            patch.object(api, 'run_child') as save,
            patch.object(api, 'start_managed_service', side_effect=RuntimeError('new start failed')) as start,
        ):
            self.assertEqual(api.worker(job['id']), 1)
        self.assertEqual(save.call_count, 1)
        self.assertEqual(start.call_count, 1)
        saved = api.optional(api.JOBS / 'job.json')
        self.assertEqual(saved['state'], 'failed')
        self.assertEqual(saved['rollback_error'], 'recovery pending')

    def test_cancellation_after_recovery_skips_profile_save_and_restart(self):
        job = self.job()

        def stop(job_id):
            (api.JOBS / ('cancel.' + job_id)).touch()

        with (
            patch.object(port.Settings, 'load', return_value=self.settings),
            patch.object(api, 'stop_service', side_effect=stop),
            patch.object(api, 'run_child') as save,
            patch.object(api, 'start_managed_service') as start,
        ):
            self.assertEqual(api.worker(job['id']), 0)
        save.assert_not_called()
        start.assert_not_called()
        self.assertEqual(api.optional(api.JOBS / 'job.json')['state'], 'cancelled')

    def test_cancellation_after_save_stops_before_restart(self):
        job = self.job()

        def save(job_id, argv):
            (api.JOBS / ('cancel.' + job_id)).touch()

        with (
            patch.object(port.Settings, 'load', return_value=self.settings),
            patch.object(api, 'stop_service') as stop,
            patch.object(api, 'run_child', side_effect=save),
            patch.object(api, 'start_managed_service') as start,
        ):
            self.assertEqual(api.worker(job['id']), 0)
        start.assert_not_called()
        self.assertEqual(stop.call_count, 2)
        self.assertEqual(api.optional(api.JOBS / 'job.json')['state'], 'cancelled')


if __name__ == '__main__':
    unittest.main()
