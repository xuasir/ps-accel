import datetime
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import observability as obs
import portal_luci as api
import portal_observe as observer
import portal_openwrt as port
from telemetry import Telemetry
from test_domains import DEVICES
from test_telemetry import wait_until


class DomainApiTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for module, name in ((port, 'RUNTIME'), (port, 'PERSIST'), (api, 'JOBS')):
            value = self.root / name.lower()
            value.mkdir()
            p = patch.object(module, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.settings = port.Settings('br-lan', '10.0.0.250/24', '10.0.0.100', '10.0.0.101')
        self.enrollment = {'network': self.settings.engine(), 'profile': '65',
                           'ps5_mac': DEVICES['ps5']['mac'], 'portal_mac': DEVICES['portal']['mac']}
        obs.atomic_json(port.PERSIST / 'auto-config.json', self.enrollment)
        self.row = {'device': 'portal', 'domain': 'new.sony.example', 'first_epoch': time.time(),
                    'first_seen': obs.utc(), 'last_seen': obs.utc(), 'counts': {'dns_error': 1},
                    'addresses': [], 'device_mac': DEVICES['portal']['mac']}

    def test_domain_reads_are_separate_from_service_commands_and_job_locks(self):
        obs.atomic_json(port.RUNTIME / 'domains.json', {'time': obs.utc(), 'pid': 123, 'identity': 'live',
                                                     'state': 'observing', 'domains': [self.row]})
        with (patch.object(api, 'alive', return_value=True),
              patch.object(port, 'command', side_effect=AssertionError('unexpected command')),
              patch.object(api, 'control_lock', side_effect=AssertionError('unexpected lock'))):
            result = api.dispatch('domains', {'incident': ''})
        self.assertTrue(result['observer']['fresh'])
        self.assertEqual(result['domains'][0]['domain'], 'new.sony.example')
        self.assertNotIn('device_mac', result['domains'][0])

    def test_failure_marker_is_available_while_management_is_busy(self):
        obs.atomic_json(api.JOBS / 'job.json', {'id': 'a' * 32, 'state': 'running'})
        with (patch.object(api, 'control_lock', side_effect=AssertionError('unexpected management lock')),
              patch.object(port, 'exclusive', side_effect=AssertionError('unexpected relay lock'))):
            result = api.dispatch('incident', {'note': 'Portal 连接失败 8801330f'})
        saved = obs.read_incidents(port.PERSIST)[0]
        self.assertEqual(saved['id'], result['id'])
        self.assertEqual(saved['source'], 'manual')
        self.assertEqual(api.optional(api.JOBS / 'job.json')['state'], 'running')

    def test_logging_preferences_change_without_restarting_the_relay(self):
        obs.atomic_json(port.PERSIST / 'baseline.json', {'receipt': 'retained'})
        with (patch.object(api, 'control_lock', side_effect=AssertionError('unexpected management lock')),
              patch.object(port, 'exclusive', side_effect=AssertionError('unexpected relay lock')),
              patch.object(port, 'command', return_value=MagicMock(returncode=0)) as command):
            result = api.dispatch('logging', {'mode': 'verbose', 'domains': 1, 'tag': 'Portal 4.0'})
        self.assertEqual(result['logging']['mode'], 'verbose')
        command.assert_called_once_with('/etc/init.d/ps-accel-observe', 'start', check=False, timeout=3)
        self.assertEqual(obs.read_bounded(port.PERSIST / 'baseline.json'), {'receipt': 'retained'})

    def test_disabled_capture_keeps_preferences_and_existing_history(self):
        obs.atomic_json(port.PERSIST / 'domains.json', {'domains': [self.row]})
        with patch.object(port, 'command') as command:
            api.dispatch('logging', {'mode': 'compact', 'domains': 0, 'tag': ''})
        command.assert_not_called()
        result = api.domains()
        self.assertEqual(result['observer']['state'], 'disabled')
        self.assertEqual(result['domains'][0]['domain'], 'new.sony.example')

    def test_replaced_device_does_not_inherit_the_previous_devices_inventory(self):
        obs.atomic_json(port.PERSIST / 'domains.json', {'domains': [self.row]})
        updated = dict(self.enrollment, portal_mac='02:00:00:00:00:99')
        obs.atomic_json(port.PERSIST / 'auto-config.json', updated)
        self.assertEqual(api.domains()['domains'], [])

    def test_selected_failure_includes_recent_dns_error_and_continues_filling_the_window(self):
        incident = obs.new_incident('manual', '失败')
        obs.save_incident(port.PERSIST, incident)
        event = {'epoch': incident['epoch'] - 1, 'time': obs.utc(incident['epoch'] - 1),
                 'device': 'portal', 'kind': 'dns_error', 'domains': ['new.sony.example'], 'problem': True, 'rcode': 3}
        obs.atomic_json(port.RUNTIME / 'domains.json', {'time': obs.utc(), 'recent': [event], 'domains': [self.row]})
        result = api.domains(incident['id'])
        self.assertEqual(result['selected']['evidence']['candidates'][0]['domain'], 'new.sony.example')
        self.assertFalse(result['selected']['evidence']['evidence_complete'])
        self.assertEqual(result['selected']['evidence']['events'][0]['rcode'], 3)

    def test_unknown_or_malicious_failure_ids_are_rejected(self):
        for request in ({'incident': '../config'}, {'incident': None}, {'incident': 1}, {'incident': 'a' * 33}):
            with self.assertRaises(ValueError):
                api.validate('domains', request)
        with self.assertRaises(ValueError):
            api.domains('a' * 32)

    def test_log_policy_and_failure_note_validation_keep_the_rpc_boundary_narrow(self):
        for request in ({'mode': 'verbose; reboot', 'domains': 1, 'tag': ''},
                        {'mode': 'compact', 'domains': True, 'tag': ''},
                        {'mode': 'compact', 'domains': 1, 'tag': '\n恶意'},
                        {'mode': 'compact', 'domains': 1, 'tag': 'x' * 65}):
            with self.assertRaises(ValueError):
                api.validate('logging', request)
        for note in ('', '\n', 'x' * 301, None, 123):
            with self.assertRaises(ValueError):
                api.validate('incident', {'note': note})

    def test_observer_failure_is_reported_with_saved_log_preferences(self):
        with patch.object(port, 'command', side_effect=TimeoutError('observer request timeout')):
            result = api.configure_logging({'mode': 'compact', 'domains': 1, 'tag': '已保存'})
            self.assertTrue(result['ok'])
            self.assertIn('启动待确认', result['observer_warning'])
        self.assertEqual(obs.load_preferences(port.PERSIST / 'observability.json').tag, '已保存')
        with patch.object(port, 'command', side_effect=OSError('observer unavailable')):
            result = api.configure_logging({'mode': 'compact', 'domains': 1, 'tag': '已保存'})
        self.assertTrue(result['ok'])
        self.assertIn('启动待确认', result['observer_warning'])

    def test_diagnostics_include_domains_public_addresses_and_redacted_failure_evidence(self):
        incident = obs.new_incident('manual', '10.0.0.101 fe80::1234 02:00:00:00:00:03 连接失败')
        incident['evidence'] = {'events': [{'device': 'portal', 'kind': 'dns_error', 'address': '10.0.0.1',
                                           'domains': ['new.sony.example'], 'public': '1.1.1.1'}]}
        obs.save_incident(port.PERSIST, incident)
        data = api.redact_domain_data({'incidents': obs.read_incidents(port.PERSIST),
                                      'domains': [{'domain': 'new.sony.example', 'address': '1.1.1.1'}]})
        serialized = json.dumps(data, ensure_ascii=False)
        self.assertIn('new.sony.example', serialized)
        self.assertIn('1.1.1.1', serialized)
        for private in ('10.0.0.101', 'fe80::1234', '02:00:00:00:00:03', incident['id']):
            self.assertNotIn(private, serialized)

    def test_corrupted_reports_and_log_lines_keep_domain_reading_available(self):
        (port.RUNTIME / 'domains.json').write_text('{broken')
        (port.RUNTIME / 'domains.jsonl').write_text('{broken\n[]\n')
        obs.atomic_json(port.PERSIST / 'domains.json', {'domains': [self.row]})
        incident = obs.new_incident('manual', '失败')
        obs.save_incident(port.PERSIST, incident)
        result = api.domains(incident['id'])
        self.assertEqual(len(result['domains']), 1)
        self.assertEqual(result['selected']['evidence']['event_count'], 0)

    def test_manual_marker_preserves_errors_when_routine_context_exceeds_the_file_limit(self):
        now = time.time()
        events = [{'epoch': now - 10 + index / 10, 'time': obs.utc(now), 'device': 'portal',
                   'kind': 'dns_query', 'domains': ['long.sony.example'], 'problem': False,
                   'note': '上下文' * 300} for index in range(79)]
        events.append({'epoch': now - 1, 'time': obs.utc(now), 'device': 'portal',
                       'kind': 'dns_error', 'domains': ['new.sony.example'], 'problem': True, 'rcode': 3})
        obs.atomic_json(port.RUNTIME / 'domains.json', {'time': obs.utc(), 'recent': events})
        result = api.mark_incident('连接失败')
        path = port.PERSIST / 'incidents' / (result['id'] + '.json')
        saved = obs.read_bounded(path)
        self.assertLessEqual(path.stat().st_size, obs.MAX_INCIDENT_BYTES)
        self.assertTrue(saved['evidence']['truncated'])
        self.assertTrue(any(item['kind'] == 'dns_error' for item in saved['evidence']['events']))


class ObserverPersistenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for name in ('RUNTIME', 'PERSIST'):
            p = patch.object(port, name, self.root / name.lower())
            p.start()
            self.addCleanup(p.stop)

    def test_independent_observer_persists_completed_failure_evidence(self):
        incident = obs.new_incident('manual', '失败', epoch=time.time() - 20)
        obs.save_incident(port.PERSIST, incident)
        event = {'epoch': incident['epoch'] - 1, 'time': obs.utc(incident['epoch'] - 1), 'device': 'portal',
                 'kind': 'dns_error', 'domains': ['new.sony.example'], 'problem': True}
        recorder = observer.ObserverTelemetry()
        recorder.snapshot({'time': obs.utc(), 'state': 'observing', 'domains': [], '_history': [event],
                           'coverage_start': incident['epoch'] - 200})
        recorder.close(timeout=2)
        saved = obs.read_incidents(port.PERSIST)[0]
        self.assertTrue(saved['captured_at'])
        self.assertEqual(saved['evidence']['candidates'][0]['domain'], 'new.sony.example')
        self.assertFalse(saved['evidence']['coverage_limited'])
        self.assertNotIn('_history', obs.read_bounded(port.RUNTIME / 'domains.json'))

    def test_large_failure_evidence_is_truncated_to_a_valid_bounded_json_file(self):
        incident = obs.new_incident('manual', '失败', epoch=time.time() - 20)
        obs.save_incident(port.PERSIST, incident)
        names = [str(index) + '.' + 'x' * 50 + '.sony.example' for index in range(8)]
        events = [{'epoch': incident['epoch'] + index / 10, 'time': obs.utc(incident['epoch']), 'device': 'portal',
                   'kind': 'dns_error', 'domains': names, 'problem': True, 'note': '中' * 500} for index in range(80)]
        recorder = observer.ObserverTelemetry()
        recorder.snapshot({'time': obs.utc(), 'domains': [], '_history': events})
        recorder.close(timeout=2)
        path = port.PERSIST / 'incidents' / (incident['id'] + '.json')
        self.assertLessEqual(path.stat().st_size, obs.MAX_INCIDENT_BYTES)
        self.assertTrue(obs.read_bounded(path)['evidence']['truncated'])

    def test_enrollment_checks_mac_and_network_before_opening_capture(self):
        settings = port.Settings('br-lan', '10.0.0.250/24', '10.0.0.100', '10.0.0.101')
        enrollment = {'network': settings.engine(), 'ps5_mac': DEVICES['ps5']['mac'],
                      'portal_mac': DEVICES['portal']['mac']}
        obs.atomic_json(port.PERSIST / 'auto-config.json', enrollment)
        with patch.object(port.Settings, 'load', return_value=settings):
            bridge, devices = observer.enrolled_devices()
            self.assertEqual(bridge, 'br-lan')
            self.assertEqual(devices, DEVICES)
            enrollment['portal_mac'] = '02:00:00:00:00:03; reboot'
            obs.atomic_json(port.PERSIST / 'auto-config.json', enrollment)
            with self.assertRaises(ValueError):
                observer.enrolled_devices()

    def test_observer_restart_preserves_evidence_saved_with_the_failure_marker(self):
        incident = obs.new_incident('manual', '失败', epoch=time.time() - 20)
        event = {'epoch': incident['epoch'] - 1, 'time': obs.utc(incident['epoch'] - 1), 'device': 'portal',
                 'kind': 'dns_error', 'domains': ['before-restart.sony.example'], 'problem': True}
        incident['evidence'] = {'events': [event]}
        obs.save_incident(port.PERSIST, incident)
        recorder = observer.ObserverTelemetry()
        recorder.snapshot({'time': obs.utc(), 'state': 'disabled', 'domains': []})
        recorder.close(timeout=2)
        saved = obs.read_incidents(port.PERSIST)[0]
        self.assertEqual(saved['evidence']['candidates'][0]['domain'], 'before-restart.sony.example')
        self.assertTrue(saved['evidence']['coverage_limited'])

    def test_maximum_domain_inventory_remains_readable_with_long_names_and_ipv6_addresses(self):
        address = '2001:4860:1234:5678:abcd:ef01:2345:6789'
        rows = [{'device': 'portal', 'domain': str(index) + '.' + '.'.join(['x' * 60] * 4),
                 'first_epoch': time.time(), 'last_epoch': time.time(), 'first_seen': obs.utc(), 'last_seen': obs.utc(),
                 'counts': {key: 1000000000000 for key in ('dns_query', 'dns_ok', 'dns_empty', 'dns_error',
                                                       'dns_timeout', 'tcp_ok', 'tcp_reset', 'tcp_timeout', 'tls_sni', 'unreachable')},
                 'addresses': [{'address': address, 'ttl': 86400, 'expires_at': obs.utc()} for _ in range(8)],
                 'last_problem': 'tcp_timeout', 'new_since_tag': True} for index in range(512)]
        recent = [{'epoch': time.time(), 'time': obs.utc(), 'device': 'portal', 'kind': 'dns_ok',
                   'domains': [row['domain'] for row in rows[:8]], 'addresses': rows[0]['addresses'],
                   'tag': '中' * 64} for _ in range(80)]
        recorder = observer.ObserverTelemetry()
        recorder.snapshot({'time': obs.utc(), 'state': 'observing', 'domains': rows, 'recent': recent})
        recorder.close(timeout=2)
        report = obs.read_bounded(port.RUNTIME / 'domains.json')
        self.assertEqual(len(report['domains']), 512)
        self.assertLessEqual((port.RUNTIME / 'domains.json').stat().st_size, 1048576)


if __name__ == '__main__':
    unittest.main()
