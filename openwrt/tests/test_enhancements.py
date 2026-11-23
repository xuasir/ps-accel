import base64
from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal_active_probe as probe
import portal_auto as engine
import portal_luci as api
import portal_openwrt as port
from profiles import PROFILES, PROFILE_INFO, public_profiles
from test_probe import fixture


class EnhancementTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for name in ('RUNTIME', 'PERSIST', 'SYSNET', 'HANDLE', 'ENGINE_LOCK'):
            replacement = self.root / name.lower()
            p = patch.object(port, name, replacement)
            p.start()
            self.addCleanup(p.stop)
        port.RUNTIME.mkdir()
        port.PERSIST.mkdir()
        self.settings = port.Settings('br-lan', '10.0.0.250/24', '10.0.0.100', '10.0.0.101')
        self.config = {'network': self.settings.engine(), 'profile': '65',
                       'ps5_mac': '02:00:00:00:00:02', 'portal_mac': '02:00:00:00:00:03'}
        port.atomic(port.PERSIST / 'auto-config.json', self.config)

    def save_baseline(self, **upstream_changes):
        upstream = {'fingerprint': engine.fingerprint(self.config), 'forwarded_out': 3, 'restored': True}
        upstream.update(upstream_changes)
        port.atomic(port.PERSIST / 'baseline.json', {
            'port_fingerprint': port.port_fingerprint(self.settings), 'upstream': upstream})

    def test_all_fixed_profiles_decode_to_their_actual_requests(self):
        for name, delta in PROFILES.items():
            with self.subTest(profile=name):
                data, plain, stream, position = fixture()
                with patch.object(probe, 'PATCH_DELTA', delta):
                    modified, changed = probe.mutate(data)
                self.assertTrue(changed)
                self.assertEqual(len(modified), len(data))
                cipher = base64.b64decode(modified[position:position + 800])
                decoded = bytes(a ^ b for a, b in zip(cipher, stream))
                self.assertEqual(decoded[334:339], PROFILE_INFO[name]['request'])
                self.assertEqual(decoded[:334], plain[:334])
                self.assertEqual(decoded[339:], plain[339:len(decoded)])
        json.dumps(public_profiles())

    def test_profile_switch_preserves_transport_receipt(self):
        self.save_baseline()
        with patch.object(port.Settings, 'load', return_value=self.settings), patch.object(port, 'command') as cmd:
            port.set_profile('100')
        updated = port.Settings(**dict(port.asdict(self.settings), profile='100'))
        self.assertEqual(port.read_json(port.PERSIST / 'auto-config.json')['profile'], '100')
        self.assertTrue(port.baseline_state(updated)['valid'])
        self.assertEqual(cmd.call_args_list[0].args, ('uci', 'set', 'ps_accel.main.profile=100'))
        self.assertFalse((port.RUNTIME / 'auto-baseline.json').exists())

    def test_profile_switch_rolls_back_when_uci_commit_fails(self):
        failure = subprocess.CalledProcessError(1, ['uci', 'commit'])
        with patch.object(port.Settings, 'load', return_value=self.settings):
            with patch.object(port, 'command', side_effect=[None, failure, None, None]) as cmd:
                with self.assertRaises(subprocess.CalledProcessError):
                    port.set_profile('45')
        self.assertEqual(port.read_json(port.PERSIST / 'auto-config.json'), self.config)
        self.assertEqual(cmd.call_args_list[2].args, ('uci', 'set', 'ps_accel.main.profile=65'))

    def test_profile_switch_waits_for_complete_recovery(self):
        for blocker in (port.ENGINE_LOCK, port.HANDLE, port.RUNTIME / 'recovery-required'):
            blocker.touch()
            with patch.object(port, 'command') as command:
                with self.assertRaisesRegex(RuntimeError, '停止中继'):
                    port.set_profile('100')
                command.assert_not_called()
            blocker.unlink()

    def test_receipt_rejects_invalid_traffic_and_restore_evidence(self):
        for changes in ({'forwarded_out': 0}, {'forwarded_out': '3'}, {'restored': False}, {'fingerprint': 'stale'}):
            self.save_baseline(**changes)
            self.assertFalse(port.baseline_state(self.settings)['valid'])

    def test_bridge_and_peer_changes_invalidate_the_receipt(self):
        self.save_baseline()
        other = port.Settings(**dict(port.asdict(self.settings), bridge='br-other'))
        self.assertFalse(port.baseline_state(other)['valid'])
        port.atomic(port.PERSIST / 'auto-config.json', dict(self.config, ps5_mac='02:00:00:00:00:99'))
        self.assertFalse(port.baseline_state(self.settings)['valid'])

    def test_stop_waits_for_controller_and_guardian_before_repair(self):
        events = []
        attempts = iter([True, False, False])
        @contextmanager
        def exclusive():
            if next(attempts):
                raise port.ControllerBusy('controller is finishing')
            yield
        with patch.object(port, 'command', side_effect=lambda *args: events.append('stop')):
            with patch.object(port, 'exclusive', side_effect=exclusive), patch.object(port, 'pids', side_effect=[[123], []]):
                with patch.object(port.time, 'sleep'), patch.object(port, 'repair_existing', side_effect=lambda: events.append('repair')):
                    port.stop_and_repair()
        self.assertEqual(events, ['stop', 'repair'])

    def test_stop_timeout_retains_resources(self):
        port.HANDLE.touch()
        with patch.object(port, 'command'), patch.object(port, 'pids', return_value=[123]):
            with patch.object(port.time, 'monotonic', side_effect=[0, 0, 2]), patch.object(port.time, 'sleep'):
                with patch.object(port, 'repair_existing') as repair:
                    with self.assertRaisesRegex(RuntimeError, '恢复路径已保留'):
                        port.stop_and_repair(timeout=1)
                    repair.assert_not_called()
        self.assertTrue(port.HANDLE.exists())

    def test_boot_wait_observes_an_up_bridge(self):
        bridge = port.SYSNET / 'br-lan'
        (bridge / 'bridge').mkdir(parents=True)
        (bridge / 'flags').write_text('0x1003')
        with patch.object(port, 'command') as command:
            port.wait_for_bridge(self.settings)
            command.assert_not_called()

    def test_boot_wait_has_a_deadline_and_does_not_create_a_bridge(self):
        with patch.object(port.time, 'monotonic', side_effect=[0, 0, 2]), patch.object(port.time, 'sleep'):
            with patch.object(port, 'command') as command:
                with self.assertRaisesRegex(RuntimeError, '就绪超时'):
                    port.wait_for_bridge(self.settings, timeout=1)
                command.assert_not_called()

    def test_restore_reports_socket_close_failures(self):
        state = {'config': self.settings.engine(), 'own_mac': '02:00:00:00:00:01',
                 'ps5_mac': self.config['ps5_mac'], 'portal_mac': self.config['portal_mac']}
        socket = MagicMock()
        socket.close.side_effect = OSError('socket close failed')
        with patch.object(engine.net, 'configure'), patch.object(engine.net, 'open_socket', return_value=socket):
            with patch.object(engine.net, 'send'), patch.object(engine.time, 'sleep'):
                errors = engine.restore_peer(state)
        self.assertEqual(len(errors), 1)
        self.assertIn('socket close failed', errors[0])

    def test_profile_rpc_rejects_command_injection_and_types(self):
        for value in ('100; reboot', '999', 65, True, None):
            with self.assertRaises(ValueError):
                api.validate('profile', {'profile': value})
        self.assertEqual(api.validate('profile', {'profile': '35'}), {'profile': '35'})

    def test_diagnostics_excludes_addresses_raw_logs_and_session_ids(self):
        current = {'environment': {'model': 'FastRhino R66S'}, 'config': port.asdict(self.settings),
                   'configured': True, 'running': False, 'mode': 'active', 'modified': 7, 'control_mbps': 0,
                   'uptime_seconds': 0, 'foreign_relay': False, 'counts': {'forwarded_out': 42},
                   'baseline_valid': True, 'baseline_reason': '校验通过', 'recovery_required': False,
                   'recovery_errors': ['10.0.0.101 02:00:00:00:00:03 unreachable'],
                   'job': {'action': 'doctor', 'state': 'failed', 'error': '10.0.0.100 failed'},
                   'log': 'private-session-id', 'events': 'private-session-id'}
        with patch.object(api, 'status', return_value=current):
            serialized = json.dumps(api.diagnostics(), ensure_ascii=False)
        for private in ('10.0.0.100', '10.0.0.101', '10.0.0.250', '02:00:00:00:00:03', 'private-session-id'):
            self.assertNotIn(private, serialized)
        self.assertIn('FastRhino R66S', serialized)

    def test_diagnostics_rpc_stays_read_only(self):
        with patch.object(api, 'diagnostics', return_value={'ok': True}) as export:
            with patch.object(api.subprocess, 'Popen') as spawn:
                self.assertTrue(api.dispatch('diagnostics', {})['ok'])
                export.assert_called_once()
                spawn.assert_not_called()


if __name__ == '__main__':
    unittest.main()
