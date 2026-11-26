import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal_luci as api
import portal_observe as observer
import portal_openwrt as port
import portal_policy as policy


class SharedDeviceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        locations = [(port, 'PERSIST', root / 'etc'), (port, 'RUNTIME', root / 'run'),
                     (port, 'SYSNET', root / 'net'), (port, 'CONFIG_FILE', root / 'config'),
                     (port, 'ENGINE_LOCK', root / 'engine.lock'), (port, 'HANDLE', root / 'namespace'),
                     (api, 'JOBS', root / 'jobs')]
        for module, name, value in locations:
            replacement = patch.object(module, name, value)
            replacement.start()
            self.addCleanup(replacement.stop)
        (port.SYSNET / 'br-lan' / 'bridge').mkdir(parents=True)
        port.CONFIG_FILE.write_text('original configuration\n')
        self.config = dict(bridge='br-lan', portal_ip='10.0.0.101', ps5_ip='10.0.0.100')
        self.values = dict(self.config, address='', profile='65', enabled='0')
        self.inventory = [
            dict(mac='02:00:00:00:00:01', label='Portal', addresses=['10.0.0.101'], source='dhcp'),
            dict(mac='02:00:00:00:00:02', label='PS5', addresses=['10.0.0.100'], source='dhcp')]
        self.commands = []

        def command(*args, **kwargs):
            self.commands.append(args)
            if args[:3] == ('ip', '-j', 'addr'):
                return MagicMock(returncode=0, stdout=json.dumps([{'addr_info': [
                    {'family': 'inet', 'local': '10.0.0.1', 'prefixlen': 24}]}]))
            return MagicMock(returncode=0, stdout='')
        for replacement in (patch.object(port, 'command', side_effect=command),
                            patch.object(port, 'uci_values', side_effect=lambda: dict(self.values)),
                            patch.object(policy, 'inventory', side_effect=lambda: self.inventory)):
            replacement.start()
            self.addCleanup(replacement.stop)

    def binding(self, **changes):
        return dict(config=self.config, portal_mac=self.inventory[0]['mac'],
                    ps5_mac=self.inventory[1]['mac'], confirmed_at=100, **changes)

    def test_device_confirmation_works_before_relay_configuration_and_starts_observation(self):
        with patch.object(port, 'setup', side_effect=AssertionError('relay namespace created')):
            api.save_devices(self.config)
        binding = port.device_binding(self.values)
        self.assertEqual(binding['portal_mac'], self.inventory[0]['mac'])
        self.assertEqual(binding['ps5_mac'], self.inventory[1]['mac'])
        self.assertEqual(binding['config'], self.config)
        self.assertFalse((port.PERSIST / 'auto-config.json').exists())
        self.assertFalse(any(args[:2] == ('ip', 'netns') for args in self.commands))
        self.assertIn(('/etc/init.d/ps-accel-observe', 'start'), self.commands)
        self.assertFalse(any('address=' in arg or 'profile=' in arg for args in self.commands for arg in args))

    def test_saved_devices_feed_the_passive_observer_without_a_relay_address(self):
        port.atomic(port.PERSIST / 'devices.json', self.binding())
        with patch.object(port.Settings, 'load', side_effect=AssertionError('bitrate settings requested')):
            bridge, devices = observer.enrolled_devices()
        self.assertEqual(bridge, 'br-lan')
        self.assertEqual(devices['portal'], {'ip': '10.0.0.101', 'mac': self.inventory[0]['mac']})

    def test_device_reads_report_shared_identity_and_inventory_before_bitrate_enrollment(self):
        port.atomic(port.PERSIST / 'devices.json', self.binding())
        result = api.dispatch('devices', {})
        self.assertTrue(result['configured'])
        self.assertFalse(result['proxy_enabled'])
        self.assertEqual(result['devices'], self.inventory)

    def test_a_changed_mac_invalidates_old_relay_enrollment_and_baseline(self):
        old = self.binding()
        old['portal_mac'] = '02:00:00:00:00:99'
        port.atomic(port.PERSIST / 'devices.json', old)
        port.atomic(port.PERSIST / 'auto-config.json', {
            'network': {'interface': port.IFACE, 'portal_ip': self.config['portal_ip'], 'ps5_ip': self.config['ps5_ip']},
            'portal_mac': old['portal_mac'], 'ps5_mac': old['ps5_mac']})
        port.atomic(port.PERSIST / 'baseline.json', {'receipt': 'old'})
        api.save_devices(self.config)
        self.assertFalse((port.PERSIST / 'auto-config.json').exists())
        self.assertFalse((port.PERSIST / 'baseline.json').exists())

    def test_confirming_the_same_devices_retains_valid_relay_enrollment(self):
        port.atomic(port.PERSIST / 'auto-config.json', {
            'network': {'interface': port.IFACE, 'portal_ip': self.config['portal_ip'], 'ps5_ip': self.config['ps5_ip']},
            'portal_mac': self.inventory[0]['mac'], 'ps5_mac': self.inventory[1]['mac']})
        port.atomic(port.PERSIST / 'baseline.json', {'receipt': 'retained'})
        api.save_devices(self.config)
        self.assertTrue((port.PERSIST / 'auto-config.json').exists())
        self.assertEqual(port.read_json(port.PERSIST / 'baseline.json'), {'receipt': 'retained'})

    def test_ambiguous_or_same_device_addresses_fail_before_uci_changes(self):
        self.inventory.append(dict(mac='02:00:00:00:00:03', label='duplicate',
                                   addresses=['10.0.0.101'], source='neighbour'))
        with self.assertRaisesRegex(ValueError, 'MAC 待确认'):
            api.save_devices(self.config)
        self.assertFalse(any(args[0] == 'uci' for args in self.commands))

    def test_two_addresses_owned_by_one_mac_fail_before_persistence(self):
        self.inventory = [dict(mac='02:00:00:00:00:01', label='same',
                               addresses=['10.0.0.101', '10.0.0.100'], source='dhcp')]
        with self.assertRaisesRegex(ValueError, '同一设备'):
            api.save_devices(self.config)
        self.assertFalse((port.PERSIST / 'devices.json').exists())

    def test_router_address_and_addresses_outside_the_lan_fail_before_persistence(self):
        for address in ('10.0.0.1', '10.0.0.0', '10.0.0.255', '8.8.8.8'):
            with self.subTest(address=address), self.assertRaisesRegex(ValueError, 'LAN 网桥'):
                api.save_devices(dict(self.config, portal_ip=address))
        self.assertFalse((port.PERSIST / 'devices.json').exists())

    def test_running_relay_and_proxy_require_their_stop_paths_before_device_changes(self):
        port.ENGINE_LOCK.write_text('owned')
        with self.assertRaisesRegex(RuntimeError, '停止码率增强'):
            api.save_devices(self.config)
        port.ENGINE_LOCK.unlink()
        port.atomic(policy.folder() / 'manifest.json', {'enabled': True})
        with self.assertRaisesRegex(RuntimeError, '停用透明代理'):
            api.save_devices(self.config)
        self.assertEqual(self.commands, [])

    def test_missing_devices_are_probed_on_the_selected_bridge_and_still_require_identity(self):
        self.inventory = []
        with self.assertRaisesRegex(ValueError, 'MAC 待确认'):
            api.save_devices(self.config)
        probes = [args for args in self.commands if args[0] == 'ping']
        self.assertEqual(probes, [('ping', '-I', 'br-lan', '-c', '1', '-W', '1', '10.0.0.101'),
                                  ('ping', '-I', 'br-lan', '-c', '1', '-W', '1', '10.0.0.100')])

    def test_persistence_failure_restores_device_file_and_previous_configuration(self):
        old = self.binding()
        old['portal_mac'] = '02:00:00:00:00:99'
        port.atomic(port.PERSIST / 'devices.json', old)
        before = (port.PERSIST / 'devices.json').read_bytes()
        atomic = port.atomic
        def fail(path, value):
            if path == port.PERSIST / 'devices.json':
                port.CONFIG_FILE.write_text('changed configuration')
                raise OSError('device storage unavailable')
            return atomic(path, value)
        with patch.object(port, 'atomic', side_effect=fail):
            with self.assertRaisesRegex(OSError, 'storage unavailable'):
                api.save_devices(self.config)
        self.assertEqual(port.CONFIG_FILE.read_text(), 'original configuration\n')
        self.assertEqual((port.PERSIST / 'devices.json').read_bytes(), before)
        self.assertIn(('uci', 'revert', 'ps_accel'), self.commands)

    def test_device_parameters_reject_commands_and_duplicate_ips_before_job_launch(self):
        for change in ({'bridge':'br-lan; reboot'}, {'portal_ip':'10.0.0.100'},
                       {'portal_ip':'::1'}, {'portal_ip':'127.0.0.1'}, {'ps5_ip':None}):
            with self.subTest(change=change), patch.object(api.subprocess, 'Popen') as spawn:
                with self.assertRaises(ValueError):
                    api.dispatch('device_save', dict(self.config, **change))
                spawn.assert_not_called()

    def test_device_revision_and_saved_binding_change_without_relay_enrollment(self):
        revision = port.configuration_revision()
        port.atomic(port.PERSIST / 'devices.json', self.binding())
        self.assertNotEqual(revision, port.configuration_revision())
        self.values['portal_ip'] = '10.0.0.111'
        self.assertEqual(port.device_binding(self.values), {})

    def test_feature_job_logs_keep_previous_outputs_and_the_legacy_current_log(self):
        with (patch.object(api, 'process_identity', return_value='live'),
              patch.object(api, 'alive', return_value=False),
              patch.object(api.subprocess, 'Popen', return_value=MagicMock(pid=4242))):
            api.dispatch('device_save', self.config)
            (api.JOBS / 'devices.log').write_text('devices confirmed\n')
            api.dispatch('doctor', {})
            (api.JOBS / 'bitrate.log').write_text('bitrate environment checked\n')
        self.assertEqual(api.logs('devices')['text'], 'devices confirmed\n')
        self.assertEqual(api.logs('bitrate')['text'], 'bitrate environment checked\n')
        self.assertEqual(api.logs('log')['text'], 'bitrate environment checked\n')
        with self.assertRaises(ValueError):
            api.validate('logs', {'kind':'../secret'})


    def test_feature_results_survive_a_later_task_in_another_feature(self):
        port.atomic(api.JOBS / 'job.json', {'id': 'device', 'action': 'device_save', 'state': 'queued'})
        api.update_job('device', state='complete')
        port.atomic(api.JOBS / 'job.json', {'id': 'bitrate', 'action': 'configure', 'state': 'queued'})
        api.update_job('bitrate', state='failed', error='relay address unavailable')
        current = {'id': 'proxy', 'action': 'psportal_apply', 'state': 'running', 'busy': True}
        results = api.feature_jobs(current)
        self.assertEqual(results['devices']['state'], 'complete')
        self.assertEqual(results['bitrate']['error'], 'relay address unavailable')
        self.assertTrue(results['proxy']['busy'])

    def test_proxy_diagnostic_export_contains_its_config_and_redacts_shared_identity(self):
        data = {'ok': True, 'enabled': True, 'config': {'portal': '02:00:00:00:00:01',
                'ps5': '02:00:00:00:00:02', 'domains': 'auth.sony.example', 'ports': '443', 'node': 'nodeA'},
                'active_config': {'domains': 'auth.sony.example'}, 'sources': {'portal': ['10.0.0.101']},
                'nodes': [{'password': 'unrelated-node-data'}]}
        report = {'ok': True, 'domains': [{'device': 'portal', 'domain': 'auth.sony.example',
                  'addresses': [{'address': '1.1.1.1'}]}], 'incidents': [], 'observer': {'state': 'observing'}}
        with patch.object(api.rules, 'status', return_value=data), patch.object(api, 'domains', return_value=report):
            result = api.dispatch('proxy_diagnostics', {})
        self.assertTrue(result['proxy']['enabled'])
        serialized = json.dumps(result)
        self.assertIn('auth.sony.example', serialized)
        self.assertIn('1.1.1.1', serialized)
        for value in ('10.0.0.101', '02:00:00:00:00:01', 'unrelated-node-data'):
            self.assertNotIn(value, serialized)

    def test_saved_shared_devices_scope_the_persistent_domain_inventory_before_relay_enrollment(self):
        port.atomic(port.PERSIST / 'devices.json', self.binding())
        port.atomic(port.PERSIST / 'domains.json', {'domains': [
            {'device':'portal', 'domain':'auth.sony.example', 'device_mac':self.inventory[0]['mac'],
             'counts':{}, 'addresses':[]},
            {'device':'portal', 'domain':'previous.sony.example', 'device_mac':'02:00:00:00:00:99',
             'counts':{}, 'addresses':[]}]})
        result = api.domains()
        self.assertEqual([row['domain'] for row in result['domains']], ['auth.sony.example'])


if __name__ == '__main__':
    unittest.main()
