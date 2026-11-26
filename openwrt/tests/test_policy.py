"""Policy transaction, identity changes and RPC boundary regressions."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE))
import portal_policy as policy
import portal_openwrt as port
import portal_luci as api


class PolicyTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.generator = self.root / 'util_sing-box.lua'
        self.stock = 'local original = true\nif arg[1] then\nend\n'
        self.generator.write_text(self.stock)
        self.request = dict(portal='02:00:00:00:00:01', ps5='02:00:00:00:00:02', node='nodeA',
                            domains='auth.api.playstation.com', ports='443', exclusions='dwc.dl.playstation.net')
        self.devices = [dict(mac=self.request['portal'], addresses=['10.0.0.101', '2001:db8::101']),
                        dict(mac=self.request['ps5'], addresses=['10.0.0.100'])]
        core = {'inbounds': [{'type': 'redirect', 'tag': 'redirect_tcp'}],
                'outbounds': [{'type': 'direct', 'tag': 'direct'}],
                'route': {'rules': [], 'final': 'direct'}}
        self.env = dict(versions={'singbox': '1.14.4'}, nodes=[dict(id='nodeA', label='测试', protocol='socks')],
                        devices=deepcopy(self.devices), errors=[], compatible=True, hooked=False,
                        code_hash=hashlib.sha256(self.stock.encode()).hexdigest(), enabled=True,
                        adapter_hash='adapter-v1', uci_hash='uci-v1',
                        configs=[dict(path='unused', config=core, fingerprint=policy.digest(core))])
        for obj, name, value in [(port, 'PERSIST', self.root / 'persist'), (port, 'RUNTIME', self.root / 'runtime'),
                                 (policy, 'PASSWALL', self.generator),
                                 (policy, 'STOCK_SHA256', self.env['code_hash'])]:
            p = patch.object(obj, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.snapshot_patch = patch.object(policy, 'snapshot', side_effect=lambda: deepcopy(self.env))
        self.snapshot_patch.start()
        self.addCleanup(self.snapshot_patch.stop)
        self.validation = patch.object(policy, 'validate_configs', return_value={'checked_cores': 1, 'protection_rules': 0})
        self.validate = self.validation.start()
        self.addCleanup(self.validation.stop)
        commands = patch.object(port, 'command', return_value=subprocess.CompletedProcess([], 0, '', ''))
        self.commands = commands.start()
        self.addCleanup(commands.stop)

    def apply_request(self, **changes):
        values = dict(self.request, **changes)
        plan = policy.preview(values, validate_runtime=False)
        return dict(values, token=plan['token'], confirm_restart=1)

    def attached_core(self):
        core = deepcopy(self.env['configs'][0]['config'])
        core['route']['rule_set'] = [{'tag': policy.TAG}]
        manifest = policy.read(policy.folder() / 'manifest.json')
        spec = manifest.get('diagnostics', {}).get('cores', {}).get(policy.core_key(core)) or \
            policy.diagnostics_plan(self.env['configs'], {}).get(policy.core_key(core))
        if spec:
            core['inbounds'] = [x for x in core['inbounds'] if x.get('tag') != policy.PROBE_TAG]
            core['inbounds'].append(dict(type='mixed', tag=policy.PROBE_TAG, listen='127.0.0.1', listen_port=spec['probe_port']))
            core['experimental'] = {'clash_api': {'external_controller': '127.0.0.1:' + str(spec['api_port']),
                                                'secret': manifest.get('diagnostics', {}).get('secret', 'a' * 48)}}
        return {'config': core}

    def active(self):
        manifest = dict(version=1, enabled=True, owned=True, config=self.request,
                        rules_path=str(policy.folder() / 'rules.json'),
                        direct_rules_path=str(policy.folder() / 'direct-rules.json'),
                        diagnostics=dict(secret='a' * 48, cores=policy.diagnostics_plan(self.env['configs'], {})))
        port.atomic(policy.folder() / 'manifest.json', manifest)
        port.atomic(policy.folder() / 'draft.json', self.request)
        port.atomic(policy.folder() / 'rules.json', policy.rule_set(self.request, dict(portal=['10.0.0.101'], ps5=['10.0.0.100'])))
        port.atomic(policy.folder() / 'direct-rules.json', policy.direct_rule_set(self.request, dict(portal=['10.0.0.101'], ps5=['10.0.0.100'])))
        self.env['hooked'] = True
        self.env['configs'][0]['config'] = self.attached_core()['config']
        self.generator.write_text(self.stock.replace(policy.ANCHOR, policy.HOOK + policy.ANCHOR))

    def test_full_hosts_and_ports_are_canonical_and_bounded(self):
        data = policy.normalize(dict(self.request, domains='full:AUTH.api.playstation.com\n# note\nauth.api.playstation.com',
                                     ports='8443,443,443'))
        self.assertEqual(data['domains'], 'auth.api.playstation.com')
        self.assertEqual(data['ports'], '443,8443')
        wildcard = policy.normalize(dict(self.request, domains='*.PLAYSTATION.com\n*.playstation.com'))
        self.assertEqual(wildcard['domains'], '*.playstation.com')
        for invalid in ('*', 'gsconnect.*', '*signaling*', 'full:*.playstation.com', '*.203.0.113.1',
                        '*.*.playstation.com', 'domain:playstation.com', 'https://auth.api.playstation.com',
                        '203.0.113.1', 'x..example.com', 'a' * 64 + '.example.com'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                policy.normalize(dict(self.request, domains=invalid))
        for invalid in ('443;id', '1:65535', '0', '65536', '', '443,'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                policy.normalize(dict(self.request, ports=invalid))

    def test_uci_node_and_source_are_single_identifiers(self):
        for key, invalid in [('node', '../../secret'), ('portal', '10.0.0.0/24'),
                             ('portal', '01:00:00:00:00:01'), ('portal', '::1'), ('portal', 'fe80::1')]:
            with self.subTest(key=key, invalid=invalid), self.assertRaises(ValueError):
                policy.normalize(dict(self.request, **{key: invalid}))
        with self.assertRaises(ValueError):
            policy.normalize(dict(self.request, portal=self.request['ps5']))

    def test_ip_selection_tracks_its_existing_mac_and_ipv6(self):
        sources, canonical = policy.resolve(dict(self.request, portal='10.0.0.101'), self.devices)
        self.assertEqual(canonical['portal'], self.request['portal'])
        self.assertEqual(sources['portal'], ['10.0.0.101', '2001:db8::101'])
        with self.assertRaisesRegex(ValueError, '同一 MAC'):
            policy.resolve(dict(self.request, ps5='2001:db8::101'), self.devices)

    def test_ambiguous_reassigned_address_falls_back_to_existing_policy(self):
        other = dict(mac='02:00:00:00:00:03', addresses=['10.0.0.100'])
        sources, _ = policy.resolve(self.request, self.devices + [other])
        self.assertEqual(sources['ps5'], [])
        self.env['devices'].append(other)
        self.assertFalse(policy.preview(self.request)['can_apply'])

    def test_inventory_prefers_current_lease_to_a_stale_neighbour(self):
        leases = self.root / 'leases'
        leases.write_text('0 02:00:00:00:00:03 10.0.0.101 laptop *\n')
        neighbours = [dict(lladdr=self.request['portal'], dst='10.0.0.101', state=['STALE']),
                      dict(lladdr=self.request['portal'], dst='2001:db8::101', state=['REACHABLE']),
                      dict(lladdr=self.request['ps5'], dst='10.0.0.100', state='FAILED')]
        result = subprocess.CompletedProcess([], 0, json.dumps(neighbours), '')
        with patch.object(policy, 'LEASES', leases), patch.object(port, 'command', return_value=result):
            devices = {x['mac']: x for x in policy.inventory()}
        self.assertEqual(devices[self.request['portal']]['addresses'], ['2001:db8::101'])
        self.assertEqual(devices['02:00:00:00:00:03']['addresses'], ['10.0.0.101'])
        self.assertNotIn(self.request['ps5'], devices)

    def test_rules_require_source_host_tcp_port_and_exclusion_together(self):
        result = policy.rule_set(self.request, dict(portal=['10.0.0.101', '2001:db8::101'], ps5=['10.0.0.100']))
        self.assertEqual(result, {'version': 3, 'rules': [{'type': 'logical', 'mode': 'and', 'rules': [
            {'source_ip_cidr': ['10.0.0.100/32', '10.0.0.101/32', '2001:db8::101/128']},
            {'domain': ['auth.api.playstation.com'],
             'domain_suffix': ['.auth.np.ac.playstation.net', '.np.communication.playstation.net',
                               '.gsconnect.playstation.net', '.remoteplay.playstation.net'],
             'domain_regex': [r'^gsconnect\.'], 'domain_keyword': ['signaling']},
            {'network': 'tcp', 'port': [443]},
            {'domain': ['dwc.dl.playstation.net'], 'invert': True}]}]})
        self.assertEqual(policy.rule_set(self.request, dict(portal=[], ps5=[])), {'version': 3, 'rules': []})

    def test_preview_of_missing_devices_or_nodes_blocks_changes(self):
        self.env['devices'] = []
        self.env['nodes'] = []
        result = policy.preview(self.request)
        self.assertFalse(result['can_apply'])
        self.assertEqual(len(result['blockers']), 3)
        self.validate.assert_not_called()
        self.assertFalse(policy.folder().exists())

    def test_preview_keeps_dynamic_coverage_when_the_manual_host_is_excluded(self):
        plan = policy.preview(dict(self.request, exclusions=self.request['domains']))
        self.assertTrue(plan['can_apply'])
        self.assertTrue(plan['rules'][0]['excluded'])
        self.assertTrue(any(rule['builtin'] and not rule['excluded'] for rule in plan['rules']))

    def test_preview_validates_without_writing_persistent_settings(self):
        plan = policy.preview(self.request)
        self.assertTrue(plan['can_apply'])
        self.assertTrue(plan['restart_required'])
        self.validate.assert_called_once()
        self.assertFalse(policy.folder().exists())

    def test_known_passwall_port_bypasses_block_application(self):
        self.env['routing'] = dict(client_proxy=True, acl_enabled=False, tcp_ports='80,443,8443',
                                   bypass_ports='443', tcp_mode='proxy', ipv6=True, chn_list='0')
        self.assertFalse(policy.preview(self.request)['can_apply'])
        self.env['routing']['bypass_ports'] = 'disable'
        self.assertFalse(policy.preview(dict(self.request, ports='5223'))['can_apply'])
        self.assertTrue(policy.preview(self.request)['can_apply'])

    def test_client_bypass_and_ipv6_scope_are_visible(self):
        self.env['routing'] = dict(client_proxy=False, acl_enabled=False, tcp_ports='1:65535',
                                   bypass_ports='disable', tcp_mode='proxy', ipv6=False, chn_list='0')
        plan = policy.preview(self.request)
        self.assertFalse(plan['can_apply'])
        self.assertTrue(any('IPv6' in message for message in plan['entry_scope']['notices']))

    def test_saved_recovery_state_requires_an_explicit_shared_restart(self):
        self.active()
        port.atomic(policy.runtime() / 'receipt.json', {'state': 'recovery_required'})
        self.assertTrue(policy.preview(self.request, validate_runtime=False)['restart_required'])

    def test_cold_apply_checks_restart_confirmation_before_mutation(self):
        request = dict(self.apply_request(), confirm_restart=0)
        with self.assertRaisesRegex(RuntimeError, '确认'):
            policy.apply(request)
        self.assertEqual(self.generator.read_text(), self.stock)
        self.assertFalse(policy.folder().exists())

    def test_outdated_uci_core_or_adapter_previews_are_rejected(self):
        for key in ('uci_hash', 'adapter_hash', 'code_hash'):
            request = self.apply_request()
            saved = self.env[key]
            self.env[key] += '-changed'
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, '重新生成预览'):
                policy.apply(request)
            self.env[key] = saved
        self.assertEqual(self.generator.read_text(), self.stock)
        self.assertFalse(policy.folder().exists())

    def test_runtime_changes_during_validation_are_rejected(self):
        request = self.apply_request()
        def change_during_validation(*_):
            self.env.update(uci_hash='uci-changed')
            return {'expected_outbounds': {}}
        self.validate.side_effect = change_during_validation
        with self.assertRaisesRegex(RuntimeError, '校验期间'):
            policy.apply(request)
        self.assertFalse(policy.folder().exists())

    def test_first_apply_inserts_one_hook_and_waits_for_loaded_rules(self):
        with patch.object(policy, 'restart_passwall') as restart, patch.object(policy, 'live_configs', return_value=[self.attached_core()]):
            result = policy.apply(self.apply_request())
        self.assertTrue(result['restarted'])
        restart.assert_called_once()
        self.assertEqual(self.generator.read_text().count(policy.BEGIN), 1)
        self.assertEqual(policy.clean_hook(self.generator.read_text()), self.stock)
        self.assertTrue(policy.read(policy.folder() / 'manifest.json')['enabled'])
        self.assertEqual(policy.read(policy.runtime() / 'receipt.json')['state'], 'applied')

    def test_same_node_rule_change_preserves_process_and_original_generator(self):
        self.active()
        before = self.generator.read_bytes()
        with patch.object(policy, 'restart_passwall') as restart:
            result = policy.apply(self.apply_request(domains='auth.api.playstation.com\nnp.ac.playstation.net'))
        self.assertFalse(result['restarted'])
        restart.assert_not_called()
        self.assertEqual(self.generator.read_bytes(), before)
        self.assertIn('np.ac.playstation.net', policy.read(policy.folder() / 'rules.json')['rules'][0]['rules'][1]['domain'])

    def test_a_node_change_requires_a_shared_restart(self):
        self.active()
        self.env['nodes'].append(dict(id='nodeB', protocol='socks', label='B'))
        self.assertTrue(policy.preview(dict(self.request, node='nodeB'), validate_runtime=False)['restart_required'])

    def test_failed_restart_restores_original_files_then_restarts_passwall(self):
        with patch.object(policy, 'restart_passwall', side_effect=[RuntimeError('test restart failed'), None]) as restart:
            with self.assertRaisesRegex(RuntimeError, 'test restart failed'):
                policy.apply(self.apply_request())
        self.assertEqual(restart.call_count, 2)
        self.assertEqual(self.generator.read_text(), self.stock)
        self.assertFalse((policy.folder() / 'manifest.json').exists())
        self.assertFalse((policy.folder() / 'rules.json').exists())

    def test_cancellation_after_start_rolls_back_the_added_policy(self):
        def cancel():
            return (policy.folder() / 'manifest.json').exists()
        with patch.object(policy, 'restart_passwall') as restart, patch.object(policy, 'live_configs', return_value=[self.attached_core()]):
            with self.assertRaisesRegex(RuntimeError, '取消'):
                policy.apply(self.apply_request(), cancel=cancel)
        self.assertEqual(restart.call_count, 2)
        self.assertEqual(self.generator.read_text(), self.stock)
        self.assertFalse((policy.folder() / 'manifest.json').exists())

    def test_failed_hot_update_restores_the_previous_rule_set(self):
        self.active()
        before = {x: (policy.folder() / x).read_bytes() for x in ('rules.json', 'manifest.json', 'draft.json')}
        self.commands.return_value = subprocess.CompletedProcess([], 1, '', 'watcher failed')
        with patch.object(policy, 'restart_passwall') as restart, self.assertRaisesRegex(RuntimeError, '跟踪服务'):
            policy.apply(self.apply_request(ports='8443'))
        restart.assert_not_called()
        self.assertEqual({x: (policy.folder() / x).read_bytes() for x in before}, before)

    def test_rollback_preserves_concurrent_foreign_generator_edits(self):
        def restart():
            self.generator.write_text(self.generator.read_text() + '-- foreign extension\n')
            raise RuntimeError('restart failed')
        with patch.object(policy, 'restart_passwall') as mocked:
            mocked.side_effect = lambda: restart() if mocked.call_count == 1 else None
            with self.assertRaises(RuntimeError):
                policy.apply(self.apply_request())
        self.assertEqual(self.generator.read_text(), self.stock + '-- foreign extension\n')

    def test_recovery_failure_remains_visible(self):
        with patch.object(policy, 'restart_passwall', side_effect=RuntimeError('failed')):
            with self.assertRaisesRegex(RuntimeError, '启动需要检查'):
                policy.apply(self.apply_request())
        self.assertEqual(policy.read(policy.runtime() / 'receipt.json')['state'], 'recovery_required')
        self.assertEqual(self.generator.read_text(), self.stock)

    def test_disable_empties_only_owned_rules_and_keeps_hook_for_reuse(self):
        self.active()
        before = self.generator.read_bytes()
        with patch.object(policy, 'restart_passwall') as restart:
            policy.disable()
        restart.assert_not_called()
        self.assertEqual(policy.read(policy.folder() / 'rules.json'), {'version': 3, 'rules': []})
        self.assertFalse(policy.read(policy.folder() / 'manifest.json')['enabled'])
        self.assertEqual(self.generator.read_bytes(), before)
        self.assertTrue((policy.folder() / 'draft.json').exists())

    def test_disable_write_failure_restores_the_enabled_rule_set(self):
        self.active()
        before = (policy.folder() / 'rules.json').read_bytes()
        original = port.atomic
        def fail(path, value):
            if path.name == 'manifest.json':
                raise OSError('full disk')
            original(path, value)
        with patch.object(port, 'atomic', side_effect=fail), self.assertRaises(OSError):
            policy.disable()
        self.assertEqual((policy.folder() / 'rules.json').read_bytes(), before)
        self.assertTrue(policy.read(policy.folder() / 'manifest.json')['enabled'])

    def test_detach_removes_only_its_hook_even_with_foreign_program_edits(self):
        self.active()
        self.generator.write_text(self.generator.read_text() + '-- another plugin\n')
        policy.detach()
        self.assertEqual(self.generator.read_text(), self.stock + '-- another plugin\n')
        self.assertEqual(policy.read(policy.folder() / 'rules.json'), {'version': 3, 'rules': []})

    def test_source_refresh_follows_current_addresses_and_removes_lost_devices(self):
        self.active()
        changed = [dict(mac=self.request['portal'], addresses=['10.0.0.201']),
                   dict(mac=self.request['ps5'], addresses=[])]
        with patch.object(policy, 'inventory', return_value=changed):
            policy.refresh_sources()
        scopes = policy.read(policy.folder() / 'rules.json')['rules'][0]['rules'][0]
        self.assertEqual(scopes, {'source_ip_cidr': ['10.0.0.201/32']})
        with patch.object(policy, 'inventory', return_value=[]):
            policy.refresh_sources()
        self.assertEqual(policy.read(policy.folder() / 'rules.json'), {'version': 3, 'rules': []})

    def test_staged_validation_files_are_removed_on_failure(self):
        self.validation.stop()
        with patch.object(policy, 'compile_config', side_effect=RuntimeError('invalid node')):
            with self.assertRaises(RuntimeError):
                policy.validate_configs(self.request, dict(portal=['10.0.0.101'], ps5=[]), self.env['configs'])
        self.assertEqual(list(policy.runtime().glob('check-*')), [])

    def test_config_check_hides_node_credentials_from_error_messages(self):
        with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'password=secret')):
            with self.assertRaises(RuntimeError) as caught:
                policy.check_config({'outbounds': []})
        self.assertNotIn('secret', str(caught.exception))

    def test_tproxy_capability_probe_uses_nft_check_without_committing_rules(self):
        with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')) as command:
            self.assertTrue(policy.tproxy_supported())
        self.assertEqual(command.call_args.args[0], ['nft', '-c', '-f', '/dev/stdin'])
        self.assertIn('socket transparent 1', command.call_args.kwargs['input'])
        with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'unsupported')):
            self.assertFalse(policy.tproxy_supported())

    def test_lock_serializes_watchers_and_user_changes(self):
        with policy.lock():
            with self.assertRaisesRegex(RuntimeError, '正在更新'):
                with policy.lock():
                    pass

    def test_rpc_rejects_legacy_node_options_and_forged_list_revisions(self):
        request = {'domains': self.request['domains'], 'exclusions': self.request['exclusions'], 'revision': 'a' * 64}
        self.assertEqual(api.validate('psportal_apply', request), request)
        with self.assertRaises(ValueError):
            api.validate('psportal_apply', dict(request, path='/etc/passwd'))
        with self.assertRaises(ValueError):
            api.validate('psportal_apply', dict(request, revision='forged'))

    def test_luci_cancellation_uses_policy_rollback_and_keeps_bitrate_service(self):
        jobs = self.root / 'jobs'
        job_id = 'a' * 32
        port.atomic(jobs / 'job.json', dict(id=job_id, action='psportal_apply', request={'domains': self.request['domains'], 'exclusions': self.request['exclusions'], 'revision': 'a' * 64}, state='queued'))
        with patch.object(api, 'JOBS', jobs), patch.object(api, 'cancelled', return_value=True), \
             patch.object(api.rules, 'apply', side_effect=api.rules.RulesCancelled('名单应用已取消')), \
             patch.object(api, 'stop_service') as stop, patch.object(api, 'record_failure'):
            api.worker(job_id)
        stop.assert_not_called()
        self.assertEqual(json.loads((jobs / 'job.json').read_text())['state'], 'cancelled')


if __name__ == '__main__':
    unittest.main()
