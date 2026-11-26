"""Smoke coverage for native lists, upgrade cleanup and passive core sampling."""
from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import passwall_rules as rules
import portal_luci as api
import portal_openwrt as port
import portal_policy as legacy
import proxy_telemetry as telemetry
from domain_monitor import DomainMonitor
from observability import utc
from test_domains import DEVICES


CORE = {'inbounds': [{'type': 'tproxy', 'tag': 'tcp', 'listen_port': 1041}],
        'outbounds': [{'type': 'trojan', 'tag': 'current-node'}, {'type': 'direct', 'tag': 'direct'}],
        'experimental': {'clash_api': {'external_controller': '127.0.0.1:9090', 'secret': 'local-secret'}}}
UCI = """passwall.main=global
passwall.main.enabled='1'
passwall.main.tcp_node='shunt'
passwall.main.udp_node='same'
passwall.shunt=nodes
passwall.shunt.type='Xray'
passwall.shunt.protocol='_shunt'
passwall.shunt.password='private-password'
passwall.same=nodes
passwall.same.type='sing-box'
passwall.same.protocol='anytls'
"""


class NativeRulesTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.native, self.old = self.root / 'etc-rules', self.root / 'share-rules'
        self.native.mkdir()
        self.old.mkdir()
        self.reader = self.root / 'rule_list.lua'
        self.reader.write_text('local path = "/etc/%s/rules/"\nlocal name = "proxy_host"\n')
        self.service = self.root / 'passwall'
        self.service.write_text('#!/bin/sh\n')
        self.generator = self.root / 'util_sing-box.lua'
        self.generator.write_text('local unrelated = true\n')
        self.uci = UCI
        self.cores = [{'type': 'xray', 'key': 'local-core', 'config': {}}]
        self.original = {'domains': '# existing\ngeosite:google\nold.example.com\n',
                         'exclusions': '# downloads\ndwc.dl.playstation.net\n'}
        for key, text in self.original.items():
            path = self.native / rules.FILE_NAMES[key]
            path.write_text(text)
            path.chmod(0o640)
        for obj, name, value in ((port, 'PERSIST', self.root / 'persist'), (port, 'RUNTIME', self.root / 'run'),
                                 (rules, 'RULE_ROOTS', (self.native, self.old)),
                                 (rules, 'RULE_SOURCES', (self.reader,)), (rules, 'SERVICE', str(self.service)),
                                 (legacy, 'PASSWALL', self.generator)):
            patcher = patch.object(obj, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(port, 'command', side_effect=lambda *args, **kw: subprocess.CompletedProcess(args, 0, self.uci, ''))
        self.commands = patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(rules, 'live_cores', side_effect=lambda: deepcopy(self.cores))
        patcher.start()
        self.addCleanup(patcher.stop)
        patcher = patch.object(rules, 'reload_passwall')
        self.reload = patcher.start()
        self.addCleanup(patcher.stop)

    def request(self, **changes):
        return dict(self.original, revision=rules.status()['revision'], **changes)

    def contents(self):
        return {key: (self.native / name).read_text() for key, name in rules.FILE_NAMES.items()}

    def test_native_lists_keep_comments_and_geosite_and_convert_legacy_full_hosts(self):
        value = rules.normalize({'domains': '# keep\r\ngeosite:google\r\nfull:API.Example.com\r\napi.example.com\n', 'exclusions': ''})
        self.assertEqual(value['domains'], '# keep\ngeosite:google\napi.example.com\n')
        self.assertEqual(value['exclusions'], '')
        with self.assertRaises(ValueError):
            rules.normalize({'domains': '*signaling*\n', 'exclusions': ''})

    def test_status_reads_xray_shunts_and_singbox_without_node_selection_or_version_checks(self):
        value = rules.status()
        self.assertTrue(value['available'])
        self.assertEqual(value['mode'], 'native_lists')
        self.assertEqual(value['config'], self.original)
        self.assertFalse(value['pending_apply'])
        self.assertNotIn('nodes', value)
        self.assertNotIn('private-password', json.dumps(value))
        self.assertTrue(value['switches']['proxy_list_enabled'])

    def test_status_reads_metadata_with_multiline_uci_rules(self):
        self.uci += """passwall.game=shunt_rules
passwall.game.domain_list='full:example.com
geosite:games'
passwall.game.ip_list='192.0.2.0/24
198.51.100.0/24'
passwall.shunt.remarks='Game
proxy'
"""
        value = rules.status()
        self.assertTrue(value['available'])
        self.assertEqual(value['mode'], 'native_lists')
        self.assertEqual(value['config'], self.original)
        self.assertEqual(rules.metadata()['cores'], ['Xray', 'sing-box'])
        self.assertTrue(value['switches']['proxy_list_enabled'])

    def test_installed_reader_selects_the_current_and_legacy_list_directory(self):
        (self.old / 'proxy_host').write_text('legacy.example.com\n')
        self.assertEqual(rules.rule_root(), self.native)
        self.reader.write_text('local path = "/etc/passwall/rules/"\nlocal name = "proxy_host"\n')
        self.assertEqual(rules.rule_root(), self.native)
        self.reader.write_text('local path = "/usr/share/%s/rules/"\nlocal name = "proxy_host"\n')
        self.assertEqual(rules.rule_root(), self.old)

    def test_save_only_updates_native_files_and_preserves_permissions_and_uci(self):
        request = self.request()
        request['domains'] += 'new.example.com\n'
        result = rules.save(request)
        self.assertEqual(self.contents(), {key: request[key] for key in rules.FIELDS})
        self.assertTrue(result['pending_apply'])
        self.assertEqual((self.native / 'proxy_host').stat().st_mode & 0o777, 0o640)
        self.reload.assert_not_called()
        self.assertTrue(all(call.args == ('uci', '-q', 'show', 'passwall') for call in self.commands.call_args_list))
        self.assertEqual(list(self.native.glob('.*.ps-accel-*')), [])

    def test_apply_reloads_the_existing_xray_service_and_accepts_empty_lists(self):
        request = self.request()
        request.update(domains='', exclusions='')
        result = rules.apply(request)
        self.assertTrue(result['reloaded'])
        self.assertFalse(result['pending_apply'])
        self.assertEqual(self.contents(), dict.fromkeys(rules.FIELDS, ''))
        self.reload.assert_called_once_with()

    def test_disabled_or_manually_stopped_passwall_keeps_its_stopped_state(self):
        for enabled, cores in ((False, self.cores), (True, [])):
            with self.subTest(enabled=enabled):
                self.uci = UCI.replace("enabled='1'", "enabled='0'") if not enabled else UCI
                self.cores = cores
                request = self.request()
                request['domains'] = 'new.example.com\n'
                result = rules.apply(request)
                self.assertFalse(result['reloaded'])
                self.assertTrue(result['pending_apply'])
        self.reload.assert_not_called()

    def test_external_edits_reject_a_stale_save_without_overwriting_either_list(self):
        request = self.request()
        (self.native / 'direct_host').write_text('external.example.com\n')
        expected = self.contents()
        with self.assertRaisesRegex(RuntimeError, '其他页面修改'):
            rules.save(request)
        self.assertEqual(self.contents(), expected)

    def test_partial_write_failure_restores_both_original_files(self):
        request = self.request()
        request.update(domains='new.example.com', exclusions='direct.example.com')
        original_write = rules.write_bytes
        def write(path, content, mode):
            if path.name == 'direct_host':
                raise OSError('write failed')
            original_write(path, content, mode)
        with patch.object(rules, 'write_bytes', side_effect=write), self.assertRaises(OSError):
            rules.apply(request)
        self.assertEqual(self.contents(), self.original)
        self.reload.assert_not_called()

    def test_reload_failure_restores_the_lists_and_reloads_the_previous_configuration(self):
        request = self.request()
        request['domains'] = 'new.example.com\n'
        self.reload.side_effect = [RuntimeError('reload failed'), None]
        with self.assertRaisesRegex(RuntimeError, 'reload failed'):
            rules.apply(request)
        self.assertEqual(self.contents(), self.original)
        self.assertEqual(self.reload.call_count, 2)

    def test_an_external_write_during_save_survives_our_rollback(self):
        request = self.request()
        request['domains'] = 'new.example.com\n'
        original_write = rules.write_bytes
        def write(path, content, mode):
            original_write(path, content, mode)
            if path.name == 'proxy_host' and content == b'new.example.com\n':
                (self.native / 'direct_host').write_text('external.example.com\n')
        with patch.object(rules, 'write_bytes', side_effect=write), self.assertRaisesRegex(RuntimeError, '外部修改'):
            rules.save(request)
        self.assertEqual(self.contents()['domains'], self.original['domains'])
        self.assertEqual(self.contents()['exclusions'], 'external.example.com\n')

    def test_rollback_restores_our_file_when_the_other_list_exceeds_the_read_limit(self):
        request = self.request()
        request['domains'] = 'new.example.com\n'
        original_write = rules.write_bytes
        def write(path, content, mode):
            original_write(path, content, mode)
            if path.name == 'proxy_host' and content == b'new.example.com\n':
                (self.native / 'direct_host').write_text('x' * (rules.LIST_BYTES + 1))
        with patch.object(rules, 'write_bytes', side_effect=write), self.assertRaises(ValueError):
            rules.save(request)
        self.assertEqual(self.contents()['domains'], self.original['domains'])
        self.assertEqual(len(self.contents()['exclusions']), rules.LIST_BYTES + 1)

    def test_a_cancel_arriving_after_commit_reports_the_completed_list_transaction(self):
        jobs, ident = self.root / 'jobs', 'b' * 32
        port.atomic(jobs / 'job.json', {'id': ident, 'action': 'psportal_apply', 'state': 'queued', 'request': self.request()})
        with (patch.object(api, 'JOBS', jobs), patch.object(api, 'cancelled', return_value=True),
              patch.object(rules, 'apply', return_value={'notice': 'applied', 'reloaded': True, 'pending_apply': False}),
              patch.object(api, 'stop_service') as stop):
            api.worker(ident)
        self.assertEqual(api.optional(jobs / 'job.json')['state'], 'complete')
        stop.assert_not_called()

    def test_upgrade_detaches_only_the_owned_hook_and_keeps_native_lists_until_apply(self):
        self.generator.write_text('local before = true\n' + legacy.HOOK + 'local after = true\n')
        port.atomic(legacy.folder() / 'manifest.json', {'enabled': True, 'config': {
            'domains': 'full:auth.example.com\n*.signal.example.com\ngsconnect.*', 'exclusions': 'downloads.example.com'}})
        port.atomic(port.PERSIST / 'domains.json', {'domains': [{'domain': 'region.signal.example.com'}]})
        rules.migrate()
        self.assertEqual(self.generator.read_text(), 'local before = true\nlocal after = true\n')
        self.assertFalse(legacy.read(legacy.folder() / 'manifest.json')['enabled'])
        self.assertEqual(self.contents(), self.original)
        status = rules.status()
        self.assertEqual(status['config_source'], 'migration')
        self.assertIn('auth.example.com\nregion.signal.example.com\n', status['config']['domains'])
        self.assertNotIn('gsconnect.*', status['config']['domains'])
        self.assertIn('geosite:google', status['config']['domains'])
        self.reload.assert_not_called()
        rules.save(dict(status['config'], revision=status['revision']))
        rules.migrate()
        self.assertEqual(rules.status()['config_source'], 'passwall')

    def test_rpc_exposes_only_status_and_revision_bound_list_writes(self):
        request = self.request()
        self.assertEqual(api.validate('psportal_apply', request), request)
        with self.assertRaises(ValueError):
            api.validate('psportal_apply', dict(request, node='new-node'))
        for method in ('psportal_preview', 'psportal_probe', 'psportal_disable', 'psportal_autostart'):
            with self.subTest(method=method), self.assertRaises(ValueError):
                api.validate(method, {})


class NativeTrafficTests(unittest.TestCase):
    def test_existing_singbox_api_counts_native_proxy_and_direct_connections(self):
        rows = [{'id': 'native', 'metadata': {'sourceIP': DEVICES['portal']['ip'], 'network': 'tcp',
                'host': 'api.example.com', 'destinationPort': '8443'}, 'chains': ['current-node'],
                'upload': 100, 'download': 200}]
        tracker = telemetry.ConnectionTracker()
        with patch.object(telemetry, 'api_connections', return_value=rows):
            value = rules.traffic_sample(tracker, [{'type': 'sing-box', 'key': 'native', 'config': CORE}],
                {'portal': [DEVICES['portal']['ip']]}, {'domains': 'example.com', 'exclusions': ''}, {})
        self.assertEqual(value['connections'][0]['route'], 'proxy')
        self.assertTrue(value['connections'][0]['expected_proxy'])
        self.assertEqual(value['connections'][0]['bytes_down'], 200)
        self.assertEqual(value['policy_scope']['mode'], 'native_lists')

    def test_xray_keeps_dns_and_rule_membership_while_waiting_for_domain_traffic(self):
        tracker = telemetry.ConnectionTracker()
        value = rules.traffic_sample(tracker, [{'type': 'xray', 'config': {}}],
            {'portal': [DEVICES['portal']['ip']]}, {'domains': 'example.com', 'exclusions': ''}, {})
        self.assertEqual(value['state'], 'unavailable')
        self.assertEqual(value['sampled_cores'], 0)
        self.assertIn('Xray', value['limit'])
        monitor = DomainMonitor(DEVICES, epoch=value['epoch'] - 1)
        monitor.begin(value['epoch'] - 1)
        monitor.record({'kind': 'dns_ok', 'device': 'portal', 'domains': ['api.example.com'],
                        'epoch': value['epoch'] - .5, 'time': utc(value['epoch'] - .5)})
        self.assertTrue(monitor.observe_connections(value, value['epoch']))
        row = monitor.snapshot()['batches'][0]['domains'][0]
        self.assertTrue(row['traffic']['proxy_rules_seen'])
        self.assertFalse(row['traffic']['sampled'])
        self.assertEqual(monitor.traffic_state, 'unavailable')


if __name__ == '__main__':
    unittest.main()
