"""Device ACL isolation, native UCI transactions and batch traffic smoke tests."""
from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import passwall_rules as rules
import passwall_uci as uci
import portal_luci as api
import portal_openwrt as port
import portal_policy as legacy
import proxy_telemetry as telemetry
from domain_monitor import DomainMonitor
from observability import utc
from test_domains import DEVICES

BINARY = os.environ.get('PS_ACCEL_TEST_UCI') or shutil.which('uci')
SHARED_FILES = {'domains': 'proxy_host', 'exclusions': 'direct_host'}
GROUP = {role: dict(mac=row['mac'], ip=row['ip']) for role, row in DEVICES.items()}
CORE = {'inbounds': [{'type': 'tproxy', 'tag': 'tcp', 'listen_port': 1041}],
        'outbounds': [{'type': 'trojan', 'tag': 'current-node'}, {'type': 'direct', 'tag': 'direct'}],
        'experimental': {'clash_api': {'external_controller': '127.0.0.1:9090', 'secret': 'local-secret'}}}
BASE = """config global 'main'
 option enabled '1'
 option node 'xray_a'
 option acl_enable '1'
 option remote_dns '8.8.8.8'
 option v2ray_dns_mode 'tcp'
config nodes 'xray_a'
 option type 'Xray'
 option protocol 'vless'
 option remarks '已有 Xray 出口'
 option password 'private-password'
 option ech '1'
config nodes 'sing_a'
 option type 'sing-box'
 option protocol 'anytls'
 option remarks '已有 Sing-box 出口'
 option shadowtls '1'
config shunt_rules 'stock_rule'
 option remarks '已有规则'
 option domain_list 'full:unrelated.example.com'
config nodes 'stock_shunt'
 option type 'Xray'
 option protocol '_shunt'
 option default_node 'xray_a'
 option stock_rule '_direct'
config acl_rule 'other_acl'
 option enabled '1'
 option mode '1'
 option node 'sing_a'
 list sources '02:00:00:00:00:99'
"""
SHOW = """passwall.main=global
passwall.main.enabled='1'
passwall.main.node='xray_a'
passwall.main.acl_enable='1'
passwall.xray_a=nodes
passwall.xray_a.type='Xray'
passwall.xray_a.protocol='vless'
passwall.xray_a.remarks='已有 Xray 出口'
passwall.xray_a.password='private-password'
passwall.xray_a.ech='1'
passwall.sing_a=nodes
passwall.sing_a.type='Sing-Box'
passwall.sing_a.protocol='anytls'
passwall.sing_a.shadowtls='1'
passwall.shunt=nodes
passwall.shunt.type='Xray'
passwall.shunt.protocol='_shunt'
passwall.shunt.default_node='xray_a'
"""


def planned_state(schema='single_node'):
    sections = uci.parse(SHOW)
    return {'snapshot': {'sections': sections}, 'global': sections['main'], 'group': deepcopy(GROUP),
            'schema': schema, 'nodes': rules.node_choices(sections)}


class PlanningTests(unittest.TestCase):
    def test_multiline_uci_fields_and_source_lists_are_preserved(self):
        parsed = uci.parse("passwall.acl=acl_rule\npasswall.acl.sources='mac-one' 'mac-two'\n"
                           "passwall.rule=shunt_rules\npasswall.rule.domain_list='full:one.example\nfull:two.example'\n"
                           "passwall.node=nodes\npasswall.node.remarks='first line\nsecond line'\n")
        self.assertEqual(parsed['acl']['sources'], ['mac-one', 'mac-two'])
        self.assertEqual(parsed['rule']['domain_list'], 'full:one.example\nfull:two.example')
        self.assertEqual(parsed['node']['remarks'], 'first line\nsecond line')

    def test_existing_xray_and_singbox_protocol_options_keep_their_availability(self):
        nodes = rules.node_choices(uci.parse(SHOW))
        self.assertTrue(next(row for row in nodes if row['id'] == 'xray_a')['available'])
        self.assertTrue(next(row for row in nodes if row['id'] == 'sing_a')['available'])
        self.assertFalse(next(row for row in nodes if row['id'] == 'shunt')['available'])
        self.assertNotIn('private-password', json.dumps(nodes))

    def test_new_lists_start_empty_and_follow_the_existing_native_exit(self):
        state = planned_state()
        self.assertEqual(rules.initial_config(state['snapshot']['sections'], state['global'], state['nodes']),
                         {'domains': '', 'exclusions': '', 'node': 'xray_a'})
        self.assertEqual((legacy.DEFAULTS['domains'], legacy.DEFAULTS['exclusions']), ('', ''))

    def test_special_exits_use_their_native_core(self):
        sections = uci.parse(SHOW)
        for core, protocol, available in (('Xray', '_balancing', True), ('sing-box', '_urltest', True),
                                         ('Xray', '_urltest', False), ('sing-box', '_balancing', False)):
            with self.subTest(core=core, protocol=protocol):
                sections['special'] = {'.type': 'nodes', 'type': core, 'protocol': protocol}
                node = next(row for row in rules.node_choices(sections) if row['id'] == 'special')
                self.assertEqual(node['available'], available)

    def test_scoped_rules_bind_two_macs_and_make_direct_the_default_for_both_cores(self):
        for schema in ('single_node', 'split_nodes'):
            for node in ('xray_a', 'sing_a'):
                with self.subTest(schema=schema, node=node):
                    state = planned_state(schema)
                    rows = rules.managed_sections(state, {'domains': 'auth.example.com\n',
                         'exclusions': 'downloads.example.com\n', 'node': node}, 'proxy')
                    self.assertEqual(set(rows[rules.ACL_ID]['sources']), {row['mac'] for row in GROUP.values()})
                    self.assertEqual(rows[rules.NODE_ID]['default_node'], '_direct')
                    self.assertEqual(rows[rules.NODE_ID][rules.PROXY_RULE], node)
                    self.assertEqual(rows[rules.NODE_ID][rules.DIRECT_RULE], '_direct')
                    self.assertEqual(rows[rules.PROXY_RULE]['domain_list'], 'full:auth.example.com')
                    self.assertEqual(rows[rules.ACL_ID]['use_proxy_list'], '0')
                    self.assertEqual(rows[rules.ACL_ID]['use_direct_list'], '0')
                    self.assertEqual(rows[rules.ACL_ID]['dns_mode'], 'xray' if node == 'xray_a' else 'sing-box')
                    self.assertEqual(rows[rules.NODE_ID]['type'], 'Xray' if node == 'xray_a' else 'sing-box')
                    if schema == 'single_node':
                        self.assertEqual(rows[rules.ACL_ID]['node'], rules.NODE_ID)
                    else:
                        self.assertEqual(rows[rules.ACL_ID]['tcp_node'], rules.NODE_ID)
                        self.assertEqual(rows[rules.ACL_ID]['udp_node'], rules.NODE_ID)

    def test_empty_lists_create_only_lan_direct_and_default_direct_routes(self):
        rows = rules.managed_sections(planned_state(), {'domains': '', 'exclusions': '', 'node': 'xray_a'}, 'proxy')
        self.assertIsNone(rows[rules.PROXY_RULE])
        self.assertIsNone(rows[rules.DIRECT_RULE])
        self.assertNotIn(rules.PROXY_RULE, rows[rules.NODE_ID])

    def test_switching_to_xray_uses_the_native_tcp_dns_fallback(self):
        state = planned_state()
        state['global'].update(v2ray_dns_mode='quic', remote_dns='1.1.1.1#853')
        config = {'domains': 'auth.example.com', 'exclusions': '', 'node': 'xray_a'}
        rows = rules.managed_sections(state, config, 'proxy')
        self.assertEqual((rows[rules.ACL_ID]['dns_mode'], rows[rules.ACL_ID]['v2ray_dns_mode'],
                          rows[rules.ACL_ID]['remote_dns']), ('xray', 'tcp', '1.1.1.1#53'))
        config['node'] = 'sing_a'
        rows = rules.managed_sections(state, config, 'proxy')
        self.assertEqual(rows[rules.ACL_ID]['v2ray_dns_mode'], 'quic')
        self.assertNotIn(rules.DIRECT_RULE, rows[rules.NODE_ID])
        self.assertIn('192.168.0.0/16', rows[rules.LAN_RULE]['ip_list'])

    def test_all_direct_keeps_the_acl_matched_and_release_removes_only_owned_sections(self):
        state = planned_state()
        direct = rules.managed_sections(state, {'domains': '', 'exclusions': '', 'node': ''}, 'direct')
        self.assertEqual(direct[rules.ACL_ID]['enabled'], '1')
        self.assertEqual(direct[rules.ACL_ID]['mode'], '0')
        self.assertEqual(direct[rules.ACL_ID]['tcp_no_redir_ports'], '1:65535')
        self.assertEqual(direct[rules.ACL_ID]['udp_no_redir_ports'], '1:65535')
        self.assertEqual(rules.managed_sections(state, {}, 'released'), dict.fromkeys(rules.OWNED))

    def test_rule_format_defaults_to_exact_hosts_and_supports_explicit_domain_suffixes(self):
        value = rules.normalize({'domains': '# keep\r\ngeosite:google\r\nfull:API.Example.com\r\napi.example.com\n'
                                'domain:shared.example.com\n', 'exclusions': '', 'node': 'xray_a'})
        self.assertEqual(value['domains'], '# keep\ngeosite:google\napi.example.com\ndomain:shared.example.com\n')
        self.assertEqual(rules.compiled(value['domains']), 'geosite:google\nfull:api.example.com\ndomain:shared.example.com')
        self.assertFalse(rules.matches('sub.api.example.com', rules.host_rules(value['domains'])))
        self.assertTrue(rules.matches('sub.shared.example.com', rules.host_rules(value['domains'])))
        self.assertFalse(rules.matches('shared.example.com.attacker.net', rules.host_rules(value['domains'])))
        with self.assertRaises(ValueError):
            rules.normalize({'domains': '*signaling*', 'exclusions': '', 'node': 'xray_a'})

    def test_other_policy_references_and_identifier_collisions_block_mutation(self):
        for row in ({'.type': 'nodes', 'default_node': rules.NODE_ID},
                    {'.type': 'nodes', 'shunt_group': rules.GROUP_ID},
                    {'.type': 'acl_rule', 'node': rules.NODE_ID},
                    {'.type': 'nodes', 'balancing_node': [rules.NODE_ID]}):
            with self.subTest(row=row), self.assertRaises(RuntimeError):
                rules.guard({'borrowed': row})
        with self.assertRaises(RuntimeError):
            rules.guard({rules.ACL_ID: {'.type': 'acl_rule', 'enabled': '1'}})

    def test_rpc_accepts_only_scoped_fields_and_revision_bound_mode_actions(self):
        request = {'domains': 'auth.example.com', 'exclusions': '', 'node': 'xray_a', 'revision': 'a' * 64}
        self.assertEqual(api.validate('psportal_apply', request), request)
        self.assertEqual(api.validate('psportal_direct', {'revision': 'a' * 64}), {'revision': 'a' * 64})
        self.assertEqual(api.validate('psportal_release', {'revision': 'a' * 64}), {'revision': 'a' * 64})
        for bad in (dict(request, path='/etc/shadow'), dict(request, node='../node'), dict(request, revision='forged')):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                api.validate('psportal_apply', bad)
        for method in ('psportal_preview', 'psportal_probe', 'psportal_disable', 'psportal_autostart'):
            with self.subTest(method=method), self.assertRaises(ValueError):
                api.validate(method, {})


@unittest.skipUnless(BINARY, 'native UCI CLI is required for transaction integration smoke')
class NativeUCITests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        directory = self.root / 'config'
        directory.mkdir()
        self.path = directory / 'passwall'
        self.path.write_text(BASE)
        self.path.chmod(0o640)
        service, reader, generator = self.root / 'passwall-service', self.root / 'acl_config.lua', self.root / 'generator.lua'
        service.write_text('#!/bin/sh\n')
        reader.write_text('local node = "node"\nlocal mode = "mode"\n')
        generator.write_text('local original = true\n')
        native = self.root / 'rules'
        native.mkdir()
        self.shared = {'domains': '# keep global\nold.shared.example\ngeosite:google\n',
                       'exclusions': 'dwc.dl.playstation.net\n'}
        for key, name in SHARED_FILES.items():
            (native / name).write_text(self.shared[key])
        binding = {'config': {'portal_ip': GROUP['portal']['ip'], 'ps5_ip': GROUP['ps5']['ip'], 'bridge': 'br-lan'},
                   **{role + '_mac': GROUP[role]['mac'] for role in GROUP}}
        for module, name, value in ((uci, 'BINARY', BINARY), (uci, 'CONFIG', self.path),
            (uci, 'SAVEDIR', self.root / 'delta'), (port, 'RUNTIME', self.root / 'run'),
            (port, 'PERSIST', self.root / 'persist'), (rules, 'LIVE_ROOT', self.root / 'live'),
            (rules, 'SERVICE', str(service)), (rules, 'ACL_SOURCE', reader), (rules, 'APP_SOURCE', self.root / 'app.sh'),
            (legacy, 'PASSWALL', generator)):
            patcher = patch.object(module, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.cores = [{'type': 'xray', 'key': 'main', 'path': 'main.json', 'config': {}}]
        for module, name, value in ((port, 'device_binding', binding), (rules, 'live_cores', None)):
            patcher = patch.object(module, name, return_value=value) if name == 'device_binding' else patch.object(
                module, name, side_effect=lambda: deepcopy(self.cores))
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.object(rules, 'reload_passwall', side_effect=self.load_runtime)
        self.reload = patcher.start()
        self.addCleanup(patcher.stop)
        self.native = native
        self.before = uci.snapshot()['sections']

    def load_runtime(self):
        sections = uci.snapshot()['sections']
        acl = sections.get(rules.ACL_ID)
        path = rules.LIVE_ROOT / 'acl' / rules.ACL_ID / 'source_list'
        self.cores = [row for row in self.cores if row['key'] == 'main']
        if acl and sections['main'].get('acl_enable') == '1':
            path.parent.mkdir(parents=True, exist_ok=True)
            sources = acl['sources'] if isinstance(acl['sources'], list) else [acl['sources']]
            path.write_text('\n'.join('mac:' + value for value in sources) + '\n')
            if rules.policy_mode(sections) == 'proxy':
                kind = rules.core_name(sections[rules.NODE_ID]['type'])
                self.cores.append({'type': kind, 'key': 'scoped', 'path': rules.NODE_ID + '.json',
                                   'config': {'outbounds': [{'tag': rules.PROXY_RULE}]}})
        else:
            path.unlink(missing_ok=True)

    def request(self, node='xray_a', **changes):
        return dict(domains='auth.example.com\n', exclusions='downloads.example.com\n', node=node,
                    revision=rules.status()['revision'], **changes)

    def assert_unmanaged(self):
        current = uci.snapshot()['sections']
        for ident, row in self.before.items():
            self.assertEqual(current[ident], row)
        self.assertEqual({key: (self.native / name).read_text() for key, name in SHARED_FILES.items()}, self.shared)

    def test_fresh_install_and_legacy_default_backup_start_with_empty_device_lists(self):
        port.atomic(port.PERSIST / 'passwall-lists-migration.json', {'config': self.shared})
        current = rules.status()
        self.assertTrue(current['available'])
        self.assertEqual(current['config'], {'domains': '', 'exclusions': '', 'node': 'xray_a'})
        self.assertEqual(current['counts'], {'domains': 0, 'exclusions': 0})
        rules.migrate()
        self.assertEqual(rules.status()['config'], current['config'])
        self.assert_unmanaged()

    def test_multiline_stock_rules_keep_both_exit_choices_when_global_proxy_is_disabled(self):
        self.path.write_text(BASE.replace("option enabled '1'", "option enabled '0'", 1).replace(
            'full:unrelated.example.com', 'full:unrelated.example.com\nfull:second.example.com').replace(
            '已有 Xray 出口', '已有 Xray 出口\n第二行备注'))
        current = rules.status()
        self.assertTrue(current['available'])
        self.assertTrue(current['running'])
        self.assertFalse(current['passwall_enabled'])
        self.assertEqual({row['id'] for row in current['nodes'] if row['available']}, {'xray_a', 'sing_a'})
        rules.apply(self.request('sing_a'))
        self.assertEqual(rules.status()['environment']['selected_core'], 'sing-box')

    def test_save_is_local_and_preserves_native_lists_uci_and_permissions(self):
        before = self.path.read_bytes()
        result = rules.save(self.request())
        self.assertEqual(self.path.read_bytes(), before)
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o640)
        self.assertIn('auth.example.com', rules.status()['config']['domains'])
        self.assertTrue(result['pending_apply'])
        self.reload.assert_not_called()
        self.assert_unmanaged()

    def test_native_transactions_cover_xray_singbox_and_both_acl_schemas(self):
        for schema in ('single_node', 'split_nodes'):
            for node in ('xray_a', 'sing_a'):
                with self.subTest(schema=schema, node=node):
                    self.path.write_text(BASE)
                    rules.ACL_SOURCE.write_text('"node" "mode"' if schema == 'single_node' else '"tcp_node" "udp_node"')
                    result = rules.apply(self.request(node))
                    self.assertTrue(result['reloaded'])
                    status = rules.status()
                    self.assertTrue(status['loaded'])
                    self.assertEqual(status['policy_mode'], 'proxy')
                    self.assertEqual(status['config']['node'], node)
                    self.assert_unmanaged()
                    sections = uci.snapshot()['sections']
                    self.assertEqual(sections[rules.NODE_ID]['default_node'], '_direct')
                    self.assertEqual(sections[rules.PROXY_RULE]['domain_list'], 'full:auth.example.com')
                    self.assertEqual(sections[rules.DIRECT_RULE]['domain_list'], 'full:downloads.example.com')
                    order = [ident for ident, row in sections.items() if row['.type'] == 'acl_rule']
                    self.assertEqual(order[0], rules.ACL_ID)

    def test_repeated_apply_retains_priority_and_empty_lists_never_catch_all_traffic(self):
        rules.apply(self.request())
        request = self.request()
        request.update(domains='', exclusions='')
        rules.apply(request)
        sections = uci.snapshot()['sections']
        order = [ident for ident, row in sections.items() if row['.type'] == 'acl_rule']
        self.assertEqual(order, [rules.ACL_ID, 'other_acl'])
        self.assertNotIn(rules.PROXY_RULE, sections)
        self.assertNotIn(rules.DIRECT_RULE, sections)
        self.assertNotIn(rules.PROXY_RULE, sections[rules.NODE_ID])
        self.assertFalse(rules.status()['pending_apply'])
        self.assert_unmanaged()

    def test_proxy_direct_and_release_keep_other_devices_configuration_intact(self):
        rules.apply(self.request())
        rules.direct({'revision': rules.status()['revision']})
        sections = uci.snapshot()['sections']
        self.assertEqual(sections[rules.ACL_ID]['mode'], '0')
        self.assertEqual(sections[rules.ACL_ID]['sources'], [GROUP['portal']['mac'], GROUP['ps5']['mac']])
        self.assertTrue(rules.status()['loaded'])
        rules.release({'revision': rules.status()['revision']})
        self.assertFalse(any(ident in uci.snapshot()['sections'] for ident in rules.OWNED))
        self.assertEqual(rules.status()['policy_mode'], 'released')
        self.assert_unmanaged()

    def test_stale_revisions_and_pending_native_edits_preserve_configuration(self):
        request = self.request()
        self.path.write_text(BASE + "config nodes 'new_node'\n option type 'Xray'\n option protocol 'trojan'\n")
        before = self.path.read_bytes()
        with self.assertRaisesRegex(RuntimeError, '已有修改'):
            rules.apply(request)
        self.assertEqual(self.path.read_bytes(), before)
        uci.command('set', 'passwall.main.unapplied=1')
        with self.assertRaisesRegex(RuntimeError, '待保存配置'):
            rules.apply(self.request())
        self.assertEqual(self.path.read_bytes(), before)

    def test_reload_failure_and_cancellation_restore_owned_rules_and_keep_other_fields(self):
        before = uci.snapshot()['sections']
        def fail_once():
            if self.reload.call_count == 1:
                raise RuntimeError('reload failed')
            self.load_runtime()
        self.reload.side_effect = fail_once
        with self.assertRaisesRegex(RuntimeError, 'reload failed'):
            rules.apply(self.request())
        self.assertEqual(uci.snapshot()['sections'], before)
        self.reload.side_effect = self.load_runtime
        count = 0
        def cancelled():
            nonlocal count
            count += 1
            return count == 3
        with self.assertRaises(rules.RulesCancelled):
            rules.apply(self.request(), cancel=cancelled)
        self.assertEqual(uci.snapshot()['sections'], before)
        self.assertEqual(list(port.RUNTIME.glob('passwall-uci-*')), [])

    def test_the_acl_switch_is_restored_on_release_and_other_latent_acls_are_protected(self):
        self.path.write_text(BASE.replace("option acl_enable '1'", "option acl_enable '0'").replace(
            "config acl_rule 'other_acl'\n option enabled '1'", "config acl_rule 'other_acl'\n option enabled '0'"))
        before = uci.snapshot()['sections']
        rules.apply(self.request())
        self.assertEqual(uci.snapshot()['sections']['main']['acl_enable'], '1')
        rules.release({'revision': rules.status()['revision']})
        self.assertEqual(uci.snapshot()['sections'], before)
        self.path.write_text(BASE.replace("option acl_enable '1'", "option acl_enable '0'"))
        before_data = self.path.read_bytes()
        with self.assertRaisesRegex(RuntimeError, '其他启用规则'):
            rules.apply(self.request())
        self.assertEqual(self.path.read_bytes(), before_data)

    def test_the_two_devices_can_run_while_global_proxying_stays_disabled(self):
        self.path.write_text(BASE.replace("option enabled '1'", "option enabled '0'"))
        self.cores = []
        rules.apply(self.request())
        self.assertEqual(uci.snapshot()['sections']['main']['enabled'], '0')
        self.assertTrue(rules.status()['loaded'])
        self.assertTrue(rules.status()['enabled'])

    def test_manually_stopped_global_service_remains_stopped_until_started_in_passwall(self):
        self.cores = []
        result = rules.apply(self.request())
        self.assertFalse(result['reloaded'])
        self.assertTrue(result['pending_apply'])
        self.reload.assert_not_called()
        self.assertFalse(rules.status()['loaded'])
        self.load_runtime()
        self.assertTrue(rules.status()['loaded'])

    def test_native_bookkeeping_during_reload_survives_a_scope_rollback(self):
        def reload():
            uci.command('set', 'passwall.main.bookkeeping=retained')
            uci.command('commit', 'passwall')
            self.load_runtime()
            raise RuntimeError('runtime failed')
        self.reload.side_effect = lambda: reload() if self.reload.call_count == 1 else self.load_runtime()
        with self.assertRaisesRegex(RuntimeError, 'runtime failed'):
            rules.apply(self.request())
        sections = uci.snapshot()['sections']
        self.assertEqual(sections['main']['bookkeeping'], 'retained')
        self.assertFalse(any(ident in sections for ident in rules.OWNED))

    def test_upgrade_keeps_native_lists_and_detaches_only_the_legacy_hook(self):
        legacy.PASSWALL.write_text('local before = true\n' + legacy.HOOK + 'local after = true\n')
        port.atomic(legacy.folder() / 'manifest.json', {'enabled': True})
        before = self.path.read_bytes()
        rules.migrate()
        self.assertEqual(legacy.PASSWALL.read_text(), 'local before = true\nlocal after = true\n')
        self.assertEqual(self.path.read_bytes(), before)
        self.assert_unmanaged()
        self.assertTrue((rules.folder() / 'draft.json').exists())


class TrafficTests(unittest.TestCase):
    def test_scoped_rule_membership_is_exact_with_direct_precedence(self):
        from sony_domains import scope_proxy
        scope = {'mode': 'device_acl', 'scope_enabled': True, 'proxy_list_enabled': True,
                 'domains': 'api.example.com\ndomain:shared.example.com', 'exclusions': 'direct.shared.example.com'}
        self.assertTrue(scope_proxy('api.example.com', scope))
        self.assertFalse(scope_proxy('sub.api.example.com', scope))
        self.assertTrue(scope_proxy('sub.shared.example.com', scope))
        self.assertFalse(scope_proxy('direct.shared.example.com', scope))
        self.assertFalse(scope_proxy('api.example.com', dict(scope, scope_enabled=False)))

    def test_native_singbox_proxy_samples_keep_device_scopes_and_actual_counters(self):
        rows = [{'id': 'native', 'metadata': {'sourceIP': GROUP['portal']['ip'], 'network': 'tcp',
                'host': 'api.example.com', 'destinationPort': '8443'}, 'chains': ['current-node'],
                'upload': 100, 'download': 200}]
        tracker = telemetry.ConnectionTracker()
        with patch.object(telemetry, 'api_connections', return_value=rows):
            value = rules.traffic_sample(tracker, [{'type': 'sing-box', 'key': 'native', 'config': CORE}],
                {'portal': [GROUP['portal']['ip']]}, {'domains': 'api.example.com', 'exclusions': ''},
                {'controlled': True, 'proxy_list_enabled': True, 'direct_list_enabled': True})
        self.assertEqual(value['connections'][0]['route'], 'proxy')
        self.assertTrue(value['connections'][0]['expected_proxy'])
        self.assertEqual(value['connections'][0]['bytes_down'], 200)
        self.assertEqual(value['policy_scope']['mode'], 'device_acl')

    def test_xray_keeps_batch_membership_while_waiting_for_domain_traffic(self):
        tracker = telemetry.ConnectionTracker()
        value = rules.traffic_sample(tracker, [{'type': 'xray', 'config': {}}],
            {'portal': [GROUP['portal']['ip']]}, {'domains': 'api.example.com', 'exclusions': ''},
            {'controlled': True, 'proxy_list_enabled': True})
        self.assertEqual(value['state'], 'unavailable')
        self.assertEqual(value['sampled_cores'], 0)
        self.assertIn('Xray', value['limit'])
        monitor = DomainMonitor(DEVICES, epoch=value['epoch'] - 1)
        monitor.begin(value['epoch'] - 1)
        monitor.record({'kind': 'dns_ok', 'device': 'portal', 'domains': ['api.example.com'],
                        'epoch': value['epoch'] - .5, 'time': utc(value['epoch'] - .5)})
        self.assertTrue(monitor.observe_connections(value, value['epoch']))
        traffic = monitor.snapshot()['batches'][0]['domains'][0]['traffic']
        self.assertTrue(traffic['proxy_rules_seen'])
        self.assertFalse(traffic['sampled'])


if __name__ == '__main__':
    unittest.main()
