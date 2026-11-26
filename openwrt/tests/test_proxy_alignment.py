"""Meaningful smoke coverage for Sony coverage, actual core evidence and probes."""
import copy
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import ipaddress
from pathlib import Path
import subprocess
import re
import sys
import threading
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import proxy_telemetry as telemetry
import sony_domains as sony
import portal_policy as policy
import portal_luci as api
import portal_openwrt as port
import test_policy as fixtures


CORE = {'inbounds': [{'type': 'redirect', 'tag': 'tcp', 'listen_port': 1041}],
        'outbounds': [{'type': 'direct', 'tag': 'direct'}]}
SOURCES = {'portal': ['10.0.0.101', 'fd00::101'], 'ps5': ['10.0.0.100']}
MANIFEST = {'config': {'node': 'nodeA', 'domains': 'auth.api.playstation.com\nregion.np.communication.playstation.net',
                      'ports': '443', 'exclusions': sony.FIRMWARE_HOST}}


def connection(ident='one', source='10.0.0.101', host='region.np.communication.playstation.net', chain=None, down=100):
    return {'id': ident, 'metadata': {'sourceIP': source, 'sourcePort': '51000', 'network': 'tcp',
            'destinationIP': '1.1.1.1', 'destinationPort': '443', 'host': host},
            'chains': [policy.TAG, 'direct'] if chain is None else chain, 'upload': 80, 'download': down}


class AlignmentTests(unittest.TestCase):
    def test_unseen_dynamic_hosts_match_the_generated_scoped_rules_on_first_connection(self):
        config = dict(MANIFEST['config'], domains='full:auth.api.playstation.com\n*.custom.example.com',
                      exclusions='blocked.np.communication.playstation.net\n*.auth.np.ac.playstation.net')
        rules = policy.rule_set(config, SOURCES)['rules'][0]
        def accepts(rule, host, source='10.0.0.101', network='tcp', port=443):
            if rule.get('type') == 'logical':
                matched = all(accepts(child, host, source, network, port) for child in rule['rules'])
            elif 'source_ip_cidr' in rule:
                matched = any(ipaddress.ip_address(source) in ipaddress.ip_network(cidr) for cidr in rule['source_ip_cidr'])
            elif 'network' in rule:
                matched = network == rule['network'] and port in rule['port']
            else:
                matched = (host in rule.get('domain', [])
                           or any(host.endswith(suffix) for suffix in rule.get('domain_suffix', []))
                           or any(re.search(regex, host) for regex in rule.get('domain_regex', []))
                           or any(keyword in host for keyword in rule.get('domain_keyword', [])))
            return not matched if rule.get('invert') else bool(matched)
        hosts = ('new.region.np.communication.playstation.net', 'gsconnect.new.example.net',
                 'new.gsconnect.playstation.net', 'v2-signaling.new.example.net',
                 'new.remoteplay.playstation.net', 'new.deep.custom.example.com', 'auth.api.playstation.com')
        for host in hosts:
            with self.subTest(host=host):
                self.assertTrue(accepts(rules, host))
                self.assertTrue(accepts(rules, host, source='fd00::101'))
                self.assertFalse(accepts(rules, host, source='10.0.0.200'))
                self.assertFalse(accepts(rules, host, port=8443))
                self.assertFalse(accepts(rules, host, network='udp'))
        for host in ('blocked.np.communication.playstation.net', 'new.auth.np.ac.playstation.net',
                     'custom.example.com', 'np.communication.playstation.net',
                     'new.np.communication.playstation.net.example.com', 'xgsconnect.example.net', sony.FIRMWARE_HOST):
            with self.subTest(host=host):
                self.assertFalse(accepts(rules, host))
        config['exclusions'] = ''
        self.assertTrue(accepts(policy.rule_set(config, SOURCES)['rules'][0], 'unseen.auth.np.ac.playstation.net'))

    def test_fixed_dynamic_domains_and_connectivity_follow_reference_categories(self):
        expected = {'REGION.auth.np.ac.playstation.net': 'auth',
                    'region.np.communication.playstation.net': 'signaling',
                    'gsconnect.region.playstation.net': 'signaling',
                    'region.remoteplay.playstation.net': 'signaling', 'www.google.com': 'api',
                    'dwc.dl.playstation.net': 'api', 'example.com': 'misc'}
        for host, category in expected.items():
            self.assertEqual(sony.classify_sony_domain(host), category)
        self.assertEqual(sony.domain_info(sony.FIRMWARE_HOST)['suggestion'], 'direct')
        self.assertTrue(set(sony.CONNECTIVITY_HOSTS) <= set(policy.DEFAULTS['domains'].splitlines()))

    def test_candidates_preserve_explicit_exclusions_and_complete_only_full_hosts(self):
        host = 'region.np.communication.playstation.net'
        rows = [{'domain': host, 'device': 'portal'}, {'domain': host}, {'domain': sony.FIRMWARE_HOST}, {'domain': 'example.com'}]
        result = sony.candidates(rows, {'domains': '', 'exclusions': host})
        self.assertEqual([x['domain'] for x in result], [host, 'google.com', 'www.google.com'])
        self.assertTrue(result[0]['excluded'])
        self.assertTrue(result[0]['included'])
        self.assertTrue(all('*' not in x['domain'] for x in result))

    def test_wildcard_candidates_and_actual_expectations_agree_with_routing(self):
        host = 'unseen.auth.np.ac.playstation.net'
        manifest = {'config': dict(MANIFEST['config'], domains='auth.api.playstation.com',
                                  exclusions='*.np.communication.playstation.net')}
        rows = [{'domain': host}, {'domain': 'new.np.communication.playstation.net'}]
        candidates = sony.candidates(rows, manifest['config'])
        self.assertTrue(candidates[0]['included'])
        self.assertFalse(candidates[0]['excluded'])
        self.assertTrue(candidates[1]['excluded'])
        with patch.object(telemetry, 'api_connections', return_value=[connection('auth', host=host),
                          connection('blocked', host=rows[1]['domain'], chain=['direct'])]):
            result = telemetry.ConnectionTracker().sample([{'config': CORE}], SOURCES, manifest, epoch=100)
        by_host = {row['domain']: row for row in result['connections']}
        self.assertTrue(by_host[host]['expected_proxy'])
        self.assertFalse(by_host[rows[1]['domain']]['expected_proxy'])

    def test_actual_chains_and_payloads_are_scoped_to_device_identity(self):
        tracker = telemetry.ConnectionTracker()
        rows = [connection(), connection('other', source='10.0.0.200'),
                connection('six', source='fd00::101', host=sony.FIRMWARE_HOST, chain=['direct'])]
        with patch.object(telemetry, 'api_connections', return_value=rows):
            result = tracker.sample([{'config': CORE}], SOURCES, MANIFEST, epoch=100)
        self.assertEqual(len(result['connections']), 2)
        self.assertTrue(result['traffic_verified'])
        self.assertTrue(result['download_direct_verified'])
        selected = next(x for x in result['connections'] if x['route'] == 'selected')
        self.assertEqual(selected['phase'], 'CONNECTED')
        self.assertEqual([x['stage'] for x in selected['trace']], ['core_observed', 'route_selected', 'client_payload', 'upstream_payload'])

    def test_api_errors_keep_history_and_require_fresh_evidence_for_verification(self):
        tracker = telemetry.ConnectionTracker()
        with patch.object(telemetry, 'api_connections', return_value=[connection(down=0)]):
            first = tracker.sample([{'config': CORE}], SOURCES, MANIFEST, epoch=100)
        with patch.object(telemetry, 'api_connections', side_effect=OSError('private-token')):
            failed = tracker.sample([{'config': CORE}], SOURCES, MANIFEST, epoch=102)
        self.assertFalse(failed['traffic_verified'])
        self.assertTrue(failed['connections'][0]['active'])
        self.assertNotIn('private-token', json.dumps(failed))
        with patch.object(telemetry, 'api_connections', return_value=[]):
            tracker.sample([{'config': CORE}], SOURCES, MANIFEST, epoch=104)
            closed = tracker.sample([{'config': CORE}], SOURCES, MANIFEST, epoch=106)
        self.assertFalse(closed['connections'][0]['active'])
        self.assertEqual(closed['connections'][0]['failure'], 'upstream_response_missing')
        changed = copy.deepcopy(MANIFEST)
        changed['config']['node'] = 'nodeB'
        with patch.object(telemetry, 'api_connections', return_value=[]):
            result = tracker.sample([{'config': CORE}], SOURCES, changed, epoch=108)
        self.assertEqual(result['connections'], [])

    def test_connection_cache_is_bounded_under_many_target_flows(self):
        with patch.object(telemetry, 'api_connections', return_value=[connection(str(i)) for i in range(200)]):
            result = telemetry.ConnectionTracker().sample([{'config': CORE}], SOURCES, MANIFEST, epoch=100)
        self.assertEqual(len(result['connections']), telemetry.MAX_CONNECTIONS)
        self.assertEqual(result['health']['capacity_drops'], 72)

    def test_an_old_tag_during_node_restart_does_not_verify_the_new_node(self):
        manifest = dict(MANIFEST, expected_outbounds={telemetry.core_key(CORE): 'new-node-signature'})
        with patch.object(telemetry, 'api_connections', return_value=[connection()]):
            result = telemetry.ConnectionTracker().sample([{'config': CORE}], SOURCES, manifest, epoch=100)
        self.assertFalse(result['traffic_verified'])
        self.assertEqual(result['connections'][0]['route'], 'previous')

    def test_loopback_api_uses_the_configured_secret_and_fixed_read_endpoint(self):
        seen = []
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                seen.append((self.path, self.headers.get('Authorization')))
                body = json.dumps({'connections': [connection()]}).encode()
                self.send_response(200); self.end_headers(); self.wfile.write(body)
            def log_message(self, *_):
                pass
        server = HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        try:
            config = {'experimental': {'clash_api': {'external_controller': '127.0.0.1:' + str(server.server_port), 'secret': 'test-secret'}}}
            self.assertEqual(telemetry.api_connections(config)[0]['id'], 'one')
        finally:
            server.server_close(); thread.join(timeout=1)
        self.assertEqual(seen, [('/connections', 'Bearer test-secret')])
        for endpoint in ('example.com:9090', '0.0.0.0:9090', '192.0.2.1:9090', '127.0.0.1:0'):
            with self.assertRaises(ValueError):
                telemetry.loopback_endpoint(endpoint)

    def test_probe_checks_fixed_targets_and_cancel_stops_between_targets(self):
        manifest = {'diagnostics': {'secret': 'a' * 48, 'cores': {telemetry.core_key(CORE): {'probe_port': 18781}}}}
        response = dict(tcp=True, tls=True, failure='', dns={'ok': True})
        with patch.object(telemetry, 'probe_target', return_value=response) as target:
            result = telemetry.probe([{'config': CORE}], manifest)
        self.assertTrue(result['healthy'])
        self.assertEqual([(x.args[0], x.args[2]) for x in target.call_args_list],
                         [(host, path) for host, _, path in telemetry.PROBE_TARGETS])
        with patch.object(telemetry, 'probe_target') as target:
            result = telemetry.probe([{'config': CORE}], manifest, cancel=lambda: True)
        self.assertTrue(result['cancelled']); target.assert_not_called()

    def test_target_tcp_rejection_is_distinct_from_probe_entry_failure(self):
        sock = MagicMock()
        sock.recv.side_effect = [bytes([value]) for value in b'HTTP/1.1 502 Bad Gateway\r\n\r\n']
        with patch.object(telemetry, 'dns_probe', return_value={'ok': True}), \
             patch.object(telemetry.socket, 'create_connection', return_value=sock):
            result = telemetry.probe_target('auth.api.playstation.com', 443, 'proxy', '127.0.0.1:18781', 'a' * 48)
        self.assertEqual(result['failure'], 'target_connect_failure')
        self.assertFalse(result['tcp']); sock.close.assert_called_once()
        with patch.object(telemetry, 'dns_probe', return_value={'ok': True}), \
             patch.object(telemetry.socket, 'create_connection', side_effect=OSError('secret')):
            result = telemetry.probe_target('auth.api.playstation.com', 443, 'proxy', '127.0.0.1:18781', 'a' * 48)
        self.assertEqual(result['failure'], 'probe_entry_failure')
        self.assertNotIn('secret', json.dumps(result))

    def test_dns_probe_is_bounded_and_probe_rpc_rejects_custom_targets(self):
        with patch.object(telemetry.subprocess, 'run', side_effect=subprocess.TimeoutExpired('resolve', 3)):
            self.assertFalse(telemetry.dns_probe('www.google.com', 443)['ok'])
        with self.assertRaises(ValueError):
            api.validate('psportal_probe', {'target': 'custom.example'})
        acl = json.loads((Path(__file__).resolve().parents[1] / 'luci/root/usr/share/rpcd/acl.d/luci-app-ps-accel.json').read_text())['luci-app-ps-accel']
        self.assertNotIn('psportal_probe', acl['write']['ubus']['ps-accel'])
        self.assertNotIn('psportal_probe', acl['read']['ubus']['ps-accel'])


class AlignmentPolicyTests(unittest.TestCase):
    setUp = fixtures.PolicyTests.setUp
    active = fixtures.PolicyTests.active
    attached_core = fixtures.PolicyTests.attached_core
    def test_download_rules_are_device_scoped_and_disable_clears_both_sets(self):
        self.active()
        rules = policy.direct_rule_set(self.request, {'portal': ['10.0.0.101'], 'ps5': []})
        self.assertEqual(rules['rules'][0]['rules'], [{'source_ip_cidr': ['10.0.0.101/32']},
                         {'domain': [sony.FIRMWARE_HOST]}, {'network': 'tcp', 'port': [80, 443]}])
        self.assertEqual(policy.direct_rule_set(dict(self.request, exclusions=''), SOURCES)['rules'], [])
        wildcard = policy.direct_rule_set(dict(self.request, exclusions='*.dl.playstation.net'), SOURCES)
        self.assertEqual(wildcard['rules'][0]['rules'][1], {'domain': [sony.FIRMWARE_HOST]})
        policy.disable()
        self.assertEqual(policy.read(policy.folder() / 'direct-rules.json')['rules'], [])

    def test_legacy_attachment_requires_one_restart_and_a_warm_update_reuses_ports(self):
        self.active()
        warm = policy.preview(self.request, validate_runtime=False)
        self.assertFalse(warm['restart_required'])
        self.assertEqual(warm['direct_rules'][0]['domain'], sony.FIRMWARE_HOST)
        manifest = policy.read(policy.folder() / 'manifest.json')
        del manifest['direct_rules_path']
        port.atomic(policy.folder() / 'manifest.json', manifest)
        self.assertTrue(policy.preview(self.request, validate_runtime=False)['restart_required'])

    def test_existing_manifest_refresh_and_warm_apply_load_dynamic_rules(self):
        self.active()
        before = self.generator.read_bytes()
        with patch.object(policy, 'inventory', return_value=self.devices):
            policy.refresh_sources()
        matcher = policy.read(policy.folder() / 'rules.json')['rules'][0]['rules'][1]
        self.assertIn('.auth.np.ac.playstation.net', matcher['domain_suffix'])
        request = dict(self.request, domains='*.custom.example.com', exclusions='*.np.communication.playstation.net')
        plan = policy.preview(request, validate_runtime=False)
        self.assertFalse(plan['restart_required'])
        self.assertTrue(next(rule for rule in plan['rules'] if rule['domain'] == '*.np.communication.playstation.net')['excluded'])
        with patch.object(policy, 'restart_passwall') as restart:
            policy.apply(dict(request, token=plan['token'], confirm_restart=0))
        restart.assert_not_called()
        self.assertEqual(self.generator.read_bytes(), before)
        clauses = policy.read(policy.folder() / 'rules.json')['rules'][0]['rules']
        self.assertIn('.custom.example.com', clauses[1]['domain_suffix'])
        self.assertEqual(clauses[-1], {'domain_suffix': ['.np.communication.playstation.net'], 'invert': True})

    def test_retired_probe_rpc_keeps_bitrate_and_original_rules_running(self):
        with patch.object(api, 'stop_service') as stop:
            with self.assertRaises(ValueError):
                api.dispatch('psportal_probe', {})
        stop.assert_not_called()

    def test_current_status_requires_matching_configuration_device_and_age(self):
        self.active()
        manifest = policy.read(policy.folder() / 'manifest.json')
        sources, _ = policy.resolve(manifest['config'], self.devices)
        revision = telemetry.evidence_revision(manifest, sources)
        port.atomic(policy.runtime() / 'connections.json', dict(epoch=100, revision=revision,
                    traffic_verified=True, download_direct_verified=True, matched_connections=1,
                    connections=[{'route': 'selected'}]))
        port.atomic(policy.runtime() / 'probes.json', dict(epoch=100, revision=revision, healthy=True))
        with patch.object(policy.time, 'time', return_value=102):
            result = policy.status()
            self.assertTrue(result['entry_scope']['traffic_verified'])
            self.assertTrue(result['probes']['current_config'])
            changed = copy.deepcopy(manifest)
            changed['config']['node'] = 'nodeB'
            port.atomic(policy.folder() / 'manifest.json', changed)
            result = policy.status()
            self.assertFalse(result['telemetry']['fresh'])
            self.assertEqual(result['telemetry']['connections'], [])
            self.assertFalse(result['probes']['current_config'])
            port.atomic(policy.folder() / 'manifest.json', manifest)
            self.env['devices'][0]['addresses'] = ['10.0.0.102']
            self.assertFalse(policy.status()['entry_scope']['traffic_verified'])
            self.env['devices'] = copy.deepcopy(self.devices)
        with patch.object(policy.time, 'time', return_value=116):
            result = policy.status()
            self.assertFalse(result['telemetry']['traffic_verified'])
            self.assertFalse(result['telemetry']['download_direct_verified'])

    def test_probe_uses_current_loaded_outbound_and_records_its_revision(self):
        self.active()
        core = copy.deepcopy(self.env['configs'][0]['config'])
        core['outbounds'].append({'type': 'direct', 'tag': policy.TAG})
        manifest = policy.read(policy.folder() / 'manifest.json')
        manifest['expected_outbounds'] = {telemetry.core_key(core): telemetry.outbound_signature(core)}
        port.atomic(policy.folder() / 'manifest.json', manifest)
        with patch.object(policy, 'live_configs', return_value=[{'config': core}]), \
             patch.object(policy, 'inventory', return_value=self.devices), \
             patch.object(policy, 'probe', return_value={'healthy': True, 'targets': []}):
            result = policy.probe_connections()
        sources, _ = policy.resolve(manifest['config'], self.devices)
        self.assertEqual(result['revision'], telemetry.evidence_revision(manifest, sources))
        with patch.object(policy, 'live_configs', return_value=self.env['configs']), \
             patch.object(policy, 'probe') as probe:
            with self.assertRaisesRegex(RuntimeError, '加载待确认'):
                policy.probe_connections()
        probe.assert_not_called()


if __name__ == '__main__':
    unittest.main()
