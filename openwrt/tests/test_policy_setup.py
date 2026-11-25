"""Local node discovery and independent proxy startup preferences."""
from pathlib import Path
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portal_openwrt as port
import portal_policy as policy
sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_policy as fixtures


class LocalNodesTests(unittest.TestCase):
    def test_uci_reads_local_nodes_without_lua_and_reports_filtered_nodes(self):
        data = """passwall.main=global
passwall.main.enabled='0'
passwall.nodeA=nodes
passwall.nodeA.type='sing-box'
passwall.nodeA.protocol='trojan'
passwall.nodeA.remarks='本地节点 A'
passwall.nodeA.password='private-password'
passwall.nodeB=nodes
passwall.nodeB.type='Sing-Box'
passwall.nodeB.protocol='vless'
passwall.nodeB.domain_resolver='udp'
passwall.group=nodes
passwall.group.type='sing-box'
passwall.group.protocol='_shunt'
passwall.custom=nodes
passwall.custom.type='sing-box'
passwall.custom.protocol='trojan'
passwall.custom.domain_resolver='https'
passwall.custom.domain_resolver_dns_https='https://dns.example/query'
"""
        with patch.object(port, 'command', return_value=subprocess.CompletedProcess([], 0, data, '')) as command:
            result = policy.passwall_metadata()
        command.assert_called_once_with('uci', '-q', 'show', 'passwall', check=False, timeout=4)
        self.assertFalse(result['enabled'])
        self.assertEqual(len(result['nodes']), 4)
        self.assertEqual(result['nodes'][0]['label'], '本地节点 A')
        self.assertTrue(result['nodes'][0]['available'])
        self.assertTrue(result['nodes'][1]['available'])
        self.assertFalse(result['nodes'][2]['available'])
        self.assertIn('独立 DNS', result['nodes'][3]['reason'])
        self.assertNotIn('private-password', json.dumps(result))
        self.assertNotIn('dns.example', json.dumps(result))

    def test_uci_failure_has_an_explicit_node_read_error(self):
        with patch.object(port, 'command', return_value=subprocess.CompletedProcess([], 1, '', '')):
            with self.assertRaisesRegex(RuntimeError, '读取 PassWall 配置失败'):
                policy.passwall_metadata()


class ProxyStartupTests(unittest.TestCase):
    setUp = fixtures.PolicyTests.setUp

    def test_turning_boot_off_preserves_the_current_session_and_stops_after_reboot(self):
        port.atomic(policy.folder() / 'manifest.json', {'enabled': True, 'config': self.request})
        result = policy.set_autostart(False)
        self.assertTrue(result['enabled'])
        self.assertFalse(result['autostart'])
        self.assertTrue(policy.policy_enabled(policy.read(policy.folder() / 'manifest.json')))
        self.assertIn(('/etc/init.d/ps-accel-policy', 'disable'), [call.args for call in self.commands.call_args_list])
        (policy.runtime() / 'activation.json').unlink()
        self.assertFalse(policy.policy_enabled(policy.read(policy.folder() / 'manifest.json')))

    def test_turning_boot_on_preserves_the_stopped_session_and_restores_after_reboot(self):
        port.atomic(policy.folder() / 'manifest.json', {'enabled': True, 'autostart': False, 'config': self.request})
        result = policy.set_autostart(True)
        self.assertFalse(result['enabled'])
        self.assertFalse(policy.policy_enabled(policy.read(policy.folder() / 'manifest.json')))
        (policy.runtime() / 'activation.json').unlink()
        self.assertTrue(policy.policy_enabled(policy.read(policy.folder() / 'manifest.json')))

    def test_boot_setting_failure_restores_the_previous_manifest_and_preference(self):
        before = {'enabled': True, 'config': self.request}
        port.atomic(policy.folder() / 'manifest.json', before)
        self.commands.side_effect = [subprocess.CalledProcessError(1, ['service', 'disable']),
                                     subprocess.CompletedProcess([], 0, '', '')]
        with self.assertRaises(subprocess.CalledProcessError):
            policy.set_autostart(False)
        self.assertEqual(policy.read(policy.folder() / 'manifest.json'), before)
        self.assertTrue(policy.autostart_enabled())
        self.assertFalse((policy.runtime() / 'activation.json').exists())


if __name__ == '__main__':
    unittest.main()
