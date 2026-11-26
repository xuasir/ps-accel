"""Optional smoke against installed PassWall generators and proxy core binaries."""
import json
import os
from pathlib import Path
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import passwall_rules as rules
import passwall_uci as uci
import portal_openwrt as port

LUA = os.environ.get('PS_ACCEL_TEST_LUA') or shutil.which('lua')
UCI = os.environ.get('PS_ACCEL_TEST_UCI') or shutil.which('uci')
XRAY = os.environ.get('PS_ACCEL_TEST_XRAY') or shutil.which('xray')
SINGBOX = os.environ.get('PS_ACCEL_TEST_SINGBOX') or shutil.which('sing-box')
GENERATORS = Path('/usr/lib/lua/luci/passwall')
LUA_GENERATE = r'''
local directory, savedir, core, node, port, runtime = unpack(arg)
arg = {}
local api = require('luci.passwall.api')
api.uci = require('uci').cursor(directory, savedir)
api.TMP_PATH = runtime .. '/passwall'
api.CACHE_PATH = runtime .. '/cache'
api.LOG_FILE = runtime .. '/passwall.log'
api.fs.mkdirr(api.CACHE_PATH)
local generator = require('luci.passwall.util_' .. core)
io.write(generator.gen_config({flag='ps_accel_smoke', node=node, no_run='1',
    local_socks_address='127.0.0.1', local_socks_port=tonumber(port),
    use_proxy_list='0', use_gfw_list='0', chn_list='0'}))
'''


@unittest.skipUnless(LUA and UCI and (GENERATORS / 'util_xray.lua').is_file() and
                     (GENERATORS / 'util_sing-box.lua').is_file(), 'installed PassWall Lua/UCI required')
class NativeGeneratorTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='ps-accel-native-smoke-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.directory, self.savedir = self.root / 'config', self.root / 'delta'
        self.directory.mkdir()
        self.savedir.mkdir()
        self.path = self.directory / 'passwall'
        binary = 'config global_app\n'
        if XRAY:
            binary += ' option xray_file ' + shlex.quote(XRAY) + '\n'
        if SINGBOX:
            binary += ' option sing_box_file ' + shlex.quote(SINGBOX) + '\n'
        self.base = binary + """config global 'main'
 option enabled '0'
 option node 'xray_exit'
config nodes 'xray_exit'
 option type 'Xray'
 option protocol 'socks'
 option remarks 'Xray smoke'
 option address '127.0.0.1'
 option port '19080'
config nodes 'sing_exit'
 option type 'sing-box'
 option protocol 'socks'
 option remarks 'Sing-box smoke'
 option address '127.0.0.1'
 option port '19081'
config shunt_rules 'stock_rule'
 option remarks 'Existing rule'
 option domain_list 'full:unrelated.example.com
full:other.example.com'
"""
        for module, name, value in ((uci, 'CONFIG', self.path), (uci, 'BINARY', UCI),
                                    (uci, 'SAVEDIR', self.savedir), (port, 'RUNTIME', self.root / 'run')):
            patcher = patch.object(module, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def generate(self, core, exit_id):
        self.path.write_text(self.base)
        before = uci.snapshot()
        nodes = rules.node_choices(before['sections'])
        self.assertTrue(next(node for node in nodes if node['id'] == exit_id)['available'])
        state = {'snapshot': before, 'global': before['sections']['main'], 'schema': 'single_node', 'nodes': nodes,
                 'group': {'portal': {'mac': '02:00:00:00:00:01'}, 'ps5': {'mac': '02:00:00:00:00:02'}}}
        rows = rules.managed_sections(state, {'node': exit_id,
            'domains': 'auth.example.com\ndomain:shared.example.com', 'exclusions': 'direct.shared.example.com'}, 'proxy')
        self.path.write_bytes(uci.stage(before, rows, {'acl_enable': '1'}, first_acl=rules.ACL_ID))
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            listen_port = reserved.getsockname()[1]
        script = self.root / 'generate.lua'
        script.write_text(LUA_GENERATE)
        result = subprocess.run([LUA, str(script), str(self.directory), str(self.savedir), core,
            rules.NODE_ID, str(listen_port), str(self.root)], capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        config = json.loads(result.stdout)
        path = self.root / (core + '.json')
        path.write_text(result.stdout)
        return config, path, listen_port

    def check_and_start(self, core, path, listen_port):
        binary = XRAY if core == 'xray' else SINGBOX
        if not binary:
            self.skipTest(core + ' binary required for startup smoke')
        argv = [binary, 'run', '-config', str(path)] if core == 'xray' else [binary, 'run', '-c', str(path)]
        check = [binary, 'run', '-test', '-config', str(path)] if core == 'xray' else [binary, 'check', '-c', str(path)]
        checked = subprocess.run(check, capture_output=True, text=True, timeout=10, cwd=self.root)
        self.assertEqual(checked.returncode, 0, checked.stderr + checked.stdout)
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.root)
        try:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and process.poll() is None:
                try:
                    with socket.create_connection(('127.0.0.1', listen_port), timeout=.2) as client:
                        client.sendall(b'\x05\x01\x00')
                        self.assertEqual(client.recv(2), b'\x05\x00')
                        return
                except ConnectionRefusedError:
                    time.sleep(.05)
            self.fail(core + ' local SOCKS listener failed to start')
        finally:
            process.terminate()
            try:
                process.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()

    def test_xray_native_routes_and_core_startup(self):
        config, path, listen_port = self.generate('xray', 'xray_exit')
        routes = config['routing']['rules']
        proxy = next((row for row in routes if 'full:auth.example.com' in row.get('domains', row.get('domain', []))), None)
        direct = next((row for row in routes if 'full:direct.shared.example.com' in row.get('domains', row.get('domain', []))), None)
        self.assertIsNotNone(proxy, json.dumps(routes))
        self.assertIsNotNone(direct, json.dumps(routes))
        self.assertIn(rules.PROXY_RULE, proxy['outboundTag'])
        self.assertEqual(direct['outboundTag'], 'direct')
        self.assertLess(routes.index(direct), routes.index(proxy))
        self.assertEqual(routes[-1]['outboundTag'], 'direct')
        self.assertEqual(next(row for row in config['outbounds'] if row['tag'] == 'direct')['protocol'], 'freedom')
        self.check_and_start('xray', path, listen_port)

    def test_singbox_native_routes_and_core_startup(self):
        config, path, listen_port = self.generate('sing-box', 'sing_exit')
        routes = config['route']['rules']
        proxy = next(row for row in routes if 'auth.example.com' in row.get('domain', []))
        direct = next(row for row in routes if 'direct.shared.example.com' in row.get('domain', []))
        self.assertIn(rules.PROXY_RULE, proxy['outbound'])
        self.assertEqual(direct['outbound'], 'direct')
        self.assertLess(routes.index(direct), routes.index(proxy))
        self.assertEqual(config['route']['final'], 'direct')
        self.check_and_start('sing-box', path, listen_port)
