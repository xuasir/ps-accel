import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import shlex
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE))
import build


@unittest.skipUnless(shutil.which('sh') and shutil.which('make'), 'POSIX development tools required')
class DeploymentTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        # Exercise /tmp/ destination rewriting on every host, including macOS.
        self.root = Path(temp.name) / 'tmp'
        self.root.mkdir()

    def portable_fixture(self):
        with patch.object(build, 'OUT', self.root / 'out'):
            _, archive = build.build()
        with tarfile.open(archive) as package:
            package.extractall(self.root / 'bundle', filter='data')
        folder = self.root / 'bundle/ps-accel-openwrt'
        target = self.root / 'router'
        for name in ('etc/init.d', 'etc/config', 'usr/sbin', 'usr/lib', 'usr/share/luci', 'www', 'var/run/netns'):
            (target / name).mkdir(parents=True, exist_ok=True)
        (target / 'etc/openwrt_release').write_text("DISTRIB_TARGET='rockchip/armv8'\n")
        (target / 'etc/init.d/rpcd').write_text('#!/bin/sh\nexit 1\n')
        (target / 'etc/init.d/rpcd').chmod(0o755)
        # Redirect only fixed filesystem destinations into a temporary fake router.
        for name in ('install.sh', 'uninstall.sh'):
            text = (folder / name).read_text()
            text = re.sub(r'/(?:var/run|etc|usr|www|tmp)(?=/|[\s\'\"])',
                          lambda match: str(target) + match.group(), text)
            # Insert the bare root destination after rewriting the fixed paths.
            text = text.replace('cp -R "$HERE/luci/root/." /',
                                'cp -R "$HERE/luci/root/." "' + str(target) + '/"')
            (folder / name).write_text(text)
        (folder / 'files/ps-accel').write_text('#!/bin/sh\necho "service $*" >> "$PS_ACCEL_TEST_LOG"\n')
        (folder / 'files/ps-accel.init').write_text('#!/bin/sh\necho "init $*" >> "$PS_ACCEL_TEST_LOG"\n')
        (folder / 'files/ps-accel-observe').write_text('#!/bin/sh\necho "observer $*" >> "$PS_ACCEL_TEST_LOG"\n')
        (folder / 'files/ps-accel-observe.init').write_text('#!/bin/sh\necho "observer-init $*" >> "$PS_ACCEL_TEST_LOG"\n')
        (folder / 'files/ps-accel-policy').write_text('#!/bin/sh\necho "policy $*" >> "$PS_ACCEL_TEST_LOG"\n')
        (folder / 'files/ps-accel-policy.init').write_text('#!/bin/sh\necho "policy-init $*" >> "$PS_ACCEL_TEST_LOG"\n')
        manifest_path = folder / 'MANIFEST.json'
        manifest = json.loads(manifest_path.read_text())
        for name in manifest:
            manifest[name] = hashlib.sha256((folder / name).read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
        fakebin = self.root / 'bin'
        fakebin.mkdir()
        for name, body in {'id': 'echo 0', 'ip': 'exit 0', 'uci': 'exit 0',
                           'apk': 'echo "apk $*" >> "$PS_ACCEL_TEST_LOG"; exit 1',
                           'opkg': 'echo "opkg $*" >> "$PS_ACCEL_TEST_LOG"; exit 1'}.items():
            command = fakebin / name
            command.write_text('#!/bin/sh\n' + body + '\n')
            command.chmod(0o755)
        python = fakebin / 'python3'
        python.write_text('#!/bin/sh\nexec ' + shlex.quote(sys.executable) + ' "$@"\n')
        python.chmod(0o755)
        env = dict(os.environ, PATH=str(fakebin) + os.pathsep + os.environ['PATH'],
                   PS_ACCEL_TEST_LOG=str(self.root / 'commands.log'))
        return folder, target, env

    def test_offline_install_and_uninstall_preserve_configuration(self):
        folder, target, env = self.portable_fixture()
        installed = subprocess.run(['sh', str(folder / 'install.sh'), '--offline'], env=env, capture_output=True)
        self.assertEqual(installed.returncode, 0, installed.stderr.decode())
        self.assertTrue((target / 'usr/lib/ps-accel/profiles.py').exists())
        self.assertTrue((target / 'usr/lib/ps-accel/telemetry.py').exists())
        self.assertTrue((target / 'usr/lib/ps-accel/stream_quality.py').exists())
        self.assertTrue((target / 'usr/lib/ps-accel/portal_observe.py').exists())
        self.assertTrue((target / 'usr/lib/ps-accel/portal_policy.py').exists())
        self.assertTrue((target / 'usr/lib/ps-accel/psportal_adapter.lua').exists())
        self.assertEqual((target / 'etc/ps-accel/observability.json').stat().st_mode & 0o777, 0o600)
        self.assertTrue((target / 'etc/init.d/ps-accel-observe').exists())
        self.assertEqual((target / 'etc/config/ps_accel').stat().st_mode & 0o777, 0o600)
        config = (target / 'etc/config/ps_accel').read_bytes()
        removed = subprocess.run(['sh', str(folder / 'uninstall.sh')], env=env, capture_output=True)
        self.assertEqual(removed.returncode, 0, removed.stderr.decode())
        self.assertFalse((target / 'usr/lib/ps-accel').exists())
        self.assertEqual((target / 'etc/config/ps_accel').read_bytes(), config)
        log = (self.root / 'commands.log').read_text()
        self.assertIn('service stop', log)
        self.assertIn('observer-init enable', log)
        self.assertIn('observer-init start', log)
        self.assertIn('observer-init stop', log)
        self.assertIn('policy detach', log)
        self.assertIn('policy-init stop', log)
        self.assertFalse((target / 'etc/init.d/ps-accel-policy').exists())
        self.assertFalse((target / 'etc/init.d/ps-accel-observe').exists())
        self.assertTrue((target / 'etc/ps-accel/observability.json').exists())
        self.assertNotIn('apk add', log)
        self.assertNotIn('opkg install', log)

    def test_foreign_engine_lock_blocks_install_before_mutation(self):
        folder, target, env = self.portable_fixture()
        (target / 'var/run/portal-lab-capture.lock').write_text('999')
        result = subprocess.run(['sh', str(folder / 'install.sh'), '--offline'], env=env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((target / 'usr/lib/ps-accel').exists())
        self.assertFalse((self.root / 'commands.log').exists())

    def test_manifest_failure_blocks_install_before_file_copy(self):
        folder, target, env = self.portable_fixture()
        (folder / 'app/profiles.py').write_text('corrupted')
        result = subprocess.run(['sh', str(folder / 'install.sh'), '--offline'], env=env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((target / 'usr/lib/ps-accel').exists())

    def test_native_sdk_recipe_installs_the_luci_and_engine_files(self):
        sdk = self.root / 'sdk'
        (sdk / 'include').mkdir(parents=True)
        (sdk / 'rules.mk').write_text('INCLUDE_DIR:=$(TOPDIR)/include\n')
        (sdk / 'include/package.mk').write_text(
            'PKG_BUILD_DIR:=$(TOPDIR)/build\n'
            'INSTALL_DIR:=mkdir -p\nINSTALL_DATA:=install -m 0644\n'
            'INSTALL_BIN:=install -m 0755\nCP:=cp -a\n'
            '.PHONY: validation\nvalidation:\n'
            '\t$(call Build/Prepare)\n\t$(call Package/ps-accel/install,$(TOPDIR)/root)\n')
        subprocess.run(['make', '-f', str(SOURCE / 'Makefile'), 'TOPDIR=' + str(sdk), 'validation'],
                       cwd=SOURCE, check=True, capture_output=True)
        root = sdk / 'root'
        self.assertTrue((root / 'www/luci-static/resources/view/ps-accel/settings.js').exists())
        self.assertTrue((root / 'usr/lib/ps-accel/profiles.py').exists())
        self.assertTrue((root / 'usr/lib/ps-accel/telemetry.py').exists())
        self.assertTrue((root / 'usr/lib/ps-accel/domain_tracker.py').exists())
        self.assertTrue((root / 'usr/lib/ps-accel/psportal_adapter.lua').exists())
        self.assertEqual((root / 'etc/init.d/ps-accel-policy').stat().st_mode & 0o777, 0o755)
        self.assertEqual((root / 'etc/init.d/ps-accel-observe').stat().st_mode & 0o777, 0o755)
        self.assertEqual((root / 'usr/libexec/rpcd/ps-accel').stat().st_mode & 0o777, 0o755)
        self.assertEqual((root / 'usr/lib/ps-accel').stat().st_mode & 0o777, 0o700)
        self.assertFalse((root / 'usr/lib/ps-accel/build.py').exists())


if __name__ == '__main__':
    unittest.main()
