#!/usr/bin/env python3
"""Build a reproducible OpenWrt ipk and portable install bundle, using only stdlib."""
import gzip
import hashlib
import io
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parent
OUT = ROOT / 'release-assets'
VERSION = '0.1.2-1'
ENGINE = ['portal_auto.py', 'portal_auto_platform.py', 'portal_active_probe.py',
          'portal_capture.py', 'portal_egress_witness.py', 'portal_windows_network.py',
          'protocol.py', 'profiles.py', 'telemetry.py', 'LICENSE', 'requirements.txt', 'UPSTREAM.md']


def archive(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.GNU_FORMAT) as tar:
        # Explicit parents ensure opkg uses the intended private directory modes.
        directories = {str(p) for name in files for p in Path(name).parents if str(p) != '.'}
        for name in sorted(directories, key=lambda n: (len(Path(n).parts), n)):
            info = tarfile.TarInfo('./' + name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o700 if name.startswith(('usr/lib/ps-accel', 'etc/ps-accel')) else 0o755
            tar.addfile(info)
        for name, (data, mode) in sorted(files.items()):
            info = tarfile.TarInfo('./' + name)
            info.size = len(data)
            info.mode = mode
            info.uid = info.gid = 0
            tar.addfile(info, io.BytesIO(data))
    return gzip.compress(buf.getvalue(), mtime=0)


def build():
    OUT.mkdir(exist_ok=True)
    source_rev = (ROOT / 'UPSTREAM_REV').read_text().strip()
    app = {name: (ROOT / name).read_bytes() for name in ENGINE}
    app['portal_openwrt.py'] = (ROOT / 'portal_openwrt.py').read_bytes()
    app['portal_luci.py'] = (ROOT / 'portal_luci.py').read_bytes()
    app['UPSTREAM_REV'] = (source_rev + '\n').encode()
    data = {'usr/lib/ps-accel/' + n: (v, 0o600) for n, v in app.items()}
    for name, target, mode in [('ps-accel', 'usr/sbin/ps-accel', 0o755),
                               ('ps-accel.init', 'etc/init.d/ps-accel', 0o755),
                               ('ps_accel', 'etc/config/ps_accel', 0o600)]:
        data[target] = ((ROOT / 'files' / name).read_bytes(), mode)
    ui_files = {}
    for folder, prefix in [('root', ''), ('htdocs', 'www/')]:
        base = ROOT / 'luci' / folder
        for path in sorted(base.rglob('*')):
            if path.is_file():
                relative = path.relative_to(base).as_posix()
                mode = 0o755 if relative.startswith('usr/libexec/rpcd/') else 0o644
                data[prefix + relative] = (path.read_bytes(), mode)
                ui_files['luci/' + folder + '/' + relative] = (path.read_bytes(), mode)
    # Dependencies use OpenWrt's actual package name "scapy", not "python3-scapy".
    control = (f'Package: ps-accel\nVersion: {VERSION}\nArchitecture: all\n'
               'Maintainer: PS Accel\nSection: net\nPriority: optional\n'
               'Depends: python3, scapy, ip-full, kmod-veth, libpcap, luci-base, rpcd\n'
               'License: MIT\nSource: https://github.com/atameric/ps5-portal-high-bitrate\n'
               'Description: Experimental PlayStation Portal bitrate relay in an isolated network namespace\n'
               f'Installed-Size: {sum(len(v[0]) for v in data.values())}\n').encode()
    preinst = b'''#!/bin/sh
[ -n "$IPKG_INSTROOT" ] && exit 0
if [ -e /usr/lib/ps-accel ] || [ -e /usr/sbin/ps-accel ] || [ -e /etc/init.d/ps-accel ]; then
 if [ -f /usr/lib/opkg/info/ps-accel.list ] && [ -f /usr/lib/opkg/info/ps-accel.control ]; then
  /usr/sbin/ps-accel stop || exit 1
 else
  echo 'Unmanaged existing install: stop/uninstall it before installation; keep configuration.' >&2
  exit 1
 fi
fi
if [ -e /var/run/netns/ps-accel ] || [ -e /var/run/portal-lab-capture.lock ]; then
 echo 'Stop/repair existing relay before installation.' >&2
 exit 1
fi
exit 0
'''
    postinst = b'''#!/bin/sh
[ -n "$IPKG_INSTROOT" ] && exit 0
chmod 700 /usr/lib/ps-accel
rm -rf /usr/lib/ps-accel/__pycache__
chmod 600 /etc/config/ps_accel
uci set ps_accel.main.enabled=0
uci commit ps_accel
/etc/init.d/ps-accel disable
rm -f /tmp/luci-indexcache*
if /etc/init.d/rpcd running >/dev/null 2>&1; then /etc/init.d/rpcd reload; fi
echo 'Installed disabled. Open LuCI: Services -> PS Portal bitrate.'
exit 0
'''
    prerm = b'''#!/bin/sh
[ -n "$IPKG_INSTROOT" ] && exit 0
/usr/sbin/ps-accel stop || exit 1
/etc/init.d/ps-accel disable
exit 0
'''
    postrm = b'''#!/bin/sh
[ -n "$IPKG_INSTROOT" ] && exit 0
# Imported Python creates caches unknown to opkg. Remove them so reinstall works.
[ ! -e /var/run/netns/ps-accel ] || exit 1
rm -rf /usr/lib/ps-accel
rm -f /tmp/luci-indexcache*
if /etc/init.d/rpcd running >/dev/null 2>&1; then /etc/init.d/rpcd reload; fi
exit 0
'''
    ctrl = archive({'control': (control, 0o644), 'conffiles': (b'/etc/config/ps_accel\n', 0o644),
                    'preinst': (preinst, 0o755), 'postinst': (postinst, 0o755),
                    'prerm': (prerm, 0o755), 'postrm': (postrm, 0o755)})
    payload = archive(data)
    # Official OpenWrt ipkg-build uses an outer gzip tar containing these three members.
    ipk = OUT / f'ps-accel_{VERSION}_all.ipk'
    ipk.write_bytes(archive({'debian-binary': (b'2.0\n', 0o644),
                            'control.tar.gz': (ctrl, 0o644), 'data.tar.gz': (payload, 0o644)}))
    bundle = {'app/' + n: (v, 0o600) for n, v in app.items()}
    bundle.update(ui_files)
    for n in ('ps-accel', 'ps-accel.init', 'ps_accel'):
        bundle['files/' + n] = ((ROOT / 'files' / n).read_bytes(), 0o600)
    for n in ('install.sh', 'uninstall.sh', 'README.zh-CN.md'):
        bundle[n] = ((ROOT / n).read_bytes(), 0o644)
    bundle['MANIFEST.json'] = (json.dumps({n: hashlib.sha256(v[0]).hexdigest()
                                         for n, v in sorted(bundle.items())}, indent=2).encode(), 0o644)
    tgz = OUT / f'ps-accel-openwrt-{VERSION}.tar.gz'
    tgz.write_bytes(archive({'ps-accel-openwrt/' + n: v for n, v in bundle.items()}))
    (OUT / 'SHA256SUMS').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n'
                                            for p in (ipk, tgz)))
    print(ipk)
    print(tgz)
    return ipk, tgz


if __name__ == '__main__':
    build()
