#!/usr/bin/env python3
"""OpenWrt supervisor: an isolated Ethernet relay attached to the existing LAN bridge.

The router's forwarding, firewall and network configuration are never rewritten.
Only an owned veth pair and network namespace are created. The upstream protocol
engine, packet gates, baseline and recovery guardian are retained.
"""
import argparse
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import shlex
import shutil
import subprocess
import sys
import time
import uuid

APP = Path(__file__).resolve().parent
if not (APP / 'portal_auto.py').exists():
    APP = APP.parent  # run from a source checkout
sys.path.insert(0, str(APP))
from profiles import APP_VERSION, PROFILES
PERSIST = Path('/etc/ps-accel')
RUNTIME = Path('/tmp/ps-accel')
NS = 'ps-accel'
HOST = 'psa-host'
PEER = 'psa-peer'
IFACE = 'relay0'
ALIAS = 'ps-accel-openwrt-v1'
HANDLE = Path('/var/run/netns') / NS
ENGINE_LOCK = Path('/var/run/portal-lab-capture.lock')
SYSNET = Path('/sys/class/net')
CONFIG_FILE = Path('/etc/config/ps_accel')
FINGERPRINT_FILES = ('portal_auto.py', 'portal_auto_platform.py', 'portal_active_probe.py',
                     'portal_windows_network.py', 'protocol.py', 'profiles.py', 'telemetry.py', 'observability.py',
                     'stream_quality.py')


class ControllerBusy(RuntimeError):
    pass


def command(*args, check=True, timeout=15):
    return subprocess.run([str(x) for x in args], text=True, capture_output=True,
                          check=check, timeout=timeout)


def atomic(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(value, indent=2) + '\n')
    temp.chmod(0o600)
    temp.replace(path)


def read_json(path):
    return json.loads(path.read_text())


def uci_get(key, default=''):
    result = command('uci', '-q', 'get', 'ps_accel.main.' + key, check=False)
    return result.stdout.strip() if result.returncode == 0 else default


def uci_values():
    """Read one coherent UCI section in one process, including staged changes."""
    result = command('uci', '-q', 'show', 'ps_accel.main', check=False, timeout=3)
    if result.returncode:
        raise RuntimeError('读取插件配置失败，请检查 UCI 配置。')
    values = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition('=')
        if separator and key.startswith('ps_accel.main.'):
            tokens = shlex.split(value)
            if len(tokens) != 1:
                raise ValueError('插件配置包含无效字段。')
            values[key.removeprefix('ps_accel.main.')] = tokens[0]
    return values


def configuration_revision():
    """Cheap change token; full content fingerprints remain a start-time gate."""
    paths = [CONFIG_FILE, Path('/tmp/.uci/ps_accel'), Path('/etc/rc.d/S95ps-accel'),
             PERSIST / 'auto-config.json', PERSIST / 'devices.json', PERSIST / 'baseline.json',
             PERSIST / 'observability.json', Path(__file__)]
    paths.extend(APP / name for name in FINGERPRINT_FILES)
    records = []
    for path in paths:
        try:
            st = path.lstat()
            records.append((st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns))
        except OSError:
            records.append(None)
    return hashlib.sha256(json.dumps(records).encode()).hexdigest()[:20]


DEVICE_FIELDS = ('bridge', 'portal_ip', 'ps5_ip')


def validate_devices(values):
    if set(values) != set(DEVICE_FIELDS) or any(not isinstance(v, str) or len(v) > 80 for v in values.values()):
        raise ValueError('请填写 LAN 网桥与两台设备的 IPv4 地址')
    if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', values['bridge']):
        raise ValueError('请选择有效的 LAN 网桥')
    result = dict(values)
    for role in ('portal', 'ps5'):
        try:
            ip = ipaddress.IPv4Address(values[role + '_ip'])
            if (ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_reserved
                    or int(ip) < 0x01000000 or ip in ipaddress.IPv4Network('169.254.0.0/16')):
                raise ValueError()
        except ipaddress.AddressValueError:
            raise ValueError('请填写有效的设备内网 IPv4 地址') from None
        except ValueError:
            raise ValueError('请填写有效的设备内网 IPv4 地址') from None
        result[role + '_ip'] = str(ip)
    if result['portal_ip'] == result['ps5_ip']:
        raise ValueError('Portal 与 PS5 需要分别使用独立地址')
    return result


def device_binding(values=None):
    """Shared device identity works before the bitrate relay is enrolled."""
    try:
        values = uci_values() if values is None else values
        config = validate_devices({key: values.get(key, '') for key in DEVICE_FIELDS})
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        return {}
    for name in ('devices.json', 'auto-config.json'):
        try:
            if (PERSIST / name).stat().st_size > 16384:
                continue
            binding = read_json(PERSIST / name)
            matches = (binding.get('config') == config if name == 'devices.json' else
                       binding.get('network') == {'interface': IFACE, 'ps5_ip': config['ps5_ip'],
                                                  'portal_ip': config['portal_ip']})
            macs = {role + '_mac': binding.get(role + '_mac', '').lower() for role in ('portal', 'ps5')}
            if (matches and len(set(macs.values())) == 2 and all(
                    re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac)
                    and not int(mac[:2], 16) & 1 and mac != '00:00:00:00:00:00' for mac in macs.values())):
                return dict(config=config, confirmed_at=binding.get('confirmed_at'), **macs)
        except (OSError, ValueError, TypeError, AttributeError):
            pass
    return {}


@dataclass(frozen=True)
class Settings:
    bridge: str
    address: str
    ps5_ip: str
    portal_ip: str
    profile: str = '65'

    def validate(self):
        if not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', self.bridge):
            raise ValueError('请选择有效的 LAN 网桥')
        if self.profile not in PROFILES:
            raise ValueError('请选择 35、45、65、100 或 200 Mbps 档位')
        if '/' not in self.address:
            raise ValueError('请填写中继独立地址和前缀，例如 192.168.1.250/24')
        local = ipaddress.IPv4Interface(self.address)
        peers = [ipaddress.IPv4Address(self.ps5_ip), ipaddress.IPv4Address(self.portal_ip)]
        addresses = [local.ip] + peers
        if local.network.prefixlen > 30 or len(set(addresses)) != 3:
            raise ValueError('Portal、PS5 和中继应使用同一 LAN 内的三个独立 IPv4 地址')
        for ip in addresses:
            if (ip not in local.network or ip in (local.network.network_address, local.network.broadcast_address)
                    or ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_reserved
                    or int(ip) < 0x01000000 or ip in ipaddress.IPv4Network('169.254.0.0/16')):
                raise ValueError('Portal、PS5 和中继地址需属于同一 LAN，且使用可用的单播 IPv4 地址')
        return self

    @classmethod
    def load(cls):
        values = uci_values()
        return cls(**{k: values.get(k, '65' if k == 'profile' else '')
                      for k in cls.__dataclass_fields__}).validate()

    def engine(self):
        return {'interface': IFACE, 'ps5_ip': self.ps5_ip, 'portal_ip': self.portal_ip}


@contextmanager
def exclusive():
    RUNTIME.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (RUNTIME / 'supervisor.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ControllerBusy('A relay or management command is active. Stop it first.') from None
        yield


def ns_command(*args, check=True):
    return command('ip', 'netns', 'exec', NS, *args, check=check)


def pids():
    if not HANDLE.exists():
        return []
    try:
        return [int(x) for x in command('ip', 'netns', 'pids', NS, timeout=2).stdout.split()]
    except subprocess.SubprocessError:
        if not HANDLE.exists():
            return []  # Namespace deletion can race a read-only status request.
        raise


def process_identity(pid):
    try:
        fields = Path('/proc', str(int(pid)), 'stat').read_text().rpartition(')')[2].split()
        return fields[19] if fields[0] != 'Z' else None
    except (OSError, ValueError, TypeError, IndexError):
        return None


def resource_ownership():
    """Validate each surviving resource independently after partial teardown."""
    link = SYSNET / HOST
    result = {'namespace_present': HANDLE.exists(), 'link_present': link.exists(),
              'namespace_owned': False, 'link_owned': False}
    try:
        state = read_json(RUNTIME / 'namespace.json')
        if result['namespace_present']:
            st = HANDLE.stat()
            result['namespace_owned'] = [st.st_dev, st.st_ino] == state.get('handle')
        if result['link_present']:
            result['link_owned'] = ((link / 'ifalias').read_text().strip() == ALIAS
                                   and int((link / 'ifindex').read_text()) == state.get('ifindex'))
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    return result


def owned():
    state = resource_ownership()
    return state['namespace_owned'] and state['link_owned']


def assert_owned_resources(state):
    if ((state['namespace_present'] and not state['namespace_owned'])
            or (state['link_present'] and not state['link_owned'])):
        raise RuntimeError('Namespace/link ownership is unknown; leaving network resources untouched.')


def teardown():
    """Only remove this supervisor's resources, after all recovery processes exit."""
    state = resource_ownership()
    if not state['namespace_present'] and not state['link_present']:
        (RUNTIME / 'namespace.json').unlink(missing_ok=True)
        return
    assert_owned_resources(state)
    if state['namespace_present'] and pids():
        raise RuntimeError('Recovery processes remain. Namespace retained; retry repair after they exit.')
    if (RUNTIME / 'recovery-required').exists():
        raise RuntimeError('设备连接仍待恢复，已保留网络资源，请重试恢复。')
    if state['link_present']:
        command('ip', 'link', 'delete', HOST)
    if state['namespace_present']:
        command('ip', 'netns', 'delete', NS)
    (RUNTIME / 'namespace.json').unlink(missing_ok=True)


def setup(settings):
    settings.validate()
    bridge = SYSNET / settings.bridge
    if not (bridge / 'bridge').is_dir():
        raise RuntimeError('Select an existing LAN bridge (usually br-lan), not a WAN or Wi-Fi device.')
    if HANDLE.exists() or (SYSNET / HOST).exists():
        raise RuntimeError('Previous or foreign namespace/link exists. Run ps-accel repair first.')
    # Catch a relay IP already assigned to the router before creating anything.
    local = ipaddress.IPv4Interface(settings.address)
    assigned = json.loads(command('ip', '-j', '-4', 'addr', 'show').stdout)
    if any(a.get('local') in (str(local.ip), settings.ps5_ip, settings.portal_ip)
           for row in assigned for a in row.get('addr_info', [])):
        raise RuntimeError('An address is already assigned to this router; choose a free relay IP.')
    created_ns = created_link = False
    try:
        command('ip', 'netns', 'add', NS)
        created_ns = True
        st = HANDLE.stat()
        host_st = Path('/proc/self/ns/net').stat()
        namespace_state = {'handle': [st.st_dev, st.st_ino],
                           'host_handle': [host_st.st_dev, host_st.st_ino],
                           'settings': asdict(settings)}
        atomic(RUNTIME / 'namespace.json', namespace_state)
        command('ip', 'link', 'add', HOST, 'type', 'veth', 'peer', 'name', PEER)
        created_link = True
        command('ip', 'link', 'set', HOST, 'alias', ALIAS)
        atomic(RUNTIME / 'namespace.json', dict(namespace_state,
               ifindex=int((SYSNET / HOST / 'ifindex').read_text())))
        command('ip', 'link', 'set', PEER, 'netns', NS)
        command('ip', '-n', NS, 'link', 'set', PEER, 'name', IFACE)
        # Match the bridge MTU, e.g. on a LAN using jumbo frames.
        mtu = (bridge / 'mtu').read_text().strip()
        command('ip', 'link', 'set', HOST, 'mtu', mtu)
        command('ip', '-n', NS, 'link', 'set', IFACE, 'mtu', mtu)
        command('ip', '-n', NS, 'link', 'set', 'lo', 'up')
        command('ip', '-n', NS, 'link', 'set', IFACE, 'up')
        command('ip', 'link', 'set', HOST, 'master', settings.bridge)
        command('ip', 'link', 'set', HOST, 'up')
        # This internal operation checks the namespace identity before sysctl writes.
        ns_command(sys.executable, __file__, '_init')
        # Probe BEFORE assigning the IP, so it cannot answer its own conflict probe.
        ns_command(sys.executable, __file__, '_probe', '--address', settings.address)
        command('ip', '-n', NS, 'addr', 'add', settings.address, 'dev', IFACE)
    except BaseException:
        cleanup_failed = False
        if created_link:
            try:
                cleanup_failed |= command('ip', 'link', 'delete', HOST, check=False).returncode != 0
            except (OSError, subprocess.SubprocessError):
                cleanup_failed = True
        if created_ns:
            try:
                cleanup_failed |= command('ip', 'netns', 'delete', NS, check=False).returncode != 0
            except (OSError, subprocess.SubprocessError):
                cleanup_failed = True
        if not cleanup_failed:
            (RUNTIME / 'namespace.json').unlink(missing_ok=True)
        raise


def assert_namespace():
    state = read_json(RUNTIME / 'namespace.json')
    current = Path('/proc/self/ns/net').stat()
    if ([current.st_dev, current.st_ino] != state['handle']
            or [current.st_dev, current.st_ino] == state['host_handle']):
        raise RuntimeError('Refusing internal operation outside the owned relay namespace')


def internal(action, args):
    assert_namespace()
    if action == '_init':
        # All paths are namespace-scoped. No sysctl is written on the router.
        for name in ('ip_forward', f'conf/{IFACE}/forwarding',
                     'conf/all/send_redirects', f'conf/{IFACE}/send_redirects'):
            Path('/proc/sys/net/ipv4', name).write_text('0\n')
        ipv6 = Path('/proc/sys/net/ipv6/conf', IFACE, 'disable_ipv6')
        if ipv6.exists():
            ipv6.write_text('1\n')
        return
    from scapy.all import ARP, Ether, get_if_hwaddr, srp
    if action == '_probe':
        address = str(ipaddress.IPv4Interface(args.address).ip)
        mac = get_if_hwaddr(IFACE)
        replies, _ = srp(Ether(src=mac, dst='ff:ff:ff:ff:ff:ff') /
                         ARP(hwsrc=mac, psrc='0.0.0.0', pdst=address),
                         iface=IFACE, timeout=2, retry=1, verbose=False)
        if any(ARP in r and r[ARP].psrc == address for _, r in replies):
            raise RuntimeError('The relay IP responded to ARP. Choose a free address outside DHCP.')
        return
    import portal_auto as engine
    if action == '_enroll':
        settings = Settings(**read_json(RUNTIME / 'namespace.json')['settings']).validate()
        config = {'network': settings.engine(), 'profile': settings.profile}
        state = engine.net.state_for(config, enroll=True)
        config.update(ps5_mac=state['ps5_mac'], portal_mac=state['portal_mac'])
        atomic(PERSIST / 'auto-config.json', config)
    elif action == '_repair':
        state = read_json(RUNTIME / 'restore-state.json')
        settings = Settings(**read_json(RUNTIME / 'namespace.json')['settings']).validate()
        if state['config'] != settings.engine():
            raise RuntimeError('Recovery data does not match this namespace; no ARP packets sent.')
        engine.net.configure(state['config'])
        errors = engine.restore_peer(state)
        if errors:
            raise RuntimeError('; '.join(errors))
        (RUNTIME / 'recovery-required').unlink(missing_ok=True)


def verify_configuration(settings):
    """A saved device pair and matching relay settings are sufficient to start."""
    import portal_auto as engine
    settings.validate()
    config = engine.config(PERSIST / 'auto-config.json')
    if config['network'] != settings.engine() or config['profile'] != settings.profile:
        raise RuntimeError('设备地址或码率配置已变化，请重新保存码率增强配置')
    binding = device_binding(asdict(settings))
    if not binding or any(binding[role + '_mac'] != config[role + '_mac'] for role in ('portal', 'ps5')):
        raise RuntimeError('请重新确认设备身份，保存设备配置后再保存码率增强配置')
    return config


def port_fingerprint(settings, config=None, engine_fingerprint=None):
    import portal_auto as engine
    from scapy import VERSION
    if config is None:
        config = engine.config(PERSIST / 'auto-config.json')
    if config['network'] != settings.engine() or config['profile'] != settings.profile:
        raise RuntimeError('UCI and enrollment differ. Run configure again.')
    digest = hashlib.sha256(Path(__file__).read_bytes())
    binding = {key: value for key, value in asdict(settings).items() if key != 'profile'}
    digest.update(json.dumps(binding, sort_keys=True).encode())
    digest.update((engine_fingerprint if engine_fingerprint is not None else engine.fingerprint(config)).encode())
    digest.update((VERSION + ':' + sys.version.split()[0]).encode())
    return digest.hexdigest()


def baseline_receipt(settings):
    receipt = read_json(PERSIST / 'baseline.json')
    import portal_auto as engine
    config = engine.config(PERSIST / 'auto-config.json')
    fingerprint = engine.fingerprint(config)
    if receipt['port_fingerprint'] != port_fingerprint(settings, config, fingerprint):
        raise RuntimeError('Baseline is for different code/configuration. Run baseline again.')
    upstream = receipt['upstream']
    if (upstream['fingerprint'] != fingerprint or
            type(upstream['forwarded_out']) is not int or upstream['forwarded_out'] <= 0 or
            upstream['restored'] is not True):
        raise RuntimeError('连接测试记录需要重新验证，请重新完成连接测试。')
    return receipt


def baseline_state(settings=None):
    if not (PERSIST / 'baseline.json').exists():
        return {'valid': False, 'reason': '尚未完成连接测试'}
    try:
        baseline_receipt(settings or Settings.load())
        return {'valid': True, 'reason': '设备、网桥与代码校验通过'}
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
        return {'valid': False, 'reason': '配置或程序已变化，请重新测试'}


def verify_baseline(settings):
    receipt = baseline_receipt(settings)
    atomic(RUNTIME / 'auto-baseline.json', receipt['upstream'])


def set_profile(profile):
    if profile not in PROFILES:
        raise ValueError('目标码率档位无效')
    if ENGINE_LOCK.exists() or HANDLE.exists() or (RUNTIME / 'recovery-required').exists():
        raise RuntimeError('请先停止中继并完成网络恢复，再保存码率。')
    import portal_auto as engine
    settings = Settings.load()
    config_path = PERSIST / 'auto-config.json'
    original = engine.config(config_path)
    if original['network'] != settings.engine() or original['profile'] != settings.profile:
        raise RuntimeError('设备配对与配置需要同步，请重新检测设备。')
    atomic(config_path, dict(original, profile=profile))
    try:
        command('uci', 'set', 'ps_accel.main.profile=' + profile)
        command('uci', 'commit', 'ps_accel')
    except BaseException:
        atomic(config_path, original)
        command('uci', 'set', 'ps_accel.main.profile=' + settings.profile, check=False)
        command('uci', 'commit', 'ps_accel', check=False)
        raise
    print(f'目标码率已保存为 {profile} Mbps，连接测试记录保留。启动中继后重新连接 Portal。')


def wait_for_bridge(settings, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        bridge = SYSNET / settings.bridge
        try:
            if (bridge / 'bridge').is_dir() and int((bridge / 'flags').read_text().strip(), 0) & 1:
                return
        except (OSError, ValueError):
            pass
        time.sleep(.5)
    raise RuntimeError(f'等待 {settings.bridge} 就绪超时，请检查主路由的 LAN 网桥。')


def environment():
    def read(path, fallback=''):
        try:
            return Path(path).read_text().strip()
        except OSError:
            return fallback
    release = read('/etc/openwrt_release')
    def release_field(name):
        match = re.search(r'^' + name + r"=['\"]([^'\"]*)['\"]$", release, re.M)
        return match.group(1) if match else ''
    return {'version': APP_VERSION, 'model': read('/tmp/sysinfo/model', 'OpenWrt 主路由'),
            'architecture': os.uname().machine, 'kernel': os.uname().release,
            'firmware': release_field('DISTRIB_DESCRIPTION'), 'target': release_field('DISTRIB_TARGET'),
            'package_manager': 'apk' if shutil.which('apk') else 'opkg' if shutil.which('opkg') else '未知',
            'host_forwarding': read('/proc/sys/net/ipv4/ip_forward', '未知')}


def clear_engine_lock():
    if ENGINE_LOCK.exists():
        pid_file = RUNTIME / 'engine-pid'
        if not pid_file.exists() or ENGINE_LOCK.read_text().strip() != pid_file.read_text().strip():
            raise RuntimeError('A different relay owns the upstream lock; left untouched.')
        ENGINE_LOCK.unlink()


def repair_existing():
    state = resource_ownership()
    if not state['namespace_present'] and not state['link_present']:
        if (RUNTIME / 'recovery-required').exists():
            raise RuntimeError('Recovery namespace is missing. Reconnect Portal, then reboot the router.')
        clear_engine_lock()
        teardown()
        return
    assert_owned_resources(state)
    if state['namespace_present'] and pids():
        raise RuntimeError('Namespace is unowned or still has active processes. Stop the service first.')
    if state['namespace_present'] and state['link_present'] and (RUNTIME / 'restore-state.json').exists():
        # Wait out Linux ARP locktime; repeat even if guardian already repaired it.
        time.sleep(1.5)
        ns_command(sys.executable, __file__, '_repair')
    elif (RUNTIME / 'recovery-required').exists():
        raise RuntimeError('恢复所需的网络路径已变化，请重新连接 Portal 后检查恢复。')
    clear_engine_lock()
    teardown()


def stop_and_repair(timeout=90):
    command('/etc/init.d/ps-accel', 'stop')
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with exclusive():
                if not pids():
                    repair_existing()
                    print('中继已停止，网络恢复完成。', flush=True)
                    return
        except ControllerBusy:
            pass
        time.sleep(.25)
    raise RuntimeError('服务仍在退出，恢复路径已保留。请稍后重试停止。')


def supervise(settings, mode, seconds=None):
    if ENGINE_LOCK.exists():
        raise RuntimeError('Another relay or stale recovery lock exists. Stop it or run repair.')
    if (RUNTIME / 'recovery-required').exists():
        raise RuntimeError('Previous recovery is unconfirmed. Run repair first.')
    if mode == 'run':
        verify_configuration(settings)
    # Old restore data must never be used to repair a newly configured peer pair.
    for name in ('restore-state.json', 'status.json', 'recovery.json', 'engine-pid', 'engine.json', 'engine-ready.json', 'disabled'):
        (RUNTIME / name).unlink(missing_ok=True)
    child = None
    interrupted = False

    def stop(_sig, _frame):
        nonlocal interrupted
        interrupted = True
        if child is not None and child.poll() is None:
            child.send_signal(signal.SIGTERM)

    old = {sig: signal.signal(sig, stop) for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)}
    try:
        setup(settings)
        generation = uuid.uuid4().hex
        argv = ['ip', 'netns', 'exec', NS, sys.executable, '-u', str(APP / 'portal_auto.py'),
                mode, '--config', str(PERSIST / 'auto-config.json'), '--runtime', str(RUNTIME),
                '--preferences', str(PERSIST / 'observability.json'),
                '--generation', generation]
        if mode == 'run':
            argv.append('--configured-start')
        if seconds is not None:
            argv += ['--seconds', str(seconds)]
        if interrupted:
            return 0
        child = subprocess.Popen(argv, start_new_session=True)
        try:
            (RUNTIME / 'engine-pid').write_text(str(child.pid))
            atomic(RUNTIME / 'engine.json', {'pid': child.pid, 'identity': process_identity(child.pid),
                   'generation': generation,
                   'started_monotonic': time.monotonic(), 'mode': 'baseline' if mode == 'baseline' else 'active'})
        except BaseException:
            if child.poll() is None:
                child.send_signal(signal.SIGTERM)
            child.wait(timeout=90)
            raise
        rc = child.wait()
        # Guardian is in a separate session; do not remove its Ethernet path early.
        deadline = time.monotonic() + 40
        while pids() and time.monotonic() < deadline:
            time.sleep(.25)
        repair_existing()
        if mode == 'baseline' and interrupted:
            (PERSIST / 'baseline.json').unlink(missing_ok=True)
            (RUNTIME / 'auto-baseline.json').unlink(missing_ok=True)
            print('Baseline cancelled; no baseline receipt saved.', flush=True)
        if mode == 'baseline' and rc == 0 and not interrupted:
            import portal_auto as engine
            config = engine.config(PERSIST / 'auto-config.json')
            if not engine.baseline_valid(config, RUNTIME):
                raise RuntimeError('No relayed traffic observed; baseline was not saved.')
            atomic(PERSIST / 'baseline.json', {'port_fingerprint': port_fingerprint(settings),
                   'upstream': read_json(RUNTIME / 'auto-baseline.json')})
            print('Baseline saved. Check picture/controls, then run: ps-accel try', flush=True)
        return rc
    finally:
        try:
            if owned() and not pids() and not (RUNTIME / 'recovery-required').exists():
                repair_existing()
        finally:
            for sig, handler in old.items():
                signal.signal(sig, handler)


def configure(settings):
    settings.validate()
    if ENGINE_LOCK.exists() or (RUNTIME / 'recovery-required').exists():
        raise RuntimeError('Stop/repair the existing relay before changing the configuration.')
    setup(settings)
    try:
        result = ns_command(sys.executable, __file__, '_enroll')
        if result.stdout:
            print(result.stdout, end='')
        for key, value in asdict(settings).items():
            command('uci', 'set', f'ps_accel.main.{key}={value}')
        command('uci', 'set', 'ps_accel.main.enabled=0')
        command('uci', 'commit', 'ps_accel')
        enrollment = read_json(PERSIST / 'auto-config.json')
        atomic(PERSIST / 'devices.json', {
            'config': {key: asdict(settings)[key] for key in DEVICE_FIELDS},
            'portal_mac': enrollment['portal_mac'], 'ps5_mac': enrollment['ps5_mac'],
            'confirmed_at': time.time()})
        (PERSIST / 'baseline.json').unlink(missing_ok=True)
        (RUNTIME / 'auto-baseline.json').unlink(missing_ok=True)
        print('设备配对完成。进入 LuCI 启动增强，启动后重新连接 Portal。')
    finally:
        teardown()


def doctor():
    print('Python:', sys.version.split()[0])
    print('Host IPv4 forwarding (read only):', Path('/proc/sys/net/ipv4/ip_forward').read_text().strip())
    print('ip:', command('ip', '-Version').stdout.strip())
    command('ip', 'netns', 'list')
    from scapy import VERSION
    from scapy.arch.common import compile_filter
    from scapy.data import DLT_EN10MB
    compile_filter('ether dst 02:00:00:00:00:01 and ip', linktype=DLT_EN10MB)
    print('Scapy:', VERSION, '; libpcap BPF compile: OK')
    print('Kernel NET_NS:', Path('/proc/self/ns/net').exists())
    print('Namespace present:', HANDLE.exists(), '; owned:', owned(), '; processes:', pids())
    print('Service enabled:', uci_get('enabled', '0'))
    print('Doctor is read-only. configure checks veth support, bridge and peer reachability.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['configure', 'profile', 'baseline', 'try', 'service', 'stop', 'status',
                        'doctor', 'repair', '_init', '_probe', '_enroll', '_repair'])
    parser.add_argument('--bridge', default='br-lan')
    parser.add_argument('--address')
    parser.add_argument('--ps5', dest='ps5_ip')
    parser.add_argument('--portal', dest='portal_ip')
    parser.add_argument('--profile', default='65', choices=PROFILES)
    parser.add_argument('--seconds', type=int)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        parser.error('Run as root on OpenWrt.')
    os.umask(0o077)
    if args.action.startswith('_'):
        return internal(args.action, args) or 0
    if args.action == 'doctor':
        doctor()
        return 0
    if args.action == 'stop':
        stop_and_repair()
        return 0
    if args.action == 'status':
        for name in ('status.json', 'recovery.json'):
            path = RUNTIME / name
            if path.exists():
                print(name + ':\n' + path.read_text())
        print('Namespace present:', HANDLE.exists(), '; processes:', pids())
        print('Recovery required:', (RUNTIME / 'recovery-required').exists())
        print('Reports can be stale. Also check: /etc/init.d/ps-accel running')
        return 0
    with exclusive():
        if args.action == 'profile':
            set_profile(args.profile)
            return 0
        if args.action == 'repair':
            repair_existing()
            return 0
        if args.action == 'configure':
            configure(Settings(args.bridge, args.address or '', args.ps5_ip or '',
                               args.portal_ip or '', args.profile))
            return 0
        settings = Settings.load()
        if args.action == 'service' and uci_get('enabled', '0') != '1':
            print('服务已停用。进入 LuCI 保存配置后启动增强。')
            return 0
        if args.action == 'service':
            print('正在等待主路由 LAN 网桥就绪…', flush=True)
            wait_for_bridge(settings)
        if args.action == 'baseline':
            (PERSIST / 'baseline.json').unlink(missing_ok=True)
            (RUNTIME / 'auto-baseline.json').unlink(missing_ok=True)
        return supervise(settings, 'baseline' if args.action == 'baseline' else 'run', args.seconds)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as exc:
        from observability import record_failure
        record_failure(RUNTIME, PERSIST, 'supervisor', str(exc))
        if isinstance(exc, subprocess.CalledProcessError):
            print(exc.stderr.strip(), file=sys.stderr)
        print('ps-accel: ' + str(exc), file=sys.stderr)
        sys.exit(1)
