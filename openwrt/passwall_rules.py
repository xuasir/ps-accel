"""Maintain PassWall's native domain lists and observe existing core interfaces."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import signal
import stat
import subprocess
import tempfile
import time

import portal_openwrt as port
import portal_policy as legacy
from observability import load_preferences
from proxy_telemetry import ConnectionTracker
from sony_domains import (DYNAMIC_PROXY_RULES, matches_domain, native_host as valid_host,
                         native_host_rules as host_rules, native_matches as matches)

FIELDS = ('domains', 'exclusions')
FILE_NAMES = {'domains': 'proxy_host', 'exclusions': 'direct_host'}
RULE_ROOTS = (Path('/etc/passwall/rules'), Path('/usr/share/passwall/rules'))
RULE_SOURCES = (Path('/usr/lib/lua/luci/model/cbi/passwall/client/rule_list.lua'),
                Path('/usr/share/passwall/helper_dnsmasq.lua'))
SERVICE = '/etc/init.d/passwall'
PROC = Path('/proc')
LIVE_ROOT = Path('/tmp/etc/passwall')
LIST_BYTES = 256 * 1024
MAX_RULES = 4096
TRAFFIC_LIMIT = '按批次累计本机已有连接接口的字节增量。设备直达流量与采样间完成的短连接影响覆盖。'


def runtime():
    return port.RUNTIME / 'psportal'


def normalize(request):
    result = {}
    for key in FIELDS:
        text = request.get(key)
        if not isinstance(text, str) or len(text.encode('utf-8')) > LIST_BYTES:
            raise ValueError('每份域名名单限 256 KiB')
        lines, seen, count = [], set(), 0
        for line in text.splitlines():
            name = line.strip()
            if not name or name.startswith('#'):
                lines.append(name)
                continue
            if name.lower().startswith('geosite:'):
                if not re.fullmatch(r'geosite:[a-zA-Z0-9_@!:.\-]{1,240}', name):
                    raise ValueError('geosite: 规则请使用本机 PassWall 支持的标签')
            else:
                name = name.lower().removeprefix('full:').rstrip('.')
                if not valid_host(name):
                    raise ValueError('每行填写一个完整域名，例如 example.com；动态域名请从监控中选择实测主机名')
            if name in seen:
                continue
            seen.add(name)
            count += 1
            lines.append(name)
        if count > MAX_RULES:
            raise ValueError('每份域名名单最多 4096 条规则')
        result[key] = '\n'.join(lines).rstrip('\n') + ('\n' if any(lines) else '')
        if len(result[key].encode('utf-8')) > LIST_BYTES:
            raise ValueError('每份域名名单限 256 KiB')
    return result


def metadata():
    """Read scalar global switches and node core types from UCI."""
    result = port.command('uci', '-q', 'show', 'passwall', check=False, timeout=4)
    if result.returncode:
        raise RuntimeError('请安装并保存本机 PassWall 配置后，重新读取名单')
    sections = {}
    fields = {'enabled', 'node', 'tcp_node', 'udp_node', 'type',
              'use_proxy_list', 'use_direct_list', 'client_proxy', 'acl_enable'}
    for line in result.stdout.splitlines():
        key, separator, raw = line.partition('=')
        parts = key.split('.', 2)
        if not separator or len(parts) < 2 or parts[0] != 'passwall':
            continue
        if len(parts) == 3 and parts[2] not in fields:
            continue
        values = shlex.split(raw)
        sections.setdefault(parts[1], {})[parts[2] if len(parts) == 3 else '.type'] = values[0] if len(values) == 1 else ''
    config = next((row for row in sections.values() if row.get('.type') == 'global'), None)
    if config is None:
        raise RuntimeError('PassWall 全局配置待就绪，请在 PassWall 保存配置后重新读取')
    cores = sorted({sections.get(config.get(key, ''), {}).get('type', '')
                    for key in ('node', 'tcp_node', 'udp_node')} - {''})
    return {'enabled': config.get('enabled') == '1', 'cores': cores,
            'proxy_list_enabled': config.get('use_proxy_list', '1') == '1',
            'direct_list_enabled': config.get('use_direct_list', '1') == '1',
            'client_proxy': config.get('client_proxy', '1') == '1',
            'acl_enabled': config.get('acl_enable', '0') == '1'}


def rule_root():
    """Prefer installed list readers; the legacy directory also holds geo assets."""
    for source in RULE_SOURCES:
        try:
            if source.stat().st_size > 1024 * 1024:
                continue
            text = source.read_text()
        except (OSError, ValueError):
            continue
        if 'proxy_host' not in text:
            continue
        for prefix, root in zip(('/etc/', '/usr/share/'), RULE_ROOTS):
            if prefix + 'passwall/rules/' in text or prefix + '%s/rules/' in text:
                return root.resolve()
    return next((root.resolve() for root in RULE_ROOTS
                 if any((root / name).exists() for name in FILE_NAMES.values())), RULE_ROOTS[0].resolve())


def files(root):
    result = {}
    for key, name in FILE_NAMES.items():
        path = root / name
        if path.is_symlink():
            raise RuntimeError('域名名单文件使用了符号链接，请在 PassWall 确认其存储路径')
        try:
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > LIST_BYTES:
                raise ValueError('PassWall 域名名单容量或文件类型需要检查')
            data = path.read_bytes()
            if len(data) > LIST_BYTES:
                raise ValueError('PassWall 域名名单超过 256 KiB')
            data.decode('utf-8')
            result[key] = {'data': data, 'mode': stat.S_IMODE(info.st_mode)}
        except FileNotFoundError:
            result[key] = {'data': None, 'mode': 0o644}
    return result


def revision(root, values):
    value = {'root': str(root), 'files': {key: row['data'].decode('utf-8') if row['data'] is not None else None
                                        for key, row in values.items()}}
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def configuration():
    if not Path(SERVICE).is_file():
        raise RuntimeError('请安装本机 PassWall 后，重新读取名单')
    info, root = metadata(), rule_root()
    values = files(root)
    config = {key: (row['data'] or b'').decode('utf-8') for key, row in values.items()}
    return info, root, values, config, revision(root, values)


@contextmanager
def lock():
    runtime().mkdir(parents=True, exist_ok=True, mode=0o700)
    with (runtime() / 'native-rules.lock').open('a') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('PassWall 名单正在更新，请稍后重试') from None
        yield


def write_bytes(path, content, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '.ps-accel-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def has_content(path, content):
    if path.is_symlink():
        return False
    try:
        with path.open('rb') as stream:
            return stream.read(LIST_BYTES + 1) == content
    except FileNotFoundError:
        return content is None


def live_cores():
    """Read only running PassWall-owned configs; credentials stay in this process."""
    result, seen = [], set()
    try:
        processes = list(PROC.iterdir())
    except OSError:
        return result
    for process in processes:
        if not process.name.isdigit():
            continue
        try:
            args = [value.decode(errors='replace') for value in (process / 'cmdline').read_bytes().split(b'\0') if value]
            binary = Path(args[0]).name if args else ''
            kind = 'sing-box' if 'sing-box' in binary else 'xray' if 'xray' in binary else ''
            if not kind:
                continue
            candidates = []
            for index, value in enumerate(args):
                if value in ('-c', '--config', '-config') and index + 1 < len(args):
                    candidates.append(Path(args[index + 1]))
                elif value.startswith(('-c=', '--config=', '-config=')):
                    candidates.append(Path(value.partition('=')[2]))
            for path in candidates:
                path = path.resolve()
                if not path.is_relative_to(LIVE_ROOT.resolve()) or path in seen or path.stat().st_size > 1024 * 1024:
                    continue
                config = json.loads(path.read_text())
                if not isinstance(config, dict):
                    continue
                seen.add(path)
                key = hashlib.sha256((str(path) + ':' + process.name + ':' +
                                      str(port.process_identity(int(process.name)))).encode()).hexdigest()[:24]
                result.append({'type': kind, 'key': key, 'config': config})
        except (OSError, ValueError, IndexError):
            continue
    return result[:8]


def status():
    try:
        info, root, values, config, current = configuration()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        return {'ok': True, 'available': False, 'config': dict.fromkeys(FIELDS, ''),
                'blockers': [str(exc)], 'warnings': [], 'revision': ''}
    receipt = legacy.read(port.PERSIST / 'passwall-lists-receipt.json')
    draft = legacy.read(port.PERSIST / 'passwall-lists-migration.json')
    migration = draft.get('base_revision') == current and isinstance(draft.get('config'), dict)
    warnings = []
    for key, label in (('proxy_list_enabled', '代理'), ('direct_list_enabled', '直连')):
        if not info[key]:
            warnings.append('PassWall 的' + label + '名单开关当前关闭，请在 PassWall 启用后使用这份名单')
    if migration:
        warnings.append('旧透明代理域名已整理为待保存草稿，保存并应用后按 PassWall 当前接管范围生效')
        if draft.get('skipped_rules'):
            warnings.append('动态规则已按实测完整域名迁移，待观测规则可从域名监控逐项加入')
    cores = live_cores()
    telemetry = legacy.read(runtime() / 'connections.json')
    telemetry['fresh'] = type(telemetry.get('epoch')) in (int, float) and 0 <= time.time() - telemetry['epoch'] < 15
    return {'ok': True, 'available': True, 'mode': 'native_lists', 'revision': current,
            'config': draft['config'] if migration else config, 'file_config': config,
            'config_source': 'migration' if migration else 'passwall',
            'enabled': info['enabled'], 'running': bool(cores), 'switches': info,
            'environment': {'cores': sorted({item['type'] for item in cores}) or info['cores'],
                            'rules_path': str(root)},
            'counts': {key: len(host_rules(text)) for key, text in config.items()},
            'pending_apply': bool(migration or receipt and (receipt.get('pending_apply') or
                                  receipt.get('applied_revision') != current)),
            'receipt': receipt, 'blockers': [], 'warnings': warnings,
            'telemetry': {key: telemetry.get(key) for key in ('state', 'fresh', 'sampled_cores', 'limit', 'errors')}}


def reload_passwall():
    process = subprocess.Popen([SERVICE, 'reload'], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        process.communicate(timeout=55)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
        raise RuntimeError('PassWall 重新加载超时') from None
    if process.returncode:
        raise RuntimeError('PassWall 重新加载失败')


class RulesCancelled(RuntimeError):
    pass


def persist(request, apply=False, cancel=lambda: False):
    config = normalize(request)
    expected = request.get('revision')
    if not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected):
        raise ValueError('请重新读取本机 PassWall 名单后保存')
    with lock():
        info, root, previous, _config, current = configuration()
        if current != expected:
            raise RuntimeError('PassWall 名单已被其他页面修改，请重新读取后再保存')
        if cancel():
            raise RulesCancelled('名单应用已取消')
        intended = {key: {'data': text.encode('utf-8'), 'mode': previous[key]['mode']} for key, text in config.items()}
        new_revision = revision(root, intended)
        written = []
        reloaded = False
        reload_attempted = False
        running = bool(apply and info['enabled'] and live_cores())
        receipt_path = port.PERSIST / 'passwall-lists-receipt.json'
        receipt = legacy.read(receipt_path)
        try:
            for key in FIELDS:
                path = root / FILE_NAMES[key]
                if files(root)[key]['data'] != previous[key]['data']:
                    raise RuntimeError('保存期间 PassWall 名单发生了外部修改，请重新读取')
                if intended[key]['data'] != previous[key]['data']:
                    write_bytes(path, intended[key]['data'], intended[key]['mode'])
                    written.append(key)
            if revision(root, files(root)) != new_revision:
                raise RuntimeError('保存期间 PassWall 名单发生了外部修改，请重新读取')
            if cancel():
                raise RulesCancelled('名单应用已取消，原名单已恢复')
            if running:
                # Re-read the switch immediately before reload to preserve a manual stop.
                if metadata()['enabled'] and live_cores():
                    reload_attempted = True
                    reload_passwall()
                    reloaded = True
            if revision(root, files(root)) != new_revision:
                raise RuntimeError('应用期间 PassWall 名单发生了外部修改，请重新读取')
            if cancel():
                raise RulesCancelled('名单应用已取消，原名单已恢复')
            pending = not reloaded and (bool(written) or receipt.get('pending_apply') or
                                        receipt.get('applied_revision') != new_revision)
            updated = dict(receipt, state='applied' if reloaded else 'saved', time=time.time(),
                           saved_revision=new_revision, pending_apply=pending, reloaded=reloaded)
            if reloaded:
                updated.update(applied_revision=new_revision, applied_at=time.time())
            port.atomic(receipt_path, updated)
        except Exception as exc:
            for key in reversed(written):
                path = root / FILE_NAMES[key]
                if has_content(path, intended[key]['data']):
                    if previous[key]['data'] is None:
                        path.unlink(missing_ok=True)
                    else:
                        write_bytes(path, previous[key]['data'], previous[key]['mode'])
            if reload_attempted and metadata()['enabled']:
                try:
                    reload_passwall()
                except Exception:
                    raise RuntimeError('原名单已恢复，PassWall 运行状态待检查，请在 PassWall 重新加载配置') from exc
            raise
        (port.PERSIST / 'passwall-lists-migration.json').unlink(missing_ok=True)
    notice = ('名单已保存并调用本机 PassWall 重新加载，当前连接可能重连' if reloaded else
              '名单已保存，PassWall 下次启动将加载这份名单' if apply else
              '本机 PassWall 名单已保存，点击“保存并应用”加载修改')
    return {'ok': True, 'revision': new_revision, 'config': config, 'reloaded': reloaded,
            'pending_apply': pending, 'notice': notice}


def save(request):
    return persist(request)


def apply(request, cancel=lambda: False):
    return persist(request, apply=True, cancel=cancel)


def migrate():
    """Retire only the owned legacy hook; import conservative full hosts as a draft."""
    with lock():
        manifest = legacy.read(legacy.folder() / 'manifest.json')
        old = legacy.read(legacy.folder() / 'draft.json') or manifest.get('config', {})
        hooked = legacy.PASSWALL.exists() and legacy.BEGIN in legacy.PASSWALL.read_text()
        if not old and not manifest and not hooked:
            return
        migration_path = port.PERSIST / 'passwall-lists-migration.json'
        if old and not migration_path.exists() and not legacy.read(port.PERSIST / 'passwall-lists-migrated.json'):
            try:
                _info, _root, _files, config, base = configuration()
                observed = legacy.read(port.PERSIST / 'domains.json').get('domains', [])
                names = [row.get('domain', '') for row in observed if isinstance(row, dict) and valid_host(row.get('domain', ''))]
                skipped = []
                for key in FIELDS:
                    hosts = host_rules(config[key])
                    for raw in str(old.get(key, '')).splitlines():
                        name = raw.strip().lower().removeprefix('full:')
                        selected = [name] if valid_host(name) else [host for host in names if matches_domain(host, [name])]
                        if '*' in name and not selected:
                            skipped.append(name)
                        for host in selected:
                            if host not in hosts:
                                config[key] = config[key].rstrip('\n') + ('\n' if config[key] else '') + host + '\n'
                                hosts.append(host)
                for host in names:
                    if matches_domain(host, DYNAMIC_PROXY_RULES) and not matches(host, host_rules(config['exclusions'])) and host not in host_rules(config['domains']):
                        config['domains'] = config['domains'].rstrip('\n') + ('\n' if config['domains'] else '') + host + '\n'
                port.atomic(migration_path, {'base_revision': base, 'config': normalize(config), 'skipped_rules': skipped})
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                # Existing legacy drafts remain available on disk for later recovery.
                pass
        if manifest or hooked:
            legacy.detach()
        port.atomic(port.PERSIST / 'passwall-lists-migrated.json', {'time': time.time()})


def device_sources():
    binding = port.device_binding()
    config = binding.get('config', {})
    if not binding:
        return {}
    devices = legacy.inventory()
    owners = {}
    for device in devices:
        for address in device['addresses']:
            owners.setdefault(address, set()).add(device['mac'])
    return {role: sorted({config[role + '_ip']} | {
        address for row in devices if row['mac'] == binding[role + '_mac'] for address in row['addresses']
        if owners[address] == {row['mac']}}) for role in ('portal', 'ps5')}


def traffic_sample(tracker, cores, sources, config, info, enabled=True):
    scope = dict({key: '\n'.join(host_rules(config.get(key, ''))) for key in FIELDS},
                 mode='native_lists', proxy_list_enabled=info.get('proxy_list_enabled', True),
                 direct_list_enabled=info.get('direct_list_enabled', True))
    readable = [item for item in cores if item['type'] == 'sing-box' and
                item['config'].get('experimental', {}).get('clash_api', {}).get('external_controller')]
    if enabled and sources:
        report = tracker.sample(readable, sources, {'mode': 'native_lists', 'config': scope})
    else:
        report = {'epoch': time.time(), 'generation': tracker.generation, 'connections': [], 'sampled_cores': 0,
                  'state': 'disabled' if not enabled else 'waiting', 'policy_scope': scope}
    report['source'] = 'passwall_core'
    report['core_types'] = sorted({item['type'] for item in cores})
    report['limit'] = TRAFFIC_LIMIT
    if enabled and sources and not report.get('sampled_cores'):
        report['state'] = 'unavailable' if cores else 'waiting'
        report['limit'] = ('当前 Xray 的聚合统计需要域名级连接数据源后，才能按域名累计字节。DNS 与批次记录持续采集。'
                           if 'xray' in report['core_types'] else
                           '等待本机 Sing-box 提供可读的回环 Clash API 连接接口。DNS 与批次记录持续采集。')
    return report


def watch():
    """Telemetry follows local PassWall and domain capture, independently of list edits."""
    tracker, next_config, stopping = ConnectionTracker(), 0, False
    cores, sources, config, info, error = [], {}, dict.fromkeys(FIELDS, ''), {}, ''
    def stop(*_):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopping:
        try:
            preferences = load_preferences(port.PERSIST / 'observability.json')
            if time.monotonic() >= next_config:
                next_config = time.monotonic() + 10
                cores, sources = live_cores(), device_sources()
                try:
                    info, _root, _files, config, _revision = configuration()
                    error = ''
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
                    config, info, error = dict.fromkeys(FIELDS, ''), {}, str(exc)
            report = traffic_sample(tracker, cores, sources, config, info, enabled=preferences.domains)
            if error:
                report['errors'] = [error]
            port.atomic(runtime() / 'connections.json', report)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            pass
        for _ in range(4):
            if stopping:
                break
            time.sleep(.5)


if __name__ == '__main__':
    import sys
    os.umask(0o077)
    if os.geteuid() != 0:
        raise SystemExit('需要 root 权限')
    if sys.argv[1:] == ['watch']:
        watch()
    elif sys.argv[1:] in (['resume'], ['migrate'], ['detach']):
        migrate()
    else:
        raise SystemExit('请选择本机名单迁移或流量观察操作')
