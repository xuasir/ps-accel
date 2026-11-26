"""Legacy policy migration and shared device inventory.

Native domain-list maintenance is implemented in passwall_rules.py. This module
retains the former format so upgrades can detach its owned generator hook.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import signal
import socket
import subprocess
import time
import uuid

import portal_openwrt as port
from proxy_telemetry import (ConnectionTracker, PROBE_TAG, core_key, evidence_revision,
                             loopback_endpoint, outbound_signature, probe)
from sony_domains import (FIRMWARE_HOST,
                         DYNAMIC_PROXY_RULES, domain_rules, domain_matcher, dynamic_rule_info,
                         matches_domain, proxy_rules, rule_excluded)

TAG = 'ps-accel-psportal'
DIRECT_TAG = TAG + '-direct'
PASSWALL = Path('/usr/lib/lua/luci/passwall/util_sing-box.lua')
STOCK_SHA256 = '38d4d247b4dca9f25dbb6753a115e0fa8fa6606b1be5e77ebdffabd9fa43dae4'
ANCHOR = 'if arg[1] then'
BEGIN = '-- PS_ACCEL_PSPORTAL_BEGIN\n'
END = '-- PS_ACCEL_PSPORTAL_END\n'
HOOK = BEGIN + '''local psportal_original = _G.gen_config
_G.gen_config = function(var)
    local raw = psportal_original(var)
    if var and var.redir_port and not var.no_run then
        local ok, patched = pcall(function()
            local adapter = dofile("/usr/lib/ps-accel/psportal_adapter.lua")
            return adapter.patch(raw)
        end)
        if ok then return patched end
    end
    return raw
end
''' + END
FIELDS = ('portal', 'ps5', 'node', 'domains', 'ports', 'exclusions')
DEFAULTS = dict(portal='', ps5='', node='', ports='443', domains='', exclusions='')
NATIVE_PROTOCOLS = {'shadowsocks', 'trojan', 'vless', 'vmess', 'hysteria2', 'tuic', 'anytls', 'socks', 'http'}
MAC_PATTERN = r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}'
LEASES = Path('/tmp/dhcp.leases')
PROC = Path('/proc')
LIVE_ROOT = Path('/tmp/etc/passwall')

def passwall_metadata():
    """Read local nodes through UCI on both Lua and ucode-based LuCI firmware."""
    result = port.command('uci', '-q', 'show', 'passwall', check=False, timeout=4)
    if result.returncode:
        raise RuntimeError('读取 PassWall 配置失败，请确认 PassWall 已安装并刷新节点')
    sections = {}
    for line in result.stdout.splitlines():
        key, separator, raw = line.partition('=')
        parts = key.split('.', 2)
        if not separator or len(parts) < 2 or parts[0] != 'passwall':
            continue
        values = shlex.split(raw)
        section = sections.setdefault(parts[1], {})
        section[parts[2] if len(parts) == 3 else '.type'] = values[0] if len(values) == 1 else ''
    global_config = next((s for s in sections.values() if s.get('.type') == 'global'), {})
    forwarding = next((s for s in sections.values() if s.get('.type') == 'global_forwarding'), {})
    nodes = []
    for node_id, node in sections.items():
        if node.get('.type') != 'nodes':
            continue
        core = node.get('type', '').lower().replace('_', '-').replace(' ', '')
        protocol = node.get('protocol', '').lower()
        reason = ''
        if core not in ('sing-box', 'singbox'):
            reason = '使用 ' + (node.get('type') or '其他核心') + '，请选择 Sing-box 节点'
        elif protocol not in NATIVE_PROTOCOLS:
            reason = '此节点协议或分流组待适配'
        elif node.get('chain_proxy', '') not in ('', '0') or node.get('detour'):
            reason = '此节点配置了链式代理'
        elif any(node.get(key) == '1' for key in ('shadowtls', 'ech', 'hysteria2_realms')):
            reason = '此节点的附加协议选项待适配'
        elif node.get('domain_resolver') and (node.get('domain_resolver_dns') or node.get('domain_resolver_dns_https')):
            reason = '此节点使用独立 DNS，请将节点 DNS 设为自动'
        elif not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', node_id):
            reason = '节点需要使用具名 UCI 配置'
        nodes.append({'id': node_id, 'label': node.get('remarks') or node_id,
                      'protocol': protocol, 'core': node.get('type', ''),
                      'available': not reason, 'reason': reason})
    return {'enabled': global_config.get('enabled') == '1', 'nodes': nodes,
            'routing': {'client_proxy': global_config.get('client_proxy', '1') == '1',
                        'acl_enabled': global_config.get('acl_enable', '0') == '1',
                        'tcp_mode': global_config.get('tcp_proxy_mode', 'proxy'),
                        'tcp_ports': forwarding.get('tcp_redir_ports', '80,443'),
                        'bypass_ports': forwarding.get('tcp_no_redir_ports', 'disable'),
                        'ipv6': forwarding.get('ipv6_tproxy', '0') == '1',
                        'chn_list': global_config.get('chn_list', 'direct')}}


class PolicyCancelled(RuntimeError):
    """Cancellation completed before mutation or after a successful rollback."""


def folder():
    return port.PERSIST / 'psportal'


def runtime():
    return port.RUNTIME / 'psportal'


def autostart_enabled():
    return read(folder() / 'startup.json').get('autostart', True) is True


def policy_enabled(manifest):
    if not manifest.get('enabled'):
        return False
    activation = read(runtime() / 'activation.json')
    if type(activation.get('enabled')) is bool:
        return activation['enabled']
    return manifest.get('autostart', True) is True


def set_autostart(enabled):
    with lock():
        manifest = read(folder() / 'manifest.json')
        current = policy_enabled(manifest)
        previous_setting = autostart_enabled()
        paths = [folder() / 'startup.json', folder() / 'manifest.json', runtime() / 'activation.json']
        previous = {p: p.read_bytes() if p.exists() else None for p in paths}
        try:
            port.atomic(runtime() / 'activation.json', {'enabled': current})
            port.atomic(folder() / 'startup.json', {'autostart': enabled})
            if manifest:
                manifest['autostart'] = enabled
                port.atomic(folder() / 'manifest.json', manifest)
            port.command('/etc/init.d/ps-accel-policy', 'enable' if enabled else 'disable', timeout=5)
        except Exception:
            for path, data in previous.items():
                if data is None:
                    path.unlink(missing_ok=True)
                else:
                    write_text(path, data.decode())
            port.command('/etc/init.d/ps-accel-policy', 'enable' if previous_setting else 'disable',
                         check=False, timeout=5)
            raise
    return {'ok': True, 'autostart': enabled, 'enabled': current}


def read(path, default=None):
    try:
        if path.stat().st_size > 1024 * 1024:
            raise ValueError('分流文件超过容量限制')
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else (default or {})
    except (OSError, ValueError):
        return {} if default is None else default


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


@contextmanager
def lock():
    runtime().mkdir(parents=True, exist_ok=True, mode=0o700)
    with (runtime() / 'policy.lock').open('a') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('精确分流正在更新，请稍后重试') from None
        yield


def domains(text):
    return domain_rules(text)


def address(value):
    ip = ipaddress.ip_address(value)
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or ip.is_reserved:
        raise ValueError('请选择设备的有效单播地址')
    return str(ip)


def selector(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError('设备标识限 64 字符')
    value = value.strip().lower()
    if re.fullmatch(MAC_PATTERN, value):
        if int(value[:2], 16) & 1 or value == '00:00:00:00:00:00':
            raise ValueError('请选择设备的单播 MAC')
        return value
    try:
        return address(value)
    except ValueError:
        raise ValueError('设备范围使用现有 MAC 或单个 IP 地址') from None


def normalize(request):
    if set(request) != set(FIELDS):
        raise ValueError('精确分流参数无效')
    data = {key: request[key] for key in FIELDS}
    data['portal'], data['ps5'] = selector(data['portal']), selector(data['ps5'])
    if data['portal'] == data['ps5']:
        raise ValueError('Portal 与 PS5 请选择不同设备')
    if not isinstance(data['node'], str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', data['node']):
        raise ValueError('请选择现有的 Sing-box 订阅节点')
    names, excluded = domains(data['domains']), domains(data['exclusions'])
    if not names:
        raise ValueError('请填写需要代理的主机名或子域名匹配规则')
    if not isinstance(data['ports'], str) or len(data['ports']) > 128:
        raise ValueError('端口列表限 128 字符')
    pieces = [x.strip() for x in data['ports'].split(',')]
    if not pieces or len(pieces) > 16 or any(not re.fullmatch(r'[0-9]{1,5}', x) or
                                           not 1 <= int(x) <= 65535 for x in pieces):
        raise ValueError('填写 1 至 16 个 TCP 端口，以逗号分隔')
    data.update(domains='\n'.join(names), exclusions='\n'.join(excluded),
                ports=','.join(str(x) for x in sorted({int(x) for x in pieces})))
    return data


def inventory():
    items, leases = {}, {}
    def add(mac, ip, source):
        try:
            mac, ip = selector(mac), address(ip)
        except (ValueError, TypeError):
            return
        if not re.fullmatch(MAC_PATTERN, mac):
            return
        if source == 'neighbour' and ip in leases and leases[ip] != mac:
            return
        row = items.setdefault(mac, {'mac': mac, 'addresses': [], 'label': mac, 'source': source})
        if ip not in row['addresses']:
            row['addresses'].append(ip)
    try:
        for line in LEASES.read_text().splitlines()[:2048]:
            fields = line.split()
            if len(fields) >= 4 and (fields[0] == '0' or int(fields[0]) > time.time()):
                add(fields[1], fields[2], 'dhcp')
                try:
                    leases[address(fields[2])] = selector(fields[1])
                except ValueError:
                    continue
                if fields[1].lower() in items and fields[3] != '*':
                    items[fields[1].lower()]['label'] = fields[3][:80]
    except (OSError, ValueError):
        pass
    try:
        result = port.command('ip', '-j', 'neigh', 'show', check=False, timeout=3)
        for row in json.loads(result.stdout or '[]')[:2048]:
            state = row.get('state', [])
            state = [state] if isinstance(state, str) else state
            if row.get('lladdr') and not set(state) & {'FAILED', 'INCOMPLETE'}:
                add(row['lladdr'], row.get('dst', ''), 'neighbour')
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        pass
    return list(items.values())


def resolve(config, devices):
    result, canonical = {}, dict(config)
    owners = {}
    for device in devices:
        for ip in device['addresses']:
            owners.setdefault(ip, set()).add(device['mac'])
    for role in ('portal', 'ps5'):
        value = config[role]
        match = next((x for x in devices if x['mac'] == value or value in x['addresses']), None)
        if match:
            result[role] = sorted(ip for ip in match['addresses'] if len(owners[ip]) == 1)
            canonical[role] = match['mac']
        else:
            result[role] = []
    if canonical['portal'] == canonical['ps5']:
        raise ValueError('Portal 与 PS5 对应同一 MAC，请选择不同设备')
    if set(result['portal']) & set(result['ps5']):
        raise ValueError('两台设备的地址范围重叠，请核对租约与邻居记录')
    return result, canonical


def rule_set(config, sources, dynamic=True):
    ips = sorted(set(sources.get('portal', []) + sources.get('ps5', [])))
    if not ips:
        return {'version': 3, 'rules': []}
    clauses = [{'source_ip_cidr': [str(ipaddress.ip_network(ip + ('/128' if ':' in ip else '/32'))) for ip in ips]},
               domain_matcher(proxy_rules(config) if dynamic else domains(config['domains'])),
               {'network': 'tcp', 'port': [int(x) for x in config['ports'].split(',')]}]
    excluded = domains(config['exclusions'])
    if excluded:
        clauses.append(dict(domain_matcher(excluded), invert=True))
    return {'version': 3, 'rules': [{'type': 'logical', 'mode': 'and', 'rules': clauses}]}


def direct_rule_set(config, sources):
    if not matches_domain(FIRMWARE_HOST, domains(config['exclusions'])):
        return {'version': 3, 'rules': []}
    return rule_set(dict(config, domains=FIRMWARE_HOST, ports='80,443', exclusions=''), sources, dynamic=False)


def free_port(number):
    try:
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', number))
        return True
    except OSError:
        return False


def diagnostics_plan(configs, old):
    previous = old.get('diagnostics', {}).get('cores', {})
    used, result = set(), {}
    def allocate(preferred=None, owned=False):
        if type(preferred) is int and 18780 <= preferred <= 18843 and preferred not in used and (owned or free_port(preferred)):
            used.add(preferred)
            return preferred
        for number in range(18780, 18844):
            if number not in used and free_port(number):
                used.add(number)
                return number
        raise RuntimeError('本地诊断端口已占满，请检查 18780–18843 的端口使用情况')
    for item in configs[:8]:
        config, key = item['config'], core_key(item['config'])
        if key in result:
            raise RuntimeError('透明入口标识重复，请检查现有核心配置')
        prior = previous.get(key, {})
        own_probe = next((x for x in config.get('inbounds', []) if x.get('tag') == PROBE_TAG), {})
        api = config.get('experimental', {}).get('clash_api', {})
        if api.get('external_controller'):
            try:
                _, api_port = loopback_endpoint(api['external_controller'])
            except ValueError:
                raise RuntimeError('现有 Sing-box 管理接口需要使用回环地址，完成后重新预览') from None
            api_owned = bool(prior.get('api_owned') and prior.get('api_port') == api_port)
            used.add(api_port)
        else:
            api_port, api_owned = allocate(prior.get('api_port')), True
        probe_port = allocate(prior.get('probe_port'), own_probe.get('listen_port') == prior.get('probe_port'))
        result[key] = dict(api_port=api_port, api_owned=api_owned, probe_port=probe_port)
    return result


def diagnostics_loaded(config, specs):
    key = core_key(config)
    spec = specs.get(key, {})
    try:
        _, api_port = loopback_endpoint(config.get('experimental', {}).get('clash_api', {}).get('external_controller', ''))
    except ValueError:
        return False
    return bool(spec and api_port == spec['api_port'] and any(x.get('tag') == PROBE_TAG and x.get('listen') == '127.0.0.1'
                and x.get('listen_port') == spec['probe_port'] for x in config.get('inbounds', [])))


def live_configs():
    result, seen = [], set()
    try:
        processes = list(PROC.iterdir())
    except OSError:
        return result
    for process in processes:
        if not process.name.isdigit():
            continue
        try:
            args = [x.decode(errors='replace') for x in (process / 'cmdline').read_bytes().split(b'\0') if x]
            if not args or 'sing-box' not in Path(args[0]).name:
                continue
            for index, arg in enumerate(args[:-1]):
                if arg not in ('-c', '--config'):
                    continue
                path = Path(args[index + 1]).resolve()
                if not path.is_relative_to(LIVE_ROOT) or path in seen or path.stat().st_size > 1024 * 1024:
                    continue
                config = json.loads(path.read_text())
                if not any(x.get('type') in ('redirect', 'tproxy') and x.get('network') != 'udp'
                           for x in config.get('inbounds', [])):
                    continue
                seen.add(path)
                result.append({'path': str(path), 'config': config, 'fingerprint': digest(config)})
        except (OSError, ValueError, IndexError):
            continue
    return result


def clean_hook(text):
    if BEGIN not in text:
        return text
    if text.count(BEGIN) != 1 or text.count(END) != 1:
        raise RuntimeError('PassWall 扩展标记需要检查')
    start, end = text.index(BEGIN), text.index(END) + len(END)
    return text[:start] + text[end:]


def tproxy_supported():
    name = 'psa_psp_check_' + uuid.uuid4().hex[:12]
    batch = ('add table inet ' + name + '\nadd chain inet ' + name + ' probe\n'
             'add rule inet ' + name + ' probe meta l4proto tcp socket transparent 1 counter\n'
             'delete table inet ' + name + '\n')
    try:
        result = subprocess.run(['nft', '-c', '-f', '/dev/stdin'], input=batch, text=True,
                                capture_output=True, timeout=3)
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def snapshot():
    errors, metadata, versions = [], {}, {}
    node_error = ''
    try:
        metadata = passwall_metadata()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        node_error = 'PassWall 节点读取失败，请确认本机 PassWall 配置并刷新节点'
        errors.append(node_error)
    try:
        result = port.command('/usr/bin/sing-box', 'version', check=False, timeout=3)
        match = re.search(r'sing-box version ([0-9.]+)', result.stdout)
        versions['singbox'] = match.group(1) if match else ''
    except (OSError, subprocess.SubprocessError):
        versions['singbox'] = ''
    try:
        text = PASSWALL.read_text()
        original = clean_hook(text)
        code_hash = hashlib.sha256(original.encode()).hexdigest()
        compatible = code_hash == STOCK_SHA256
        hooked = BEGIN in text and END in text
    except (OSError, ValueError, RuntimeError):
        compatible, hooked, code_hash = False, False, ''
    if not compatible:
        errors.append('当前适配器支持 R66S 固件内的 PassWall 26.11.11-r376，请核对程序版本')
    if versions['singbox'] != '1.14.4':
        errors.append('当前适配器需要已验证的 Sing-box 1.14.4')
    if not metadata.get('enabled'):
        errors.append('需要先启用现有 PassWall，再应用精确规则')
    nodes = metadata.get('nodes', [])
    configs = live_configs()
    if not configs:
        errors.append('需要运行现有 PassWall 的 Sing-box TCP 分流入口')
    if len(configs) > 8:
        errors.append('当前活动分流入口超过首版验证范围')
    if any(x.get('type') == 'tproxy' and x.get('network') != 'udp'
           for item in configs for x in item['config'].get('inbounds', [])) and not tproxy_supported():
        errors.append('当前 TProxy TCP 入口需要可用的 nft socket transparent 支持，请先核对原 PassWall 连通性')
    uci_hash = hashlib.sha256()
    for path in (Path('/etc/config/passwall'), Path('/tmp/.uci/passwall')):
        try:
            uci_hash.update(path.read_bytes())
        except OSError:
            uci_hash.update(b'missing')
    try:
        adapter_hash = hashlib.sha256((port.APP / 'psportal_adapter.lua').read_bytes()).hexdigest()
    except OSError:
        adapter_hash = ''
        errors.append('精确分流适配程序待安装')
    return {'versions': versions, 'nodes': nodes, 'node_error': node_error, 'devices': inventory(), 'errors': errors,
            'compatible': compatible, 'hooked': hooked, 'code_hash': code_hash,
            'configs': configs, 'enabled': bool(metadata.get('enabled')), 'uci_hash': uci_hash.hexdigest(),
            'adapter_hash': adapter_hash, 'routing': metadata.get('routing', {})}


def loaded(config):
    return any(x.get('tag') == TAG for x in config.get('route', {}).get('rule_set', []))


def port_in_scope(spec, number):
    if spec == 'disable':
        return False
    for item in spec.split(','):
        item = item.strip()
        if re.fullmatch(r'\d{1,5}', item) and int(item) == number:
            return True
        if re.fullmatch(r'\d{1,5}:\d{1,5}', item):
            start, end = map(int, item.split(':'))
            if start <= number <= end:
                return True
    return False


def entry_scope(config, sources, env):
    routing, blockers, notices = env.get('routing', {}), [], []
    if routing and not routing.get('acl_enabled'):
        if not routing.get('client_proxy'):
            blockers.append('当前 PassWall 客户端接管已关闭，请先核对两台设备的访问控制')
        for number in map(int, config['ports'].split(',')):
            if (not port_in_scope(routing.get('tcp_ports', ''), number) or
                    port_in_scope(routing.get('bypass_ports', 'disable'), number)):
                blockers.append('TCP ' + str(number) + ' 位于现有 PassWall 接管范围之外，请核对原端口规则')
    if routing.get('acl_enabled'):
        notices.append('设备访问控制继续生效；设备对应的 TCP 入口与端口需要在 PassWall 中核对')
    if routing.get('tcp_mode') == 'disable' or routing.get('chn_list') == 'direct':
        notices.append('当前域名 / IP 列表和直连策略决定哪些连接进入代理核心')
    if any(':' in ip for ips in sources.values() for ip in ips) and routing and not routing.get('ipv6'):
        notices.append('现有 IPv6 接管关闭，IPv6 连接继续执行原策略')
    notices.append('配置载入后，以新连接的核心出口日志和 Portal 实机连接确认命中')
    return {'blockers': blockers, 'notices': notices, 'traffic_verified': False}


def status():
    env = snapshot()
    manifest = read(folder() / 'manifest.json')
    enabled = policy_enabled(manifest)
    config = read(folder() / 'draft.json', DEFAULTS)
    receipt = read(runtime() / 'receipt.json')
    errors = list(env['errors'])
    attached = sum(loaded(x['config']) for x in env['configs'])
    sources = {}
    if manifest.get('config'):
        try:
            sources, _ = resolve(manifest['config'], env['devices'])
        except ValueError as exc:
            errors.append(str(exc))
    scope = entry_scope(config, sources, env)
    errors.extend(scope['blockers'])
    telemetry = read(runtime() / 'connections.json')
    revision = evidence_revision(manifest, sources)
    current = telemetry.get('revision') == revision
    fresh = bool(current and enabled and
                 0 <= time.time() - telemetry.get('epoch', 0) < 15) if type(telemetry.get('epoch')) in (int, float) else False
    if not current:
        telemetry.update(connections=[], matched_connections=0)
    telemetry['fresh'] = fresh
    telemetry['traffic_verified'] = bool(fresh and telemetry.get('traffic_verified'))
    telemetry['download_direct_verified'] = bool(fresh and telemetry.get('download_direct_verified'))
    scope['traffic_verified'] = telemetry['traffic_verified']
    probes = read(runtime() / 'probes.json')
    probes['current_config'] = bool(enabled and probes.get('revision') == revision)
    return {'ok': True, 'config': config, 'active_config': manifest.get('config', {}),
            'enabled': enabled, 'autostart': autostart_enabled(),
            'environment': {'passwall': '26.11.11-r376' if env['compatible'] else '',
                            'singbox': env['versions']['singbox'], 'compatible': env['compatible'],
                            'passwall_enabled': env['enabled'], 'hooked': env['hooked'],
                            'active_cores': len(env['configs']), 'attached_cores': attached,
                            'routing': env.get('routing', {})},
            'nodes': env['nodes'], 'node_error': env.get('node_error', ''),
            'devices': env['devices'], 'sources': sources,
            'blockers': errors, 'receipt': receipt, 'entry_scope': scope,
            'telemetry': telemetry, 'probes': probes,
            'dynamic_rules': dynamic_rule_info(),
            'scope': '指定设备的域名规则与 TCP 端口，自动覆盖动态认证 / 信令；原 DNS、防火墙范围及默认规则继续生效'}


def preview(request, validate_runtime=True):
    config = normalize(request)
    env = snapshot()
    sources, canonical = resolve(config, env['devices'])
    errors = list(env['errors'])
    selected = next((x for x in env['nodes'] if x['id'] == config['node']), None)
    if not selected or selected.get('available') is False:
        errors.append(selected.get('reason') if selected else '请选择本机 PassWall 的 Sing-box 节点')
    for role, ips in sources.items():
        if not ips:
            errors.append(('Portal' if role == 'portal' else 'PS5') + ' 当前地址待发现，请保持设备在线')
    scope = entry_scope(config, sources, env)
    errors.extend(scope['blockers'])
    old = read(folder() / 'manifest.json')
    diagnostics = {}
    try:
        diagnostics = diagnostics_plan(env['configs'], old)
    except RuntimeError as exc:
        errors.append(str(exc))
    recovery = read(runtime() / 'receipt.json').get('state') == 'recovery_required'
    restart = (recovery or not env['hooked'] or not env['configs'] or
               any(not loaded(x['config']) for x in env['configs']) or
               old.get('config', {}).get('node') != config['node'] or
               any(not diagnostics_loaded(x['config'], diagnostics) for x in env['configs']) or
               not old.get('direct_rules_path'))
    token = digest({'config': config, 'sources': sources, 'code_hash': env['code_hash'],
                    'cores': [x['fingerprint'] for x in env['configs']], 'old': old, 'uci': env.get('uci_hash'),
                    'adapter': env.get('adapter_hash'), 'diagnostics': diagnostics,
                    'dynamic_rules': DYNAMIC_PROXY_RULES})
    excluded = domains(config['exclusions'])
    targets = proxy_rules(config)
    if all(rule_excluded(rule, excluded) for rule in targets):
        errors.append('目标域名规则均在排除列表中，请检查规则')
    checks = {}
    if not errors and validate_runtime:
        try:
            checks = validate_configs(canonical, sources, env['configs'])
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            errors.append(str(exc) if isinstance(exc, RuntimeError) else '生成配置校验失败，请核对节点与原有分流')
    return {'ok': True, 'config': canonical, 'token': token, 'can_apply': not errors,
            'blockers': errors, 'restart_required': restart, 'sources': sources, 'validation': checks, 'entry_scope': scope,
            'rules': [{'domain': x, 'network': 'tcp', 'ports': config['ports'],
                       'builtin': x in DYNAMIC_PROXY_RULES,
                       'excluded': rule_excluded(x, excluded)} for x in targets],
            'direct_rules': [{'domain': FIRMWARE_HOST, 'network': 'tcp', 'ports': '80,443'}]
                            if matches_domain(FIRMWARE_HOST, excluded) else [],
            'diagnostics': {'core_count': len(diagnostics), 'loopback_only': True,
                            'probe_targets': ['认证', '信令', '连通探测', '固件下载直连']},
            'preserves': ['原有强制直连与阻断优先', '其他设备及其他连接保留原规则顺序与默认出口',
                          '沿用现有 DNS 与防火墙接管范围'],
            'notice': ('首次接入或切换节点需要重启 PassWall，已有连接可能重连' if restart else
                       '本次更新本地规则集，保持 PassWall 进程运行')}


def save(request):
    config = normalize(request)
    with lock():
        port.atomic(folder() / 'draft.json', config)
    return {'ok': True, 'saved': True}


def compile_config(config, manifest, path):
    payload = {'config': config, 'manifest': dict(manifest, rules_path=str(path))}
    result = subprocess.run(['lua', str(port.APP / 'psportal_adapter.lua'), 'preview'],
                            input=json.dumps(payload), text=True, capture_output=True, timeout=5)
    if result.returncode:
        raise RuntimeError('PassWall 节点转换或分流结构校验失败，请核对原生节点与规则')
    return json.loads(result.stdout)


def check_config(config):
    result = subprocess.run(['/usr/bin/sing-box', 'check', '-c', '/dev/stdin'],
                            input=json.dumps(config), text=True, capture_output=True, timeout=8)
    if result.returncode:
        raise RuntimeError('生成的 Sing-box 配置校验失败；原配置保持可用')


def restart_passwall():
    process = subprocess.Popen(['/etc/init.d/passwall', 'restart'], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    try:
        process.communicate(timeout=60)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
        raise RuntimeError('PassWall 重启超时，正在恢复原配置') from None
    if process.returncode:
        raise RuntimeError('PassWall 重启失败，需要核对节点与原服务状态')


def write_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temp = path.with_name(path.name + '.psportal-' + uuid.uuid4().hex)
    try:
        temp.write_text(text)
        temp.chmod(0o600 if path != PASSWALL else 0o644)
        temp.replace(path)
    finally:
        temp.unlink(missing_ok=True)


def validate_configs(config, sources, configs):
    staged = runtime() / ('check-' + uuid.uuid4().hex + '.json')
    direct_staged = staged.with_name(staged.stem + '-direct.json')
    old = read(folder() / 'manifest.json')
    manifest = {'version': 1, 'enabled': True, 'config': config,
                'owned': bool(old.get('version')), 'direct_rules_path': str(direct_staged),
                'diagnostics': {'secret': old.get('diagnostics', {}).get('secret') or '0' * 48,
                                'cores': diagnostics_plan(configs, old)}}
    try:
        port.atomic(staged, rule_set(config, sources))
        port.atomic(direct_staged, direct_rule_set(config, sources))
        guards, expected_outbounds = 0, {}
        for item in configs:
            compiled = compile_config(item['config'], manifest, staged)
            check_config(compiled)
            outbound = next(x for x in compiled.get('outbounds', []) if x.get('tag') == TAG)
            expected_outbounds[core_key(item['config'])] = digest(outbound)
            guards += sum(x.get('type') == 'logical' and x.get('action') in ('route', 'reject')
                          and any(y.get('rule_set') == [TAG] for y in x.get('rules', []))
                          for x in compiled.get('route', {}).get('rules', []))
        return {'checked_cores': len(configs), 'protection_rules': guards, 'expected_outbounds': expected_outbounds}
    finally:
        staged.unlink(missing_ok=True)
        direct_staged.unlink(missing_ok=True)


def apply(request, cancel=lambda: False):
    original_request = {k: request[k] for k in FIELDS}
    with lock():
        plan = preview(original_request, validate_runtime=False)
        if plan['token'] != request['token']:
            raise RuntimeError('配置或设备状态已变化，请重新生成预览')
        if plan['blockers']:
            raise RuntimeError('；'.join(plan['blockers']))
        if plan['restart_required'] and request['confirm_restart'] != 1:
            raise RuntimeError('本次应用涉及 PassWall 重启，请先确认预览中的影响')
        config = plan['config']
        rules = rule_set(config, plan['sources'])
        if all(x['excluded'] for x in plan['rules']):
            raise RuntimeError('目标主机名均在直连排除列表中，请检查预览')
        manifest = {'version': 1, 'enabled': True, 'autostart': autostart_enabled(), 'owned': True, 'config': config,
                    'rules_path': str(folder() / 'rules.json'),
                    'direct_rules_path': str(folder() / 'direct-rules.json'),
                    'diagnostics': {'secret': read(folder() / 'manifest.json').get('diagnostics', {}).get('secret') or
                                    os.urandom(24).hex(),
                                    'cores': diagnostics_plan(snapshot()['configs'], read(folder() / 'manifest.json'))}}
        validation = validate_configs(config, plan['sources'], snapshot()['configs'])
        manifest['expected_outbounds'] = validation.get('expected_outbounds', {})
        if preview(original_request, validate_runtime=False)['token'] != plan['token']:
            raise RuntimeError('校验期间配置或设备状态已变化，请重新预览')
        if cancel():
            raise PolicyCancelled('精确分流应用已取消')
        paths = [folder() / 'rules.json', folder() / 'direct-rules.json', folder() / 'manifest.json', folder() / 'draft.json',
                 PASSWALL, runtime() / 'activation.json']
        previous = {p: p.read_bytes() if p.exists() else None for p in paths}
        old_enabled = policy_enabled(read(folder() / 'manifest.json'))
        restarted = False
        try:
            port.atomic(folder() / 'rules.json', rules)
            port.atomic(folder() / 'direct-rules.json', direct_rule_set(config, plan['sources']))
            port.atomic(folder() / 'manifest.json', manifest)
            port.atomic(runtime() / 'activation.json', {'enabled': True})
            port.atomic(folder() / 'draft.json', config)
            if plan['restart_required']:
                text = clean_hook(PASSWALL.read_text())
                if text.count(ANCHOR) != 1 or hashlib.sha256(text.encode()).hexdigest() != STOCK_SHA256:
                    raise RuntimeError('PassWall 程序已变化，请重新核对适配版本')
                write_text(PASSWALL, text.replace(ANCHOR, HOOK + ANCHOR, 1))
                restarted = True
                restart_passwall()
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    active = live_configs()
                    if (len(active) == len(manifest['diagnostics']['cores']) and active and
                            all(loaded(x['config']) and diagnostics_loaded(x['config'], manifest['diagnostics']['cores']) for x in active)):
                        break
                    time.sleep(.5)
                else:
                    raise RuntimeError('精确规则加载待确认，已请求恢复原配置')
            if cancel():
                raise PolicyCancelled('精确分流应用已取消，正在恢复原配置')
            for action in ('enable' if manifest['autostart'] else 'disable', 'start'):
                result = port.command('/etc/init.d/ps-accel-policy', action, check=False, timeout=5)
                if result.returncode:
                    raise RuntimeError('设备地址跟踪服务启动失败，正在恢复原规则')
            if cancel():
                raise PolicyCancelled('精确分流应用已取消，正在恢复原配置')
            port.atomic(runtime() / 'receipt.json', {'state': 'applied', 'time': time.time(),
                        'restarted': restarted, 'domains': len(plan['rules']), 'sources': plan['sources']})
            return {'ok': True, 'restarted': restarted}
        except Exception:
            for path, data in previous.items():
                if data is None:
                    path.unlink(missing_ok=True)
                elif path == PASSWALL and path.exists() and path.read_bytes() != data:
                    current = path.read_text()
                    # Preserve concurrent program edits, removing only this owned hook.
                    if BEGIN not in data.decode():
                        write_text(path, clean_hook(current))
                else:
                    write_text(path, data.decode())
            if not old_enabled:
                for action in ('stop', 'disable'):
                    try:
                        port.command('/etc/init.d/ps-accel-policy', action, check=False, timeout=5)
                    except (OSError, subprocess.SubprocessError):
                        pass
            if restarted:
                try:
                    restart_passwall()
                except Exception:
                    port.atomic(runtime() / 'receipt.json', {'state': 'recovery_required', 'time': time.time()})
                    raise RuntimeError('原配置已恢复，PassWall 启动需要检查') from None
            raise


def disable_files():
    manifest = read(folder() / 'manifest.json')
    paths = [folder() / 'rules.json', folder() / 'direct-rules.json', folder() / 'manifest.json', runtime() / 'receipt.json']
    previous = {p: p.read_bytes() if p.exists() else None for p in paths}
    try:
        port.atomic(folder() / 'rules.json', {'version': 3, 'rules': []})
        port.atomic(folder() / 'direct-rules.json', {'version': 3, 'rules': []})
        manifest['enabled'] = False
        port.atomic(folder() / 'manifest.json', manifest)
        port.atomic(runtime() / 'receipt.json', {'state': 'disabled', 'time': time.time()})
    except Exception:
        for path, data in previous.items():
            if data is None:
                path.unlink(missing_ok=True)
            else:
                write_text(path, data.decode())
        raise


def disable():
    with lock():
        disable_files()
    for action in ('stop', 'disable'):
        port.command('/etc/init.d/ps-accel-policy', action, check=False, timeout=5)
    return {'ok': True, 'notice': '新连接恢复原策略；已有连接沿用当前出口直至结束'}


def detach():
    with lock():
        disable_files()
        if PASSWALL.exists():
            text = PASSWALL.read_text()
            if BEGIN in text:
                write_text(PASSWALL, clean_hook(text))


def refresh_sources():
    with lock():
        manifest = read(folder() / 'manifest.json')
        if not policy_enabled(manifest) or not manifest.get('config'):
            return
        sources, _ = resolve(manifest['config'], inventory())
        rules = rule_set(manifest['config'], sources)
        if read(folder() / 'rules.json') != rules:
            port.atomic(folder() / 'rules.json', rules)
        direct_rules = direct_rule_set(manifest['config'], sources)
        if read(folder() / 'direct-rules.json') != direct_rules:
            port.atomic(folder() / 'direct-rules.json', direct_rules)
        port.atomic(runtime() / 'watcher.json', {'time': time.time(), 'sources': sources})


def resume():
    if policy_enabled(read(folder() / 'manifest.json')):
        refresh_sources()
        for action in ('enable' if autostart_enabled() else 'disable', 'start'):
            port.command('/etc/init.d/ps-accel-policy', action, timeout=5)


def watch():
    tracker = ConnectionTracker()
    next_sources = 0
    observing = False
    stopping = False
    def stop(*_):
        nonlocal stopping
        stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    while not stopping:
        try:
            if time.monotonic() >= next_sources:
                refresh_sources()
                next_sources = time.monotonic() + 10
            manifest = read(folder() / 'manifest.json')
            if policy_enabled(manifest):
                sources, _ = resolve(manifest['config'], inventory())
                port.atomic(runtime() / 'connections.json', tracker.sample(live_configs(), sources, manifest))
                observing = True
            elif observing:
                port.atomic(runtime() / 'connections.json', {'epoch': time.time(), 'state': 'disabled',
                            'sampled_cores': 0, 'connections': [], 'generation': tracker.generation})
                observing = False
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            pass
        for _ in range(2):
            if stopping:
                break
            time.sleep(1)


def probe_connections(cancel=lambda: False):
    manifest = read(folder() / 'manifest.json')
    if not policy_enabled(manifest):
        raise RuntimeError('启用透明代理后检测所选出口')
    expected = manifest.get('expected_outbounds', {})
    configs = [item for item in live_configs()
               if expected.get(core_key(item['config'])) == outbound_signature(item['config'])
               and diagnostics_loaded(item['config'], manifest.get('diagnostics', {}).get('cores', {}))]
    if not configs:
        raise RuntimeError('当前出口检测入口加载待确认，请重新预览并启用透明代理')
    sources, _ = resolve(manifest['config'], inventory())
    result = probe(configs, manifest, cancel=cancel)
    result['revision'] = evidence_revision(manifest, sources)
    port.atomic(runtime() / 'probes.json', result)
    return result


if __name__ == '__main__':
    import sys
    os.umask(0o077)
    if os.geteuid() != 0:
        raise SystemExit('需要 root 权限')
    if sys.argv[1:] == ['watch']:
        watch()
    elif sys.argv[1:] == ['detach']:
        detach()
    elif sys.argv[1:] == ['resume']:
        resume()
    else:
        raise SystemExit('请选择受支持的分流管理操作')
