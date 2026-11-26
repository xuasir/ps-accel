"""Device-exclusive PassWall ACL and shunt rules, using the native UCI backend."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import time

import portal_openwrt as port
import portal_policy as legacy
import passwall_uci as uci
from observability import load_preferences
from proxy_telemetry import ConnectionTracker
from sony_domains import (DYNAMIC_PROXY_RULES, matches_domain, native_host as valid_host,
                         device_host_rules as host_rules, device_matches as matches)

FIELDS = ('domains', 'exclusions', 'node')
LIST_FIELDS = ('domains', 'exclusions')
ACL_SOURCE = Path('/usr/lib/lua/luci/model/cbi/passwall/client/acl_config.lua')
APP_SOURCE = Path('/usr/share/passwall/app.sh')
SERVICE = '/etc/init.d/passwall'
PROC = Path('/proc')
LIVE_ROOT = Path('/tmp/etc/passwall')
LIST_BYTES = 256 * 1024
MAX_RULES = 4096
OWNER = 'ps-accel-device-proxy-v1'
ACL_ID = 'ps_accel_devices'
NODE_ID = 'ps_accel_device_shunt'
GROUP_ID = 'ps_accel_devices'
LAN_RULE = 'ps_accel_device_lan'
DIRECT_RULE = 'ps_accel_device_direct'
PROXY_RULE = 'ps_accel_device_proxy'
OWNED = {ACL_ID: 'acl_rule', LAN_RULE: 'shunt_rules', DIRECT_RULE: 'shunt_rules',
         PROXY_RULE: 'shunt_rules', NODE_ID: 'nodes'}
LAN_NETWORKS = '10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n127.0.0.0/8\n169.254.0.0/16\n::1/128\nfc00::/7\nfe80::/10'
TRAFFIC_LIMIT = '按批次累计本机已有连接接口的字节增量。设备直达流量与采样间完成的短连接影响覆盖。'


def runtime():
    return port.RUNTIME / 'psportal'


def folder():
    return port.PERSIST / 'device-proxy'


def normalize(request):
    result = {}
    for key in LIST_FIELDS:
        text = request.get(key)
        if not isinstance(text, str) or len(text.encode('utf-8')) > LIST_BYTES:
            raise ValueError('每份设备域名名单限 256 KiB')
        lines, seen = [], set()
        for line in text.splitlines():
            name = line.strip()
            if not name or name.startswith('#'):
                lines.append(name)
                continue
            name = name.lower().removeprefix('full:').rstrip('.')
            if name.startswith('geosite:'):
                if not re.fullmatch(r'geosite:[a-z0-9_@!:.\-]{1,240}', name):
                    raise ValueError('geosite: 规则请使用本机 PassWall 支持的标签')
            elif not valid_host(name.removeprefix('domain:')):
                raise ValueError('每行填写完整域名；domain:example.com 用于显式匹配主域与子域')
            if name not in seen:
                lines.append(name)
                seen.add(name)
        if len(seen) > MAX_RULES:
            raise ValueError('每份设备域名名单最多 4096 条规则')
        result[key] = '\n'.join(lines).rstrip('\n') + ('\n' if any(lines) else '')
    node = request.get('node', '')
    if not isinstance(node, str) or node and not uci.IDENTIFIER.fullmatch(node):
        raise ValueError('请选择本机 PassWall 已保存的代理出口')
    result['node'] = node
    return result


def compiled(text):
    return '\n'.join(line if line.startswith(('domain:', 'geosite:')) else 'full:' + line
                     for line in text.splitlines() if line and not line.startswith('#'))


def core_name(value):
    value = str(value).lower().replace('-', '').replace('_', '').replace(' ', '')
    return 'sing-box' if value == 'singbox' else 'xray' if value == 'xray' else ''


def node_choices(sections):
    result = []
    for ident, row in sections.items():
        if row.get('.type') != 'nodes' or ident == NODE_ID or not uci.IDENTIFIER.fullmatch(ident):
            continue
        core, protocol = core_name(row.get('type')), uci.scalar(row.get('protocol')).lower()
        reason = ('选择本机 Xray 或 Sing-box 的代理出口' if not core else
                  '分流节点请使用其中的实际代理出口' if protocol == '_shunt' else
                  '接口节点用于直连，请选择代理出口' if protocol == '_iface' else
                  'Xray 负载均衡请使用 Xray 核心' if protocol == '_balancing' and core != 'xray' else
                  'Sing-box 自动选择请使用 Sing-box 核心' if protocol == '_urltest' and core != 'sing-box' else
                  '请在 PassWall 选择可用的实际代理出口' if protocol.startswith('_') and protocol not in ('_balancing', '_urltest') else
                  '在 PassWall 中保存节点协议后使用' if not protocol else '')
        result.append({'id': ident, 'label': uci.scalar(row.get('remarks'), ident).replace('\n', ' ')[:100],
                       'core': core, 'protocol': protocol, 'available': not reason, 'reason': reason})
    return result


def preferred_node(sections, global_config, nodes):
    ident = uci.scalar(global_config.get('node') or global_config.get('tcp_node'))
    seen = set()
    for _ in range(8):
        if ident in seen:
            break
        seen.add(ident)
        row = sections.get(ident, {})
        if row.get('protocol') == '_shunt':
            ident = uci.scalar(row.get('default_node'))
        else:
            return ident if any(node['id'] == ident and node['available'] for node in nodes) else ''
    return ''


def acl_schema(global_config):
    try:
        text = ACL_SOURCE.read_text() if ACL_SOURCE.stat().st_size < 1024 * 1024 else ''
    except OSError:
        text = ''
    if re.search(r'[\"\']tcp_node[\"\']', text):
        return 'split_nodes'
    if re.search(r'[\"\']node[\"\']', text):
        return 'single_node'
    try:
        app = APP_SOURCE.read_text() if APP_SOURCE.stat().st_size < 1024 * 1024 else ''
    except OSError:
        app = ''
    if re.search(r'config_n_get\s+@global\[0\]\s+node\b', app):
        return 'single_node'
    return 'single_node' if 'node' in global_config else 'split_nodes'


def device_group():
    try:
        binding = port.device_binding()
        config = binding.get('config', {})
        result = {role: {'ip': config.get(role + '_ip', ''), 'mac': legacy.selector(binding[role + '_mac'])}
                  for role in ('portal', 'ps5')}
        if result['portal']['mac'] == result['ps5']['mac'] or any(
                not re.fullmatch(legacy.MAC_PATTERN, row['mac']) for row in result.values()):
            return {}
        return result
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError):
        return {}


def own_parts(sections):
    return {ident: sections.get(ident) for ident in OWNED}


def own_fingerprint(sections):
    _ident, main = uci.global_section(sections)
    return legacy.digest({'parts': own_parts(sections), 'acl_enable': main.get('acl_enable')})


def guard(sections):
    for ident, kind in OWNED.items():
        row = sections.get(ident)
        if row is not None and (row.get('ps_accel_owner') != OWNER or row.get('.type') != kind):
            raise RuntimeError('设备专属配置标识已被其他配置使用，请在 PassWall 整理后应用')
    for ident, row in sections.items():
        if ident in OWNED:
            continue
        if row.get('.type') in ('global', 'acl_rule') and any(row.get(key) == NODE_ID for key in ('node', 'tcp_node', 'udp_node')):
            raise RuntimeError('设备专属分流节点已被其他设备策略引用，请先在 PassWall 整理引用')
        if row.get('.type') in ('nodes', 'shunt_rules') and row.get('shunt_group', row.get('group')) == GROUP_ID:
            raise RuntimeError('设备专属规则组已被其他配置使用，请先在 PassWall 整理引用')
        if row.get('.type') == 'nodes' and any(key in row for key in (LAN_RULE, DIRECT_RULE, PROXY_RULE)):
            raise RuntimeError('设备专属规则已被其他分流节点引用，请先在 PassWall 整理引用')
        if row.get('.type') == 'nodes' and any(row.get(key) == NODE_ID or isinstance(row.get(key), list) and NODE_ID in row[key]
                for key in ('default_node', 'main_node', 'preproxy_node', 'to_node', 'balancing_node', 'urltest_node')):
            raise RuntimeError('设备专属节点已被其他节点引用，请先在 PassWall 整理引用')


def native_config(sections):
    node = sections.get(NODE_ID, {})
    result = {'node': uci.scalar(node.get(PROXY_RULE) or node.get('ps_accel_exit'))}
    for key, ident in (('domains', PROXY_RULE), ('exclusions', DIRECT_RULE)):
        text = uci.scalar(sections.get(ident, {}).get('domain_list'))
        result[key] = '\n'.join(line.removeprefix('full:') for line in text.splitlines()) + ('\n' if text else '')
    return result


def initial_config(sections, main, nodes):
    return {'domains': '', 'exclusions': '', 'node': preferred_node(sections, main, nodes)}


def scope_ready(group, sections):
    acl = sections.get(ACL_ID, {})
    _ident, main = uci.global_section(sections)
    wanted = {row['mac'] for row in group.values()}
    sources = acl.get('sources', [])
    sources = {sources} if isinstance(sources, str) else set(sources)
    if not (len(wanted) == 2 and sources == wanted and acl.get('ps_accel_owner') == OWNER and
            acl.get('enabled') == '1' and main.get('acl_enable') == '1'):
        return False
    if policy_mode(sections) == 'direct':
        return True
    node = sections.get(NODE_ID, {})
    target = acl.get('node') == NODE_ID or (acl.get('tcp_node') == NODE_ID and acl.get('udp_node') == NODE_ID)
    return bool(target and node.get('ps_accel_owner') == OWNER and node.get('protocol') == '_shunt' and
                node.get('default_node') == '_direct')


def policy_mode(sections):
    acl = sections.get(ACL_ID, {})
    if acl.get('ps_accel_owner') != OWNER or acl.get('enabled') != '1':
        return 'released'
    direct = acl.get('mode') == '0' or (acl.get('tcp_no_redir_ports') == '1:65535' and
                                       acl.get('udp_no_redir_ports') == '1:65535')
    return 'direct' if direct else 'proxy'


def source_list(group):
    try:
        path = LIVE_ROOT / 'acl' / ACL_ID / 'source_list'
        if path.stat().st_size > 4096:
            return False
        actual = {line.strip().lower() for line in path.read_text().splitlines() if line.strip()}
        return len(group) == 2 and actual == {'mac:' + row['mac'] for row in group.values()}
    except OSError:
        return False


def service_running(cores=None):
    return bool(cores if cores is not None else live_cores()) or (LIVE_ROOT / 'acl' / ACL_ID / 'source_list').is_file()


def native_core_present(cores):
    return any(NODE_ID in item.get('path', '') or
               any(PROXY_RULE in str(row.get('tag', '')) for row in item['config'].get('outbounds', [])) for item in cores)


def runtime_current(state, cores):
    if not state['controlled'] or state['mode'] == 'released' or not source_list(state['group']):
        return False
    try:
        fresh = (LIVE_ROOT / 'acl' / ACL_ID / 'source_list').stat().st_mtime >= state['snapshot']['path'].stat().st_mtime
    except OSError:
        return False
    return bool(fresh and (state['mode'] == 'direct' or native_core_present(cores)))


def read_state():
    if not Path(SERVICE).is_file():
        raise RuntimeError('请安装本机 PassWall 后，重新读取设备规则')
    snap = uci.snapshot()
    sections = snap['sections']
    _ident, main = uci.global_section(sections)
    nodes, group = node_choices(sections), device_group()
    actual = native_config(sections)
    fingerprint = own_fingerprint(sections)
    draft = legacy.read(folder() / 'draft.json')
    receipt = legacy.read(folder() / 'receipt.json')
    has_native = any(ident in sections for ident in OWNED)
    local = draft.get('config')
    matching = isinstance(local, dict) and all(compiled(uci.scalar(local.get(key))) ==
               compiled(actual[key]) for key in LIST_FIELDS) and local.get('node') == actual['node']
    if isinstance(local, dict) and (draft.get('based_on') == fingerprint or matching or not has_native):
        config, origin = normalize(local), 'draft'
    elif has_native:
        config, origin = normalize(actual), 'passwall_acl'
    else:
        config, origin = initial_config(sections, main, nodes), 'empty'
    blockers = []
    try:
        guard(sections)
    except RuntimeError as exc:
        blockers.append(str(exc))
    if snap['pending']:
        blockers.append('PassWall 有待保存配置，请先在 PassWall 保存或撤销后应用设备规则')
    latent = main.get('acl_enable', '0') != '1' and any(row.get('.type') == 'acl_rule' and
             ident != ACL_ID and row.get('enabled') == '1' for ident, row in sections.items())
    if latent:
        blockers.append('访问控制总开关当前关闭，已有其他启用规则；请先在 PassWall 整理并启用访问控制')
    mode = policy_mode(sections)
    current = legacy.digest({'uci': snap['digest'], 'draft': draft, 'devices': group})
    return {'snapshot': snap, 'global': main, 'nodes': nodes, 'group': group, 'config': config,
            'actual': actual, 'origin': origin, 'fingerprint': fingerprint, 'receipt': receipt,
            'revision': current, 'mode': mode, 'has_native': has_native, 'blockers': blockers,
            'controlled': scope_ready(group, sections), 'schema': acl_schema(main)}


def metadata():
    state = read_state()
    main = state['global']
    return {'enabled': main.get('enabled') == '1', 'acl_enabled': main.get('acl_enable') == '1',
            'cores': sorted({node['core'] for node in state['nodes'] if node['core']}),
            'nodes': state['nodes'], 'schema': state['schema']}


def configuration():
    state = read_state()
    info = {'mode': 'device_acl', 'controlled': state['controlled'], 'policy_mode': state['mode'],
            'proxy_list_enabled': state['controlled'] and state['mode'] == 'proxy',
            'direct_list_enabled': state['controlled'], '_state': state}
    return info, folder(), own_parts(state['snapshot']['sections']), state['actual'], state['revision']


@contextmanager
def lock():
    runtime().mkdir(parents=True, exist_ok=True, mode=0o700)
    with (runtime() / 'native-rules.lock').open('a') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('设备访问控制正在更新，请稍后重试') from None
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
                result.append({'type': kind, 'key': key, 'config': config, 'path': str(path)})
        except (OSError, ValueError, IndexError):
            continue
    return result[:32]


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


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    content = (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    write_bytes(path, content, 0o600)
    return content


def status():
    try:
        state = read_state()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        return {'ok': True, 'available': False, 'mode': 'device_acl', 'config': dict.fromkeys(FIELDS, ''),
                'blockers': [str(exc)], 'warnings': [], 'revision': '', 'nodes': [], 'devices_ready': False}
    main, config, receipt = state['global'], state['config'], state['receipt']
    cores = live_cores()
    loaded = runtime_current(state, cores)
    node = next((row for row in state['nodes'] if row['id'] == config['node'] and row['available']), None)
    warnings = []
    if state['has_native'] and not state['controlled']:
        warnings.append('设备访问控制的范围或总开关已有变化，应用会绑定当前已确认的两台设备')
    equal = all(compiled(config[key]) == compiled(state['actual'][key]) for key in LIST_FIELDS) and config['node'] == state['actual']['node']
    pending = (not loaded if state['has_native'] else False) or not equal
    telemetry = legacy.read(runtime() / 'connections.json')
    telemetry['fresh'] = type(telemetry.get('epoch')) in (int, float) and 0 <= time.time() - telemetry['epoch'] < 15
    return {'ok': True, 'available': True, 'mode': 'device_acl', 'revision': state['revision'],
            'config': config, 'file_config': state['actual'], 'config_source': state['origin'],
            'nodes': state['nodes'], 'device_group': state['group'], 'devices_ready': len(state['group']) == 2,
            'policy_mode': state['mode'], 'controlled': state['controlled'], 'loaded': loaded,
            'enabled': state['mode'] == 'proxy' and loaded, 'running': service_running(cores),
            'passwall_enabled': main.get('enabled') == '1', 'acl_id': ACL_ID, 'node_id': NODE_ID,
            'can_apply': len(state['group']) == 2 and bool(node) and not state['blockers'],
            'can_direct': len(state['group']) == 2 and not state['blockers'],
            'can_release': state['has_native'] and not state['blockers'],
            'counts': {key: len(host_rules(config[key])) for key in LIST_FIELDS},
            'active_counts': {key: len(host_rules(state['actual'][key])) for key in LIST_FIELDS},
            'switches': {'acl_enabled': main.get('acl_enable') == '1'},
            'environment': {'cores': sorted({item['type'] for item in cores}), 'selected_core': node['core'] if node else '',
                            'rules_path': 'PassWall UCI · ' + GROUP_ID, 'schema': state['schema']},
            'pending_apply': pending, 'receipt': receipt, 'blockers': state['blockers'], 'warnings': warnings,
            'telemetry': {key: telemetry.get(key) for key in ('state', 'fresh', 'sampled_cores', 'limit', 'errors')}}


def managed_sections(state, config, mode):
    rows = dict.fromkeys(OWNED)
    if mode == 'released':
        return rows
    if len(state['group']) != 2:
        raise ValueError('请先在设备配置确认 Portal 和 PS5，再应用设备接管')
    acl = {'.type': 'acl_rule', 'ps_accel_owner': OWNER, 'enabled': '1', 'remarks': 'PS Accel · Portal / PS5',
           'sources': [state['group'][role]['mac'] for role in ('portal', 'ps5')],
           'use_global_config': '0', 'tcp_no_redir_ports': '1:65535' if mode == 'direct' else 'disable',
           'udp_no_redir_ports': '1:65535' if mode == 'direct' else 'disable',
           'tcp_redir_ports': '1:65535', 'udp_redir_ports': '1:65535',
           'use_direct_list': '0', 'use_proxy_list': '0', 'use_block_list': '0', 'use_gfw_list': '0',
           'chn_list': '0', 'tcp_proxy_mode': 'proxy', 'udp_proxy_mode': 'proxy',
           'use_default_dns': 'direct'}
    if state['schema'] == 'single_node':
        acl.update(mode='0' if mode == 'direct' else '1', node=NODE_ID if mode == 'proxy' else 'nil')
    else:
        acl.update(tcp_node=NODE_ID if mode == 'proxy' else 'nil', udp_node=NODE_ID if mode == 'proxy' else 'nil')
    rows[ACL_ID] = acl
    if mode == 'direct':
        # Preserve the last shunt draft while this ACL explicitly bypasses proxying.
        rows.update({ident: state['snapshot']['sections'].get(ident) for ident in OWNED if ident != ACL_ID})
        return rows
    selected = next((node for node in state['nodes'] if node['id'] == config['node'] and node['available']), None)
    if selected is None:
        raise ValueError('请选择本机 PassWall 已保存的实际代理出口')
    node = {'.type': 'nodes', 'ps_accel_owner': OWNER, 'remarks': 'PS Accel · 两设备域名分流',
            'type': 'Xray' if selected['core'] == 'xray' else 'sing-box', 'protocol': '_shunt', 'shunt_group': GROUP_ID,
            'default_node': '_direct', 'domainStrategy': 'IPIfNonMatch', 'ps_accel_exit': config['node'], LAN_RULE: '_direct'}
    rows[NODE_ID] = node
    rows[LAN_RULE] = {'.type': 'shunt_rules', 'ps_accel_owner': OWNER, 'group': GROUP_ID,
                      'remarks': 'PS Accel · 局域网直连', 'network': 'tcp,udp', 'ip_list': LAN_NETWORKS}
    for key, ident, outbound, label in (('exclusions', DIRECT_RULE, '_direct', '直连域名'),
                                       ('domains', PROXY_RULE, config['node'], '代理域名')):
        text = compiled(config[key])
        if text:
            rows[ident] = {'.type': 'shunt_rules', 'ps_accel_owner': OWNER, 'group': GROUP_ID,
                           'remarks': 'PS Accel · ' + label, 'network': 'tcp,udp', 'domain_list': text}
            node[ident] = outbound
    acl.update(dns_shunt='dnsmasq', dns_mode=selected['core'])
    for key in ('remote_dns', 'v2ray_dns_mode', 'remote_dns_doh', 'remote_dns_client_ip', 'remote_rewrite_ttl'):
        value = uci.scalar(state['global'].get(key))
        if value:
            acl[key] = value
    if selected['core'] == 'xray' and acl.get('v2ray_dns_mode') in ('http3', 'tls', 'quic'):
        # Match PassWall's native fallback when a shunt switches DNS cores.
        acl.update(v2ray_dns_mode='tcp', remote_dns='1.1.1.1#53')
    return rows


class RulesCancelled(RuntimeError):
    pass


def checked_revision(state, expected):
    if not isinstance(expected, str) or not re.fullmatch(r'[0-9a-f]{64}', expected):
        raise ValueError('请重新读取设备专属规则后保存')
    if state['revision'] != expected:
        raise RuntimeError('设备规则、设备身份或 PassWall 配置已有修改，请重新读取后保存')


def save(request):
    config = normalize(request)
    with lock():
        state = read_state()
        checked_revision(state, request.get('revision'))
        guard(state['snapshot']['sections'])
        write_json(folder() / 'draft.json', {'config': config, 'based_on': state['fingerprint'], 'time': time.time()})
        current = read_state()
    return {'ok': True, 'config': config, 'revision': current['revision'], 'pending_apply': True,
            'notice': '设备专属名单草稿已保存，点击“应用设备规则”启用这组分流'}


def restore_native(before, replacements, applied_globals):
    current = uci.snapshot()
    guard(current['sections'])
    undo = {}
    for ident, desired in replacements.items():
        actual = current['sections'].get(ident)
        if actual == (uci.canonical(desired) if desired else None):
            undo[ident] = before['snapshot']['sections'].get(ident)
        elif actual != before['snapshot']['sections'].get(ident):
            raise RuntimeError('恢复期间设备规则发生外部修改，请在 PassWall 检查专属访问控制')
    global_changes = {}
    _ident, main = uci.global_section(current['sections'])
    original = before['global'].get('acl_enable')
    other_active = any(row.get('.type') == 'acl_rule' and ident != ACL_ID and row.get('enabled') == '1'
                       for ident, row in current['sections'].items())
    if applied_globals and main.get('acl_enable') == applied_globals.get('acl_enable'):
        if original == '1' or not other_active:
            global_changes['acl_enable'] = original
    data = uci.stage(current, undo, global_changes, first_acl=ACL_ID if undo.get(ACL_ID) else None)
    if current['path'].read_bytes() != current['data'] or uci.command('changes', 'passwall'):
        raise RuntimeError('恢复期间 PassWall 配置正在更新，请检查设备专属访问控制')
    write_bytes(current['path'], data, current['mode'])


def mutate(request, mode, cancel=lambda: False):
    with lock():
        state = read_state()
        checked_revision(state, request.get('revision'))
        if mode == 'released':
            guard(state['snapshot']['sections'])
            if state['snapshot']['pending']:
                raise RuntimeError('PassWall 有待保存配置，请先保存或撤销后解除接管')
        elif state['blockers']:
            raise RuntimeError('；'.join(state['blockers']))
        config = normalize(request) if mode == 'proxy' else state['config']
        replacements = managed_sections(state, config, mode)
        main, receipt = state['global'], state['receipt']
        owned_switch = receipt.get('acl_switch_owned', False)
        global_changes = {}
        if mode != 'released' and main.get('acl_enable', '0') != '1':
            global_changes['acl_enable'] = '1'
            owned_switch = True
        if mode == 'released' and owned_switch and main.get('acl_enable') == '1':
            other_active = any(row.get('.type') == 'acl_rule' and ident != ACL_ID and row.get('enabled') == '1'
                               for ident, row in state['snapshot']['sections'].items())
            if not other_active:
                global_changes['acl_enable'] = receipt.get('acl_switch_previous')
        if cancel():
            raise RulesCancelled('设备接管任务已取消')
        data = uci.stage(state['snapshot'], replacements, global_changes, first_acl=ACL_ID if mode != 'released' else None)
        # Revalidate the full config, draft, and shared device binding before the write.
        checked_revision(read_state(), state['revision'])
        if cancel():
            raise RulesCancelled('设备接管任务已取消')
        snap = state['snapshot']
        written = reload_attempted = False
        draft_path, receipt_path = folder() / 'draft.json', folder() / 'receipt.json'
        backups = {path: path.read_bytes() if path.exists() else None for path in (draft_path, receipt_path)}
        local_written = {}
        try:
            write_bytes(snap['path'], data, snap['mode'])
            written = True
            if cancel():
                raise RulesCancelled('设备接管任务已取消，原策略已恢复')
            # A scoped ACL may run while global proxying is disabled. Preserve a
            # manually stopped global service until the user starts it in PassWall.
            running = service_running()
            reloaded = running or (mode != 'released' and main.get('enabled') != '1')
            if reloaded:
                reload_attempted = True
                reload_passwall()
                if mode != 'released' and not source_list(state['group']):
                    raise RuntimeError('PassWall 专属访问控制载入待确认，请检查 PassWall 日志')
                if mode == 'proxy' and not native_core_present(live_cores()):
                    raise RuntimeError('PassWall 设备分流核心启动待确认，请检查所选节点')
            latest = read_state()
            for ident, wanted in replacements.items():
                actual = latest['snapshot']['sections'].get(ident)
                if actual != (uci.canonical(wanted) if wanted else None):
                    raise RuntimeError('应用期间设备专属规则发生外部修改，请重新读取')
            if cancel():
                raise RulesCancelled('设备接管任务已取消，原策略已恢复')
            local_written[draft_path] = write_json(draft_path, {'config': config, 'based_on': latest['fingerprint'], 'time': time.time()})
            updated = {'state': mode, 'time': time.time(), 'reloaded': reloaded, 'pending_apply': not reloaded,
                       'acl_switch_owned': owned_switch if mode != 'released' else False,
                       'acl_switch_previous': receipt.get('acl_switch_previous', main.get('acl_enable'))}
            if reloaded:
                updated.update(applied_fingerprint=latest['fingerprint'], applied_at=time.time())
            local_written[receipt_path] = write_json(receipt_path, updated)
            current = read_state()
        except Exception as exc:
            for path, content in local_written.items():
                if has_content(path, content):
                    if backups[path] is None:
                        path.unlink(missing_ok=True)
                    else:
                        write_bytes(path, backups[path], 0o600)
            if written:
                try:
                    restore_native(state, replacements, global_changes)
                    if reload_attempted:
                        reload_passwall()
                except Exception as recovery:
                    write_json(folder() / 'recovery.json', {'time': time.time(), 'parts': own_parts(snap['sections']),
                               'acl_enable': main.get('acl_enable'), 'error': str(recovery)})
                    raise RuntimeError('设备策略恢复待检查，请在 PassWall 检查 PS Accel 专属访问控制') from exc
            raise
        (folder() / 'recovery.json').unlink(missing_ok=True)
    notice = ({'proxy': '两设备域名规则已应用，其余流量默认直连', 'direct': 'Portal 和 PS5 已切换为全部直连',
               'released': '设备接管已解除，两台设备恢复原 PassWall 策略'}[mode] if reloaded else
              '设备配置已保存，PassWall 启动后加载这组策略')
    return {'ok': True, 'config': config, 'revision': current['revision'], 'policy_mode': mode,
            'reloaded': reloaded, 'pending_apply': not reloaded, 'notice': notice}


def apply(request, cancel=lambda: False):
    return mutate(request, 'proxy', cancel)


def direct(request, cancel=lambda: False):
    return mutate(request, 'direct', cancel)


def release(request, cancel=lambda: False):
    return mutate(request, 'released', cancel)


def devices_controlled():
    try:
        section = uci.snapshot()['sections'].get(ACL_ID, {})
        return section.get('ps_accel_owner') == OWNER and section.get('enabled') == '1'
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        return False


def migrate():
    """Detach the legacy hook; keep saved device rules and start new lists empty."""
    with lock():
        manifest = legacy.read(legacy.folder() / 'manifest.json')
        hooked = legacy.PASSWALL.exists() and legacy.BEGIN in legacy.PASSWALL.read_text()
        if manifest.get('enabled') or hooked:
            legacy.detach()
        if not (folder() / 'draft.json').exists():
            try:
                state = read_state()
                write_json(folder() / 'draft.json', {'config': state['config'], 'based_on': state['fingerprint'], 'time': time.time()})
            except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                pass


def detach():
    try:
        state = read_state()
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        if not uci.CONFIG.exists():
            return
        raise
    if state['has_native']:
        release({'revision': state['revision']})
    if legacy.read(legacy.folder() / 'manifest.json').get('enabled'):
        legacy.detach()


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
    scope = dict({key: '\n'.join(host_rules(config.get(key, ''))) for key in LIST_FIELDS}, mode='device_acl',
                 scope_enabled=info.get('controlled', False), proxy_list_enabled=info.get('proxy_list_enabled', False),
                 direct_list_enabled=info.get('direct_list_enabled', False))
    readable = [item for item in cores if item['type'] == 'sing-box' and
                item['config'].get('experimental', {}).get('clash_api', {}).get('external_controller')]
    readable.sort(key=lambda item: NODE_ID not in item.get('path', ''))
    if enabled and sources:
        report = tracker.sample(readable, sources, {'mode': 'device_acl', 'config': scope})
    else:
        report = {'epoch': time.time(), 'generation': tracker.generation, 'connections': [], 'sampled_cores': 0,
                  'state': 'disabled' if not enabled else 'waiting', 'policy_scope': scope}
    report['source'], report['core_types'], report['limit'] = 'passwall_core', sorted({item['type'] for item in cores}), TRAFFIC_LIMIT
    if enabled and sources and not report.get('sampled_cores'):
        report['state'] = 'unavailable' if cores else 'waiting'
        report['limit'] = ('当前 Xray 的聚合统计需要域名级连接数据源后，才能按域名累计字节。DNS 与批次记录持续采集。'
                           if 'xray' in report['core_types'] else
                           '等待本机 Sing-box 提供可读的回环 Clash API 连接接口。DNS 与批次记录持续采集。')
    return report


def watch():
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
                    info, _root, _parts, config, _revision = configuration()
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
    elif sys.argv[1:] in (['resume'], ['migrate']):
        migrate()
    elif sys.argv[1:] == ['detach']:
        detach()
    else:
        raise SystemExit('请选择设备规则迁移、解除接管或流量观察操作')
