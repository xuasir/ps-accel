"""Bounded, authenticated loopback Sing-box evidence and fixed-target probes."""
from collections import OrderedDict
import base64
import hashlib
import http.client
import ipaddress
import json
import math
import socket
import ssl
import subprocess
import sys
import time

from sony_domains import (FIRMWARE_HOST, DYNAMIC_PROXY_RULES, domain_info, domain_rules,
                         matches_domain, proxy_rules)

PROBE_TAG = 'ps-accel-psportal-probe'
MAX_CONNECTIONS = 128
API_LIMIT = 2 * 1024 * 1024
PROBE_TARGETS = (
    ('auth.api.playstation.com', 443, 'proxy'),
    ('remoteplay.dl.playstation.net', 443, 'proxy'),
    ('www.google.com', 443, 'proxy'),
    (FIRMWARE_HOST, 80, 'direct'),
)


def core_key(config):
    return ','.join(sorted(str(x.get('type')) + ':' + str(x.get('tag', '')) + ':' + str(x.get('listen_port', 0))
                           for x in config.get('inbounds', []) if x.get('type') in ('redirect', 'tproxy')
                           and x.get('network') != 'udp'))


def evidence_revision(manifest, sources):
    return hashlib.sha256(json.dumps({'config': manifest.get('config'), 'sources': sources,
                                     'expected_outbounds': manifest.get('expected_outbounds', {}),
                                     'dynamic_rules': DYNAMIC_PROXY_RULES},
                                    sort_keys=True).encode()).hexdigest()


def outbound_signature(config):
    outbound = next((x for x in config.get('outbounds', []) if x.get('tag') == 'ps-accel-psportal'), {})
    return hashlib.sha256(json.dumps(outbound, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def loopback_endpoint(value):
    if not isinstance(value, str):
        raise ValueError('管理接口需要回环地址')
    host, separator, raw_port = value.rpartition(':')
    host = host.strip('[]')
    address = ipaddress.ip_address(host)
    if not separator or not address.is_loopback or not raw_port.isdigit() or not 1 <= int(raw_port) <= 65535:
        raise ValueError('管理接口需要回环地址和有效端口')
    return str(address), int(raw_port)


def api_connections(config, timeout=1):
    api = config.get('experimental', {}).get('clash_api', {})
    host, port = loopback_endpoint(api.get('external_controller', ''))
    secret = api.get('secret', '')
    if not isinstance(secret, str) or len(secret) > 256 or any(ord(x) < 32 for x in secret):
        raise ValueError('管理接口凭据格式需要检查')
    client = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        headers = {'Authorization': 'Bearer ' + secret} if secret else {}
        client.request('GET', '/connections', headers=headers)
        response = client.getresponse()
        if response.status != 200:
            raise RuntimeError('核心连接接口返回 ' + str(response.status))
        raw = response.read(API_LIMIT + 1)
        if len(raw) > API_LIMIT:
            raise ValueError('核心连接记录超过容量限制')
        payload = json.loads(raw)
        rows = payload.get('connections') if isinstance(payload, dict) else None
        if not isinstance(rows, list):
            raise ValueError('核心连接记录格式需要检查')
        return rows
    finally:
        client.close()


def finite_number(value, default=0):
    return value if type(value) in (int, float) and math.isfinite(value) and value >= 0 else default


class ConnectionTracker:
    def __init__(self):
        self.connections = OrderedDict()
        self.revision = ''
        self.health = {'capacity_drops': 0, 'malformed': 0}

    def sample(self, configs, sources, manifest, epoch=None):
        epoch = time.time() if epoch is None else epoch
        revision = evidence_revision(manifest, sources)
        if revision != self.revision:
            self.connections.clear()
            self.revision = revision
        owners = {ip: role for role, ips in sources.items() for ip in ips}
        wanted = manifest.get('config', {})
        included, excluded = proxy_rules(wanted), domain_rules(wanted.get('exclusions', ''))
        successful, seen, errors = set(), set(), []
        for item in configs[:8]:
            config, key = item['config'], core_key(item['config'])
            try:
                rows = api_connections(config)
            except (OSError, ValueError, RuntimeError, http.client.HTTPException):
                errors.append('一个核心连接接口暂时不可用，请检查入口载入与诊断接口')
                continue
            successful.add(key)
            direct_tags = {x.get('tag') for x in config.get('outbounds', []) if x.get('type') == 'direct'}
            for row in rows[:4096]:
                if not isinstance(row, dict) or not isinstance(row.get('metadata'), dict):
                    self.health['malformed'] += 1
                    continue
                metadata = row['metadata']
                source = str(metadata.get('sourceIP', ''))
                if source not in owners or str(metadata.get('network', '')).lower() != 'tcp':
                    continue
                host = str(metadata.get('host') or '').lower().rstrip('.')[:253]
                ident = row.get('id')
                if not isinstance(ident, str) or not 1 <= len(ident) <= 128:
                    self.health['malformed'] += 1
                    continue
                connection_id = hashlib.sha256((key + ':' + ident).encode()).hexdigest()[:24]
                seen.add(connection_id)
                chain = row.get('chains', [])
                chain = [x[:128] for x in chain[:16] if isinstance(x, str)] if isinstance(chain, list) else []
                tagged = 'ps-accel-psportal' in chain
                expected = manifest.get('expected_outbounds', {}).get(key)
                selected = tagged and (not expected or outbound_signature(config) == expected)
                direct = bool(direct_tags.intersection(chain)) and not selected
                upload, download = finite_number(row.get('upload')), finite_number(row.get('download'))
                info = domain_info(host)
                phase = 'CONNECTED' if info['category'] == 'signaling' and download else \
                    'AUTH' if info['category'] == 'auth' else 'SIGNALING' if info['category'] == 'signaling' else 'CONNECTED'
                previous = self.connections.get(connection_id, {})
                trace = list(previous.get('trace', []))
                def stage(name):
                    if not any(event['stage'] == name for event in trace):
                        trace.append({'stage': name, 'epoch': epoch})
                stage('core_observed')
                if chain:
                    stage('route_selected')
                if upload:
                    stage('client_payload')
                if download:
                    stage('upstream_payload')
                value = {'id': connection_id, 'core': key, 'device': owners[source], 'source_ip': source,
                         'source_port': str(metadata.get('sourcePort', ''))[:5], 'domain': host,
                         'address': str(metadata.get('destinationIP', ''))[:45],
                         'port': str(metadata.get('destinationPort', ''))[:5],
                         'first_epoch': previous.get('first_epoch', epoch), 'last_epoch': epoch,
                         'phase': phase, 'phase_inferred': True, 'active': True,
                         'bytes_up': upload, 'bytes_down': download, 'outbound_chain': chain,
                         'route': 'selected' if selected else 'previous' if tagged else 'direct' if direct else 'original' if chain else 'unknown',
                         'expected_proxy': matches_domain(host, included)
                             and not matches_domain(host, excluded)
                             and str(metadata.get('destinationPort', '')) in wanted.get('ports', '').split(','),
                         'failure': '', 'trace': trace[-8:], 'missing_samples': 0, **info}
                self.connections[connection_id] = value
                self.connections.move_to_end(connection_id)
                if len(self.connections) > MAX_CONNECTIONS:
                    self.connections.popitem(last=False)
                    self.health['capacity_drops'] += 1
        for ident, value in list(self.connections.items()):
            if value['source_ip'] not in owners or epoch - value['last_epoch'] > 900:
                del self.connections[ident]
                continue
            if ident not in seen and value['core'] in successful and value['active']:
                value['missing_samples'] += 1
                if value['missing_samples'] >= 2:
                    value['active'], value['phase'] = False, 'DISCONNECTED'
                    value['trace'] = (value['trace'] + [{'stage': 'core_closed', 'epoch': epoch}])[-8:]
                    if value['bytes_up'] and not value['bytes_down']:
                        value['failure'] = 'upstream_response_missing'
        rows = [dict(value) for value in reversed(self.connections.values())]
        confirmed = [x for x in rows if x['last_epoch'] == epoch and x['core'] in successful and x['route'] == 'selected']
        return {'epoch': epoch, 'state': 'observing' if successful else 'waiting',
                'revision': revision,
                'sampled_cores': len(successful), 'errors': errors,
                'connections': rows, 'health': dict(self.health),
                'traffic_verified': bool(confirmed), 'matched_connections': len(confirmed),
                'download_direct_verified': any(x['last_epoch'] == epoch and x['core'] in successful and
                                               x['purpose'] == 'firmware' and x['route'] == 'direct'
                                               and x['bytes_down'] for x in rows),
                'limit': '阶段按域名与核心传输推断；登录结果结合终端确认。短连接可能在两次采样间完成。'}


def dns_probe(host, port, timeout=3):
    code = ('import json,socket,sys; '
            'print(json.dumps(sorted({x[4][0] for x in socket.getaddrinfo(sys.argv[1],int(sys.argv[2]),type=socket.SOCK_STREAM)})))')
    try:
        result = subprocess.run([sys.executable, '-c', code, host, str(port)],
                                capture_output=True, timeout=timeout, check=False)
        addresses = json.loads(result.stdout[:2048]) if result.returncode == 0 else []
        return {'ok': bool(addresses), 'addresses': addresses[:8], 'scope': 'router_resolver'}
    except (OSError, ValueError, subprocess.SubprocessError):
        return {'ok': False, 'addresses': [], 'scope': 'router_resolver'}


def probe_target(host, port, path, endpoint, secret, timeout=4):
    """Check a fixed target through the authenticated dedicated core inbound."""
    started = time.monotonic()
    result = dict(domain=host, port=port, path=path, **domain_info(host),
                  tcp=False, tls=None if port == 80 else False, stage='probe_entry', failure='')
    result['dns'] = dns_probe(host, port)
    started = time.monotonic()
    sock = None
    try:
        proxy_host, proxy_port = loopback_endpoint(endpoint)
        sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
        credential = base64.b64encode((path + ':' + secret).encode()).decode()
        request = ('CONNECT ' + host + ':' + str(port) + ' HTTP/1.1\r\nHost: ' + host + ':' + str(port) +
                   '\r\nProxy-Authorization: Basic ' + credential + '\r\n\r\n')
        sock.sendall(request.encode('ascii'))
        result['stage'] = 'target_tcp'
        response = bytearray()
        while not response.endswith(b'\r\n\r\n') and len(response) < 4096 and time.monotonic() - started < timeout:
            sock.settimeout(max(.05, timeout - (time.monotonic() - started)))
            chunk = sock.recv(1)
            if not chunk:
                break
            response.extend(chunk)
        if not response.endswith(b'\r\n\r\n') or (not bytes(response).startswith(b'HTTP/1.1 200 ') and not bytes(response).startswith(b'HTTP/1.0 200 ')):
            result['failure'], result['stage'] = 'target_connect_failure', 'target_tcp'
            return result
        result['tcp'], result['stage'] = True, 'target_tcp'
        if port != 80:
            sock.settimeout(max(.05, timeout - (time.monotonic() - started)))
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
            result['tls'], result['stage'] = True, 'target_tls'
    except ssl.SSLCertVerificationError:
        result['failure'] = 'certificate_validation'
    except (OSError, ValueError, ssl.SSLError):
        result['failure'] = 'tls_failure' if result['tcp'] else 'probe_entry_failure' if result['stage'] == 'probe_entry' else 'target_connect_failure'
    finally:
        if sock is not None:
            sock.close()
        result['duration_ms'] = round((time.monotonic() - started) * 1000)
    return result


def probe(configs, manifest, cancel=lambda: False):
    specs = manifest.get('diagnostics', {}).get('cores', {})
    secret = manifest.get('diagnostics', {}).get('secret', '')
    targets, errors = [], []
    for item in configs[:8]:
        key = core_key(item['config'])
        spec = specs.get(key, {})
        if not spec.get('probe_port') or not secret:
            continue
        endpoint = '127.0.0.1:' + str(spec['probe_port'])
        for host, port, path in PROBE_TARGETS:
            if cancel():
                return {'epoch': time.time(), 'targets': targets, 'errors': [], 'healthy': False, 'cancelled': True}
            targets.append(probe_target(host, port, path, endpoint, secret))
        break
    if not targets:
        errors.append('重新预览并启用透明代理，以载入本地出口检测入口')
    return {'epoch': time.time(), 'targets': targets, 'errors': errors,
            'healthy': bool(targets) and all(x['dns']['ok'] and x['tcp'] and x['tls'] is not False for x in targets),
            'limit': 'DNS 使用路由器解析器，TCP/TLS 使用检测入口指定出口；设备实际命中依据核心连接记录。'}
