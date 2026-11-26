#!/usr/bin/env python3
"""Narrow rpcd API and asynchronous LuCI jobs; no caller-supplied commands/paths."""
from contextlib import contextmanager
import datetime
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid
import re

import portal_openwrt as port
import portal_policy as policy
import passwall_rules as rules
from profiles import public_profiles
from stream_quality import public_quality
from domain_tracker import host_name
from domain_monitor import DomainMonitor, MAX_BATCHES, MAX_BATCH_DOMAINS, MAX_BATCH_EVENTS, batch_summary, device_macs
from sony_domains import domain_info
from observability import (LogPreferences, OBSERVATION_LIMIT, correlate, load_preferences, merge_events, new_incident,
                           read_bounded, read_domain_events, read_incidents, record_failure,
                           save_incident, save_preferences, utc)

JOBS = port.RUNTIME / 'luci'
SERVICE = '/etc/init.d/ps-accel'
CLI = '/usr/sbin/ps-accel'
START_TIMEOUT = 80
STOP_TIMEOUT = 120
CHILD_TIMEOUTS = {'configure': 120, 'baseline': 180, 'try': 210, 'doctor': 45,
                  'repair': 45, 'profile': 30, 'start': 20, 'stop': 20}
TERMINAL_STATES = {'complete', 'cancelled', 'failed'}
READ_ERRORS = (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError)
METHODS = {'status': {}, 'details': {}, 'devices': {}, 'device_save': {key: '' for key in port.DEVICE_FIELDS},
           'logs': {'kind': ''},
           'configure': {'bridge': '', 'address': '', 'ps5_ip': '', 'portal_ip': '', 'profile': ''},
           'profile': {'profile': ''}, 'diagnostics': {}, 'proxy_diagnostics': {},
           'logging': {'mode': '', 'domains': 0, 'tag': ''}, 'domains': {'incident': ''}, 'incident': {'note': ''},
           'domain_monitor': {'batch': '', 'incident': ''}, 'domain_batch_start': {},
           'baseline': {}, 'trial': {}, 'start': {'autostart': 0}, 'stop': {}, 'repair': {}, 'doctor': {}}
METHODS.update({'psportal_status': {},
                'psportal_save': dict({key: '' for key in rules.FIELDS}, revision=''),
                'psportal_apply': dict({key: '' for key in rules.FIELDS}, revision='')})


def optional(path, default=None):
    try:
        value = port.read_json(path)
        if isinstance(value, dict):
            return value
    except (OSError, ValueError):
        pass
    return {} if default is None else default


def process_identity(pid):
    try:
        fields = Path('/proc', str(int(pid)), 'stat').read_text().rpartition(')')[2].split()
        return fields[19] if fields[0] != 'Z' else None
    except (OSError, ValueError, TypeError, IndexError):
        return None


def alive(pid, identity):
    return bool(pid and identity and process_identity(pid) == identity)


@contextmanager
def control_lock(timeout=3):
    JOBS.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (JOBS / 'control.lock').open('a') as f:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError('管理任务正在更新，请稍后重试。') from None
                time.sleep(.05)
        yield


def current_job():
    job = optional(JOBS / 'job.json')
    worker_alive = alive(job.get('pid'), job.get('identity'))
    job['busy'] = worker_alive and job.get('state') not in TERMINAL_STATES
    job['stopping'] = bool(job['busy'] and job.get('id') and (JOBS / ('cancel.' + job['id'])).exists())
    job['orphan_active'] = orphaned_child(job) is not None
    if not worker_alive and job.get('state') in ('queued', 'running'):
        job['state'] = 'failed'
        job['error'] = '后台任务意外结束，请停止服务并恢复网络。'
    return job


def orphaned_child(job):
    candidates = [{'pid': job.get('child_pid'), 'identity': job.get('child_identity'), 'action': job.get('action')},
                  job.get('orphan')]
    for child in candidates:
        if (isinstance(child, dict) and child.get('pid') and child.get('identity')
                and alive(child['pid'], child['identity'])):
            return child
    return None


def update_job(job_id, **values):
    with control_lock():
        job = optional(JOBS / 'job.json')
        if job.get('id') != job_id:
            raise RuntimeError('Job ownership changed')
        job.update(values)
        record_job(job)


def record_job(job):
    port.atomic(JOBS / 'job.json', job)
    try:
        port.atomic(JOBS / (job_log_kind(job.get('action', '')) + '.json'), job)
    except READ_ERRORS as exc:
        message('功能任务摘要保存待确认：' + str(exc), error=True)


def feature_jobs(current):
    result = {}
    for kind in ('devices', 'bitrate', 'proxy'):
        job = current if current.get('id') and job_log_kind(current.get('action', '')) == kind else optional(JOBS / (kind + '.json'))
        if job:
            job = dict(job)
            if job.get('id') != current.get('id'):
                job['busy'] = False
                if job.get('state') in ('queued', 'running'):
                    job.update(state='failed', error='此前后台任务结束，结果待确认，请查看本功能日志')
            result[kind] = {key: value for key, value in job.items() if key != 'request'}
    return result


def message(text, error=False):
    try:
        print(text, file=sys.stderr if error else sys.stdout, flush=True)
    except (OSError, ValueError):
        pass


def best_effort_update(job_id, **values):
    """Final state reporting must allow process termination and recovery to finish."""
    try:
        update_job(job_id, **values)
        return True
    except Exception as exc:
        message('任务状态记录失败：' + str(exc), error=True)
        return False


def tail(path, limit=12000):
    try:
        with path.open('rb') as f:
            f.seek(0, 2)
            f.seek(max(0, f.tell() - limit))
            return f.read(limit).decode('utf-8', errors='replace')
    except OSError:
        return ''


def managed_state(peers=None):
    path = port.RUNTIME / 'engine.json'
    managed = optional(path)
    ready = optional(port.RUNTIME / 'engine-ready.json')
    if peers is None:
        peers = port.pids()
    process_alive = alive(managed.get('pid'), managed.get('identity'))
    running = bool(process_alive and managed.get('pid') in peers
                   and ready.get('pid') == managed.get('pid') and ready.get('ready') is True
                   and managed.get('generation') and ready.get('generation') == managed.get('generation'))
    return {'present': path.exists(), 'running': running, 'process_alive': process_alive, 'metadata': managed}


def status():
    """Dynamic polling: one bounded process query, local state, no config/log I/O."""
    job = current_job()
    report = optional(port.RUNTIME / 'status.json')
    warnings = []
    age = None
    try:
        peers = port.pids()
        state_known = True
    except READ_ERRORS as exc:
        peers, state_known = [], False
        warnings.append('进程状态查询失败：' + str(exc))
    try:
        stamp = datetime.datetime.fromisoformat(report['time'])
        age = (datetime.datetime.now(datetime.timezone.utc) - stamp).total_seconds()
        report_running = (report.get('state') == 'running' and report.get('pid') in peers and 0 <= age < 15)
    except (KeyError, ValueError, TypeError):
        report_running = False
    service = managed_state(peers)
    managed = service['metadata']
    if service['present']:
        running = service['running']
        stats_fresh = bool(report_running and report.get('pid') == managed.get('pid'))
    else:
        running = report_running
        stats_fresh = report_running
    counts = report.get('counts', {}) if stats_fresh or not running else {}
    if not isinstance(counts, dict):
        counts = {}
    health = report.get('observability', {})
    observability = dict(health if isinstance(health, dict) else {}, status_fresh=bool(stats_fresh or not running))
    started = managed.get('started_monotonic')
    elapsed = max(0, time.monotonic() - started) if isinstance(started, (int, float)) else 0
    recovery = optional(port.RUNTIME / 'recovery.json')
    lock_owner = ''
    try:
        lock_owner = port.ENGINE_LOCK.read_text().strip()
    except OSError:
        pass
    own_engine = ''
    try:
        own_engine = (port.RUNTIME / 'engine-pid').read_text().strip()
    except OSError:
        pass
    resources_present = port.HANDLE.exists() or (port.SYSNET / port.HOST).exists()
    recovery_pending = (port.RUNTIME / 'recovery-required').exists()
    return {'ok': True, 'details_revision': port.configuration_revision(),
            'running': running, 'mode': managed.get('mode', report.get('mode')),
            'state_known': state_known, 'status_warnings': warnings, 'engine_alive': service['process_alive'],
            'recovery_required': bool((recovery_pending or resources_present) and not running),
            'cleanup_pending': bool(resources_present and not recovery_pending and not service['process_alive']),
            'modified': counts.get('unique_modified_startups', 0),
            'last_modified': report.get('last_mutation'), 'job': {key: value for key, value in job.items() if key != 'request'},
            'feature_jobs': feature_jobs(job),
            'counts': counts, 'sample_time': report.get('time') if stats_fresh else None,
            'control_mbps': report.get('control_mbps', 0) if running and stats_fresh else 0,
            'uptime_seconds': elapsed if running and managed else report.get('uptime_seconds', 0) if running else 0,
            'observability': observability,
            'quality': public_quality(report.get('quality') if stats_fresh or not running else None,
                                      age, running, stats_fresh, managed.get('mode', report.get('mode'))),
            'foreign_relay': bool(lock_owner and lock_owner != own_engine),
            'recovery_errors': recovery.get('errors', report.get('errors', []))}


def details():
    """Static configuration and optional connection diagnostics, refreshed on changes."""
    revision = port.configuration_revision()
    warnings = []
    config = {key: '65' if key == 'profile' else '' for key in port.Settings.__dataclass_fields__}
    values = {}
    settings_valid = False
    try:
        values = port.uci_values()
        config.update({key: values.get(key, config[key]) for key in config})
        settings = port.Settings(**config).validate()
        settings_valid = True
        baseline = port.baseline_state(settings)
    except READ_ERRORS as exc:
        baseline = {'valid': False, 'reason': '配置读取或校验失败，请检查设备配置'}
        warnings.append(str(exc))
    autostart = False
    try:
        if values.get('enabled') == '1':
            autostart = port.command(SERVICE, 'enabled', check=False, timeout=3).returncode == 0
    except READ_ERRORS as exc:
        warnings.append('开机启动状态读取失败：' + str(exc))
    try:
        preferences = load_preferences(port.PERSIST / 'observability.json')
    except (OSError, ValueError, TypeError) as exc:
        preferences = LogPreferences()
        warnings.append('日志偏好读取失败：' + str(exc))
    binding = port.device_binding(values)
    enrollment = optional(port.PERSIST / 'auto-config.json')
    paired = (settings_valid and bool(binding) and enrollment.get('profile') == config['profile'] and
              enrollment.get('network') == {'interface': port.IFACE, 'ps5_ip': config['ps5_ip'],
                                            'portal_ip': config['portal_ip']})
    return {'ok': True, 'config': config, 'configured': paired,
            'devices_configured': bool(binding),
            'device_selectors': {role: binding.get(role + '_mac', config.get(role + '_ip', ''))
                                 for role in ('portal', 'ps5')},
            'details_revision': revision, 'details_warnings': warnings,
            'bridges': sorted(p.parent.name for p in port.SYSNET.glob('*/bridge') if p.is_dir()),
            'autostart': autostart, 'baseline_saved': (port.PERSIST / 'baseline.json').exists(),
            'baseline_valid': baseline['valid'], 'baseline_reason': baseline['reason'],
            'environment': port.environment(), 'profiles': public_profiles(),
            'logging': port.asdict(preferences)}


def devices():
    values = port.uci_values()
    binding = port.device_binding(values)
    return {'ok': True, 'config': {key: values.get(key, '') for key in port.DEVICE_FIELDS},
            'configured': bool(binding), 'binding': binding, 'devices': policy.inventory(),
            'proxy_enabled': policy.policy_enabled(policy.read(policy.folder() / 'manifest.json'))}


def save_devices(request):
    """Confirm LAN identities without creating a relay namespace or changing proxy rules."""
    request = port.validate_devices(request)
    with port.exclusive(), policy.lock():
        if (port.ENGINE_LOCK.exists() or (port.RUNTIME / 'recovery-required').exists()
                or port.HANDLE.exists() or (port.SYSNET / port.HOST).exists()):
            raise RuntimeError('请先停止码率增强并完成网络恢复，再保存设备配置')
        if policy.policy_enabled(policy.read(policy.folder() / 'manifest.json')):
            raise RuntimeError('请先停用透明代理，再保存设备配置')
        if not (port.SYSNET / request['bridge'] / 'bridge').is_dir():
            raise ValueError('所选 LAN 网桥待就绪，请检查设备所在网络')
        addresses = json.loads(port.command('ip', '-j', 'addr', 'show', 'dev', request['bridge'], timeout=3).stdout)
        networks = [ipaddress.IPv4Interface(str(item['local']) + '/' + str(item['prefixlen']))
                    for row in addresses for item in row.get('addr_info', []) if item.get('family') == 'inet']
        for role in ('portal', 'ps5'):
            ip = ipaddress.IPv4Address(request[role + '_ip'])
            if not any(ip in item.network and ip not in (item.ip, item.network.network_address,
                                                         item.network.broadcast_address) for item in networks):
                raise ValueError('两台设备需要使用所选 LAN 网桥内的独立地址')
        inventory = policy.inventory()
        missing = [request[role + '_ip'] for role in ('portal', 'ps5') if not any(
            request[role + '_ip'] in item['addresses'] for item in inventory)]
        for ip in missing:
            try:
                port.command('ping', '-I', request['bridge'], '-c', '1', '-W', '1', ip, check=False, timeout=3)
            except READ_ERRORS:
                pass
        if missing:
            inventory = policy.inventory()
        binding = {'config': request, 'confirmed_at': time.time()}
        for role in ('portal', 'ps5'):
            matches = [item['mac'] for item in inventory if request[role + '_ip'] in item['addresses']]
            if len(set(matches)) != 1:
                raise ValueError(('Portal' if role == 'portal' else 'PS5') +
                                 ' 地址与 MAC 待确认，请保持设备开机并刷新设备列表')
            binding[role + '_mac'] = matches[0]
        if binding['portal_mac'] == binding['ps5_mac']:
            raise ValueError('Portal 与 PS5 对应同一设备，请核对地址')
        previous = port.uci_values()
        old_binding = port.device_binding(previous)
        paths = [port.CONFIG_FILE, port.PERSIST / 'devices.json', port.PERSIST / 'auto-config.json',
                 port.PERSIST / 'baseline.json', port.RUNTIME / 'auto-baseline.json']
        backups = {path: path.read_bytes() if path.exists() else None for path in paths}
        try:
            for key, value in request.items():
                port.command('uci', 'set', 'ps_accel.main.' + key + '=' + value)
            port.command('uci', 'set', 'ps_accel.main.enabled=0')
            port.command('uci', 'commit', 'ps_accel')
            port.atomic(port.PERSIST / 'devices.json', binding)
            changed = (any(previous.get(key, '') != value for key, value in request.items()) or
                       any(old_binding.get(role + '_mac') != binding[role + '_mac'] for role in ('portal', 'ps5')))
            if changed:
                for path in paths[2:]:
                    path.unlink(missing_ok=True)
        except Exception:
            port.command('uci', 'revert', 'ps_accel', check=False)
            for path, content in backups.items():
                if content is None:
                    path.unlink(missing_ok=True)
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(content)
                    path.chmod(0o600)
            raise
    message('设备地址已确认，码率增强与域名监控共用这组设备。')
    try:
        port.command('/etc/init.d/ps-accel-observe', 'start', check=False, timeout=3)
    except READ_ERRORS as exc:
        message('域名观察服务启动待确认：' + str(exc), error=True)


def job_log_kind(action):
    if isinstance(action, str) and action.startswith('psportal_'):
        return 'proxy'
    return 'devices' if action == 'device_save' else 'bitrate'


def logs(kind):
    if kind == 'events':
        path = port.RUNTIME / 'events.log'
    elif kind == 'log':
        path = JOBS / 'job.log'
    else:
        path = JOBS / (kind + '.log')
        # Retain access to a pre-upgrade job until its feature gets a new task.
        if not path.exists() and job_log_kind(optional(JOBS / 'job.json').get('action', '')) == kind:
            path = JOBS / 'job.log'
    return {'ok': True, 'kind': kind, 'text': tail(path)}


def domains(incident_id=''):
    try:
        preferences = load_preferences(port.PERSIST / 'observability.json')
    except (OSError, ValueError, TypeError):
        preferences = LogPreferences()
    try:
        report = read_bounded(port.RUNTIME / 'domains.json')
        if not isinstance(report, dict):
            report = {}
    except (OSError, ValueError):
        report = {}
    items = report.get('domains', [])
    inventory_source = False
    if not items:
        try:
            inventory = read_bounded(port.PERSIST / 'domains.json')
            items = inventory.get('domains', [])
            inventory_source = True
        except (OSError, ValueError, AttributeError):
            items = []
    if not isinstance(items, list):
        items = []
    paired = {}
    if inventory_source:
        try:
            identity_path = port.PERSIST / 'devices.json'
            paired = read_bounded(identity_path if identity_path.exists() else port.PERSIST / 'auto-config.json', 16384)
            if not isinstance(paired, dict):
                paired = {}
        except (OSError, ValueError):
            paired = {}
    rows = []
    for item in items[:512]:
        if not isinstance(item, dict):
            continue
        if item.get('device') not in ('ps5', 'portal') or not isinstance(item.get('domain'), str):
            continue
        try:
            host_name(item['domain'])
        except ValueError:
            continue
        if inventory_source and item.get('device_mac') != paired.get(item.get('device', '') + '_mac'):
            continue
        row = {key: item[key] for key in ('device', 'domain', 'first_epoch', 'last_epoch', 'first_seen',
                                        'last_seen', 'counts', 'addresses', 'last_problem') if key in item}
        row['new_since_tag'] = bool(preferences.tag and isinstance(row.get('first_epoch'), (int, float))
                                   and row['first_epoch'] >= preferences.tag_since)
        row.update(domain_info(row['domain']))
        if not isinstance(row.get('counts'), dict):
            row['counts'] = {}
        if not isinstance(row.get('addresses'), list):
            row['addresses'] = []
        rows.append(row)
    incidents = read_incidents(port.PERSIST)
    selected = next((item for item in incidents if item['id'] == incident_id), None)
    if incident_id and selected is None:
        raise ValueError('失败记录已轮换，请选择其他记录')
    if selected is not None:
        selected = dict(selected)
        initial = selected.get('evidence', {}).get('events', [])
        events = merge_events(read_domain_events(port.RUNTIME), initial, report.get('recent', []))
        if not selected.get('captured_at'):
            selected['evidence'] = correlate(selected, events)
            selected['evidence']['coverage_start'] = report.get('coverage_start')
            coverage_start = report.get('coverage_start')
            selected['evidence']['coverage_limited'] = (type(coverage_start) not in (int, float)
                                                        or coverage_start > selected['epoch'] - 180
                                                        or report.get('state') != 'observing'
                                                        or bool(report.get('capture_drops') or report.get('rate_drops')))
    try:
        age = time.time() - datetime.datetime.fromisoformat(report['time']).timestamp()
        fresh = alive(report.get('pid'), report.get('identity')) and 0 <= age < 30
    except (KeyError, ValueError, TypeError):
        fresh = False
    try:
        _info, _root, _files, rule_config, _revision = rules.configuration()
    except READ_ERRORS:
        rule_config = dict.fromkeys(rules.FIELDS, '')
    return {'ok': True, 'logging': port.asdict(preferences), 'domains': rows,
            'dynamic_rules': [],
            'candidates': [dict(row, included=rules.matches(row['domain'], rules.host_rules(rule_config['domains'])),
                                excluded=rules.matches(row['domain'], rules.host_rules(rule_config['exclusions'])))
                           for row in rows if row.get('suggestion') == 'proxy'][:64],
            'observer': {'state': report.get('state', 'waiting') if preferences.domains else 'disabled',
                         'fresh': fresh, 'time': report.get('time'), 'bridge': report.get('bridge'),
                         'error': report.get('error', ''), 'health': report.get('health', {}),
                         'observability': report.get('observability', {}),
                         'snapshot_truncated': report.get('snapshot_truncated', False),
                         'traffic': report.get('traffic', {}),
                         'capture_drops': report.get('capture_drops', 0), 'rate_drops': report.get('rate_drops', 0)},
            'incidents': [{key: item.get(key) for key in ('id', 'source', 'note', 'time', 'tag', 'captured_at')}
                          for item in incidents], 'selected': selected, 'limit': OBSERVATION_LIMIT}


def monitor_devices():
    try:
        path = port.PERSIST / 'devices.json'
        binding = read_bounded(path if path.exists() else port.PERSIST / 'auto-config.json', 16384)
        config = binding.get('config', binding.get('network', {}))
        return {role: {'mac': binding[role + '_mac'], 'ip': config.get(role + '_ip', '')}
                for role in ('portal', 'ps5') if isinstance(binding.get(role + '_mac'), str)}
    except (OSError, ValueError, TypeError, AttributeError):
        return {}


def domain_monitor(batch_id='', incident_id=''):
    result = domains(incident_id)
    inventory = result['domains']
    devices = monitor_devices()
    live = result['observer']['fresh'] and result['observer']['state'] == 'observing'
    paths = [port.RUNTIME / 'domain-batches.json', port.PERSIST / 'domain-batches.json'] if live else [
        port.PERSIST / 'domain-batches.json', port.RUNTIME / 'domain-batches.json']
    value = {}
    for path in paths:
        try:
            candidate = read_bounded(path)
            if isinstance(candidate, dict) and candidate.get('device_macs') == device_macs(devices):
                value = candidate
                break
        except (OSError, ValueError):
            pass
    monitor = DomainMonitor(devices, value, close_active=not live)
    snapshot = monitor.snapshot()
    batches = snapshot['batches']
    selected = next((batch for batch in batches if batch['id'] == batch_id), None) if batch_id else (
        batches[0] if batches else None)
    if batch_id not in ('', 'inventory') and selected is None:
        request = optional(port.RUNTIME / 'domain-batch-request.json')
        if (live and request.get('id') == batch_id and request.get('device_macs') == device_macs(devices)
                and type(request.get('epoch')) in (int, float) and 0 <= time.time() - request['epoch'] < 30):
            selected = {'id': batch_id, 'time': utc(request['epoch']), 'epoch': request['epoch'],
                        'last_epoch': request['epoch'], 'last_seen': utc(request['epoch']),
                        'state': 'pending', 'source': 'manual', 'domains': [], 'events': [], 'event_count': 0}
            batches.insert(0, selected)
        else:
            raise ValueError('连接批次已轮换，请选择最近批次')
    rows = inventory if batch_id == 'inventory' else (selected or {}).get('domains', [])
    for row in rows:
        row['new_since_tag'] = bool(result['logging']['tag'] and type(row.get('first_epoch')) in (int, float)
                                   and row['first_epoch'] >= result['logging']['tag_since'])
    if selected:
        stats = [selected.get('traffic', {}), selected.get('unattributed_traffic', {})] + [row.get('traffic', {}) for row in rows]
        for traffic in stats:
            sampled = traffic.get('last_sample_epoch')
            traffic['fresh'] = bool(live and selected['state'] == 'collecting' and selected.get('traffic_state') == 'observing'
                                    and type(sampled) in (int, float) and 0 <= time.time() - sampled < 15)
            if not traffic['fresh']:
                for field in ('upload_rate', 'download_rate', 'proxy_rate', 'active_connections', 'proxy_active_connections'):
                    traffic[field] = 0
    result.update(domains=rows, batch=None if batch_id == 'inventory' else selected,
                  batches=[batch_summary(batch) for batch in batches], inventory_count=len(inventory),
                  batch_limits={'batches': MAX_BATCHES, 'domains': MAX_BATCH_DOMAINS,
                                'events': MAX_BATCH_EVENTS, 'idle_seconds': snapshot['idle_seconds']})
    return result


def start_domain_batch():
    report = domains()
    devices = monitor_devices()
    if len(devices) != 2 or not report['logging']['domains']:
        raise ValueError('确认设备并开启域名采集后，新建连接批次')
    if not report['observer']['fresh'] or report['observer']['state'] != 'observing':
        raise RuntimeError('等待域名采集服务就绪后，新建连接批次')
    epoch = time.time()
    request = {'id': uuid.uuid4().hex, 'epoch': epoch, 'device_macs': device_macs(devices)}
    port.atomic(port.RUNTIME / 'domain-batch-request.json', request)
    return {'ok': True, 'id': request['id'], 'time': utc(epoch)}


def configure_logging(request):
    # Separate serialization allows log changes and failure markers during a trial.
    port.PERSIST.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (port.PERSIST / 'observability.lock').open('a') as lock:
        deadline = time.monotonic() + 1
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError('日志策略正在保存，请稍后重试') from None
                time.sleep(.05)
        preferences = save_preferences(port.PERSIST / 'observability.json', request['mode'],
                                       bool(request['domains']), request['tag'])
    warning = ''
    if preferences.domains:
        try:
            result = port.command('/etc/init.d/ps-accel-observe', 'start', check=False, timeout=3)
            if result.returncode:
                warning = '域名观察服务启动失败，请检查独立服务状态'
        except READ_ERRORS as exc:
            warning = '域名观察服务启动待确认：' + str(exc)
    return {'ok': True, 'logging': port.asdict(preferences), 'observer_warning': warning}


def mark_incident(note):
    try:
        tag = load_preferences(port.PERSIST / 'observability.json').tag
    except (OSError, ValueError, TypeError):
        tag = ''
    incident = new_incident('manual', note, tag)
    try:
        report = read_bounded(port.RUNTIME / 'domains.json')
        incident['evidence'] = correlate(incident, report.get('recent', []))
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    # The observer refreshes the full window after fifteen seconds.
    core = policy.read(policy.runtime() / 'connections.json')
    incident['core_evidence'] = {'epoch': core.get('epoch'), 'connections': core.get('connections', [])[:16],
                                 'probes': policy.read(policy.runtime() / 'probes.json').get('targets', [])[:4]}
    save_incident(port.PERSIST, incident)
    return {'ok': True, 'id': incident['id'], 'time': incident['time']}


def redact(text):
    text = re.sub(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b', '[设备 MAC]', str(text))
    return re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IPv4 地址]', text)


def diagnostics():
    current = dict(details(), **status())
    job = current['job']
    domain_report = domains()
    domain_report['incidents'] = read_incidents(port.PERSIST)
    return {'ok': True, 'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'environment': current['environment'],
            'network': {'bridge': current['config'].get('bridge'), 'paired': current['configured']},
            'service': {key: current[key] for key in ('running', 'mode', 'modified', 'control_mbps',
                        'uptime_seconds', 'foreign_relay', 'counts')},
            'baseline': {'valid': current['baseline_valid'], 'reason': current['baseline_reason']},
            'recovery': {'required': current['recovery_required'],
                         'errors': [redact(error) for error in current['recovery_errors']]},
            'job': {'action': job.get('action'), 'state': job.get('state'), 'error': redact(job.get('error', ''))},
            'warnings': [redact(value) for value in current.get('status_warnings', []) + current.get('details_warnings', [])],
            'cleanup_error': redact(job.get('cleanup_error') or ''),
            'profile': current['config'].get('profile'),
            'observability': dict(current.get('observability', {}),
                                  last_error=redact(current.get('observability', {}).get('last_error', ''))),
            'quality': current['quality'],
            'domain_diagnostics': redact_domain_data(domain_report),
            'logging': redact_domain_data(current.get('logging', {})),
            'privacy': '诊断文件包含域名、公共解析地址与失败证据；设备地址、MAC 与会话报文保留在路由器本地。'}


def proxy_diagnostics():
    data = rules.status()
    report = domains()
    report['incidents'] = read_incidents(port.PERSIST)
    return {'ok': True, 'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'proxy': redact_domain_data({key: data.get(key) for key in (
                'mode', 'available', 'enabled', 'running', 'config', 'file_config', 'environment', 'switches',
                'blockers', 'warnings', 'receipt', 'pending_apply', 'telemetry')}),
            'domain_diagnostics': redact_domain_data(report),
            'privacy': '诊断包含代理配置、域名访问与失败证据；设备地址与 MAC 已遮盖。'}


def redact_domain_data(value):
    import ipaddress
    if isinstance(value, dict):
        return {key: redact_domain_data(item) for key, item in value.items()
                if key not in ('id', 'job_id', 'pid', 'identity', 'device_mac', 'ok')}
    if isinstance(value, list):
        return [redact_domain_data(item) for item in value]
    if isinstance(value, str):
        value = re.sub(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b', '[设备 MAC]', value)
        def address(match):
            try:
                return '[本地地址]' if not ipaddress.ip_address(match.group()).is_global else match.group()
            except ValueError:
                return match.group()
        value = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', address, value)
        value = re.sub(r'(?<![0-9A-Za-z:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}'
                       r'(?:%[a-zA-Z0-9_.-]+)?(?![0-9A-Za-z:])', address, value)
        try:
            ip = ipaddress.ip_address(value)
            if ip.version == 6 and not ip.is_global:
                return '[本地 IPv6 地址]'
        except ValueError:
            pass
    return value


def validate(method, request):
    if method not in METHODS:
        raise ValueError('Unknown method')
    request = {k: v for k, v in request.items() if k != 'ubus_rpc_session'}
    if set(request) != set(METHODS[method]):
        raise ValueError('Invalid arguments')
    if method == 'configure':
        if any(not isinstance(v, str) or len(v) > 80 for v in request.values()):
            raise ValueError('Invalid setting value')
        return port.asdict(port.Settings(**request).validate())
    if method == 'device_save':
        return port.validate_devices(request)
    if method == 'profile' and (not isinstance(request['profile'], str) or request['profile'] not in port.PROFILES):
        raise ValueError('请选择有效的目标码率档位')
    if method == 'logs' and request['kind'] not in ('log', 'events', 'devices', 'bitrate', 'proxy'):
        raise ValueError('请选择设备、码率增强或透明代理日志')
    if method == 'logging':
        if type(request['domains']) is not int or request['domains'] not in (0, 1):
            raise ValueError('域名记录开关无效')
        LogPreferences(request['mode'], bool(request['domains']), request['tag']).validate()
    if method == 'domains' and (not isinstance(request['incident'], str) or
                               (request['incident'] and not re.fullmatch('[0-9a-f]{32}', request['incident']))):
        raise ValueError('失败记录标识无效')
    if method == 'domain_monitor':
        for key in ('batch', 'incident'):
            value = request[key]
            if not isinstance(value, str) or (value and not re.fullmatch('[0-9a-f]{32}', value)
                                             and not (key == 'batch' and value == 'inventory')):
                raise ValueError('连接批次或失败记录标识无效')
    if method == 'incident' and (not isinstance(request['note'], str) or not request['note'].strip()
                                or len(request['note']) > 300 or any(ord(c) < 32 for c in request['note'])):
        raise ValueError('失败描述使用 1 至 300 字的单行文本')
    if method == 'start' and (type(request['autostart']) is not int or request['autostart'] not in (0, 1)):
        raise ValueError('Invalid autostart setting')
    if method in ('psportal_save', 'psportal_apply'):
        rules.normalize(request)
        if not isinstance(request['revision'], str) or not re.fullmatch('[0-9a-f]{64}', request['revision']):
            raise ValueError('请重新读取本机 PassWall 名单后保存')
    return request


def dispatch(method, request):
    request = validate(method, request)
    if method == 'status':
        return status()
    if method == 'details':
        return details()
    if method == 'devices':
        return devices()
    if method == 'logs':
        return logs(request['kind'])
    if method == 'diagnostics':
        return diagnostics()
    if method == 'proxy_diagnostics':
        return proxy_diagnostics()
    if method == 'domains':
        return domains(request['incident'])
    if method == 'domain_monitor':
        return domain_monitor(request['batch'], request['incident'])
    if method == 'domain_batch_start':
        return start_domain_batch()
    if method == 'logging':
        return configure_logging(request)
    if method == 'incident':
        return mark_incident(request['note'].strip())
    if method == 'psportal_status':
        return rules.status()
    if method == 'psportal_save':
        with control_lock():
            if current_job().get('busy'):
                raise RuntimeError('管理任务进行中，请等待完成后保存名单')
            return rules.save(request)
    with control_lock():
        old = current_job()
        if old.get('busy'):
            if method != 'stop':
                raise RuntimeError('另一项操作正在进行，请等待完成或点击停止。')
            (JOBS / ('cancel.' + old['id'])).touch(mode=0o600)
            return {'ok': True, 'id': old['id'], 'stopping': True}
        # An orphaned foreground trial can outlive its worker. Retain its identity
        # for the stop job, so recovery can signal only the exact managed process.
        orphan = orphaned_child(old)
        if orphan and method != 'stop':
            raise RuntimeError('上一次操作仍在运行，请先点击停止。')
        job_id = uuid.uuid4().hex
        job = {'id': job_id, 'action': method, 'request': request, 'state': 'queued',
               'started': time.time()}
        if orphan:
            job['orphan'] = orphan
        record_job(job)
        worker_process = None
        try:
            output_path = JOBS / (job_log_kind(method) + '.log')
            with output_path.open('w') as output:
                output_path.chmod(0o600)
                (JOBS / 'job.log').unlink(missing_ok=True)
                os.link(output_path, JOBS / 'job.log')
                worker_process = subprocess.Popen([sys.executable, '-u', str(Path(__file__).resolve()), 'worker', job_id],
                                                 stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                                 start_new_session=True, close_fds=True)
            job.update(pid=worker_process.pid, identity=process_identity(worker_process.pid))
            if not job['identity'] and worker_process.poll() is None:
                raise RuntimeError('后台任务标识获取失败。')
            record_job(job)
        except BaseException as exc:
            # The worker is waiting for this lock, so it has not entered its action.
            if worker_process is not None:
                try:
                    terminate_child(worker_process, grace=5)
                except Exception as cleanup_error:
                    job['cleanup_error'] = str(cleanup_error)
            job.update(state='failed', error=str(exc), finished=time.time())
            try:
                record_job(job)
            except Exception as record_error:
                message('任务状态记录失败：' + str(record_error), error=True)
            record_failure(port.RUNTIME, port.PERSIST, 'management', str(exc), job_id)
            raise
        return {'ok': True, 'id': job_id}


def cancelled(job_id):
    return (JOBS / ('cancel.' + job_id)).exists()


def terminate_child(child, grace):
    if child.poll() is None:
        child.send_signal(signal.SIGTERM)
    try:
        child.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=5)


def run_child(job_id, argv, cancellable=False, deadline=None):
    action = argv[1] if len(argv) > 1 else ''
    started = time.monotonic()
    deadline = min(deadline if deadline is not None else float('inf'),
                   started + CHILD_TIMEOUTS.get(action, 45))
    if started >= deadline:
        raise RuntimeError('操作执行超时，恢复路径已保留，请重试停止或恢复。')
    child = subprocess.Popen(argv, start_new_session=True, close_fds=True)
    # Foreground relays need time for their independent recovery guardian.
    grace = 90 if action in ('baseline', 'try') else 5
    signalled = False
    try:
        identity = process_identity(child.pid)
        if not identity and child.poll() is None:
            raise RuntimeError('子进程标识获取失败。')
        update_job(job_id, child_pid=child.pid, child_identity=identity)
        while child.poll() is None:
            if cancellable and cancelled(job_id):
                terminate_child(child, grace)
                signalled = True
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('操作执行超时，恢复路径已保留，请重试停止或恢复。')
            time.sleep(.2)
        if child.returncode != 0 and not signalled:
            raise RuntimeError('操作失败，请查看下方日志。')
    except BaseException as exc:
        try:
            terminate_child(child, grace)
        except Exception as cleanup_error:
            best_effort_update(job_id, child_cleanup_error=str(cleanup_error))
            raise RuntimeError(str(exc) + '；子进程退出失败：' + str(cleanup_error)) from exc
        raise
    finally:
        if child.poll() is not None:
            best_effort_update(job_id, child_pid=None, child_identity=None)


def checked(*args):
    result = port.command(*args, check=False)
    if result.stdout:
        message(result.stdout.rstrip())
    if result.returncode:
        if result.stderr:
            message(result.stderr.rstrip(), error=True)
        raise RuntimeError('命令执行失败：' + str(args[0]))


def stop_service(job_id, orphan=None):
    owner = optional(JOBS / 'job.json').get('id')
    if owner and owner != job_id:
        raise RuntimeError('Job ownership changed')
    deadline = time.monotonic() + STOP_TIMEOUT
    best_effort_update(job_id, phase='stopping', cleanup_attempted=True,
                       cleanup_complete=False, cleanup_required=True, cleanup_error=None)
    try:
        if orphan and alive(orphan['pid'], orphan['identity']):
            # Enrollment finishes its bounded setup before a recovery retry.
            if orphan.get('action') != 'configure':
                try:
                    os.kill(orphan['pid'], signal.SIGTERM)
                except ProcessLookupError:
                    pass
            orphan_deadline = min(deadline, time.monotonic() + 90)
            while alive(orphan['pid'], orphan['identity']) and time.monotonic() < orphan_deadline:
                time.sleep(.25)
            if alive(orphan['pid'], orphan['identity']):
                raise RuntimeError('上一次操作仍未结束，恢复路径已保留，请重试停止。')
        run_child(job_id, [SERVICE, 'stop'], deadline=deadline)
        best_effort_update(job_id, phase='waiting_exit')
        # procd acknowledges its request before the controller and guardian exit.
        while time.monotonic() < deadline:
            if controller_idle() and not port.pids():
                break
            time.sleep(.25)
        else:
            raise RuntimeError('等待服务退出超时，恢复路径已保留，请重试停止。')
        best_effort_update(job_id, phase='repairing')
        run_child(job_id, [CLI, 'repair'], deadline=deadline)
        best_effort_update(job_id, phase='ready', cleanup_complete=True, cleanup_required=False)
    except Exception as exc:
        best_effort_update(job_id, cleanup_error=str(exc))
        raise


def controller_idle():
    try:
        with port.exclusive():
            return True
    except port.ControllerBusy:
        return False


def start_managed_service(job_id):
    deadline = time.monotonic() + START_TIMEOUT
    update_job(job_id, service_start_requested=True, cleanup_required=True,
               cleanup_attempted=False, cleanup_complete=False, phase='starting')
    run_child(job_id, [SERVICE, 'start'], deadline=deadline)
    while not cancelled(job_id) and time.monotonic() < deadline:
        if managed_state()['running']:
            message('服务已启动，新连接使用当前目标码率。')
            return
        time.sleep(.5)
    if not cancelled(job_id):
        raise RuntimeError('中继启动超时，请查看环境检查与诊断摘要。')


def change_profile(job_id, profile):
    original = port.Settings.load().profile
    if cancelled(job_id):
        return
    if profile == original:
        update_job(job_id, restarted=False, applied_profile=profile)
        message('当前码率已保存。')
        return
    restart = port.command(SERVICE, 'running', check=False).returncode == 0
    update_job(job_id, restarted=restart, previous_profile=original, phase='stopping' if restart else 'saving')
    if restart:
        message('正在等待旧中继完成恢复，随后自动应用新码率并重启。')
        stop_service(job_id)
    if cancelled(job_id):
        return
    try:
        update_job(job_id, phase='saving')
        run_child(job_id, [CLI, 'profile', '--profile', profile])
        if restart and not cancelled(job_id):
            update_job(job_id, phase='starting')
            start_managed_service(job_id)
        update_job(job_id, applied_profile=profile, phase='ready')
    except Exception:
        if restart and not cancelled(job_id):
            try:
                update_job(job_id, phase='rollback')
                stop_service(job_id)
                run_child(job_id, [CLI, 'profile', '--profile', original])
                if not cancelled(job_id):
                    start_managed_service(job_id)
                    update_job(job_id, rolled_back=True, applied_profile=original, cleanup_required=False)
                    message('已恢复原码率并重新启动中继。')
            except Exception as recovery_error:
                best_effort_update(job_id, rollback_error=str(recovery_error))
                message('原配置恢复需要检查：' + str(recovery_error), error=True)
        raise


def worker(job_id):
    action, error, cleanup_error = None, None, None
    try:
        with control_lock():
            job = optional(JOBS / 'job.json')
            if job.get('id') != job_id:
                raise RuntimeError('Unknown job')
            job.update(pid=os.getpid(), identity=process_identity(os.getpid()), state='running')
            record_job(job)
        action, request = job['action'], validate(job['action'], job['request'])
        if action == 'device_save':
            message('正在确认 Portal / PS5 的内网地址与设备身份。')
            save_devices(request)
        elif action == 'configure':
            message('正在保存设置并检测 PS5 / Portal，请保持两台设备开机。')
            run_child(job_id, [CLI, 'configure', '--bridge', request['bridge'], '--address', request['address'],
                              '--ps5', request['ps5_ip'], '--portal', request['portal_ip'], '--profile', request['profile']])
            checked(SERVICE, 'disable')
        elif action == 'profile':
            change_profile(job_id, request['profile'])
        elif action in ('baseline', 'trial', 'doctor', 'repair'):
            if action == 'baseline':
                message('正在准备连接测试，请等待就绪提示再连接 Portal。')
            if action == 'trial':
                message('正在准备试运行，请等待就绪提示再重新连接 Portal。')
            argv = [CLI, 'try', '--seconds', '90'] if action == 'trial' else [CLI, action]
            run_child(job_id, argv, cancellable=action in ('baseline', 'trial', 'doctor'))
        elif action == 'start':
            port.verify_configuration(port.Settings.load())
            checked('uci', 'set', 'ps_accel.main.enabled=1')
            checked('uci', 'commit', 'ps_accel')
            checked(SERVICE, 'enable' if request['autostart'] else 'disable')
            start_managed_service(job_id)
        elif action == 'stop':
            stop_service(job_id, job.get('orphan'))
        elif action == 'psportal_apply':
            message('正在保存本机 PassWall 的代理与直连域名名单。')
            result = rules.apply(request, cancel=lambda: cancelled(job_id))
            message(result['notice'])
            update_job(job_id, reloaded=result['reloaded'], pending_apply=result['pending_apply'], commit_complete=True)
    except Exception as exc:
        error = None if isinstance(exc, rules.RulesCancelled) else exc
        message(str(exc), error=error is not None)

    # Cancellation and action errors share the same recovery path. A completed
    # rollback keeps its restored service; a failed cleanup ends with a retryable job.
    cancel_requested = cancelled(job_id)
    saved = optional(JOBS / 'job.json')
    if action == 'psportal_apply' and saved.get('commit_complete'):
        cancel_requested = False
    owns_job = not saved.get('id') or saved['id'] == job_id
    needs_cleanup = owns_job and action != 'psportal_apply' and (cancel_requested or (error is not None and saved.get('cleanup_required')
                                                     and not saved.get('rolled_back')))
    if needs_cleanup and not saved.get('cleanup_complete') and not saved.get('cleanup_attempted'):
        try:
            stop_service(job_id)
        except Exception as exc:
            cleanup_error = exc
            message('停止或恢复失败：' + str(exc), error=True)
    if owns_job and cancel_requested and action == 'baseline':
        try:
            for name, folder in (('baseline.json', port.PERSIST), ('auto-baseline.json', port.RUNTIME)):
                (folder / name).unlink(missing_ok=True)
        except OSError as exc:
            cleanup_error = cleanup_error or exc
    if error is not None or cleanup_error is not None:
        values = dict(state='failed', error=str(error if error is not None else cleanup_error),
                      finished=time.time())
        if cleanup_error is not None:
            values['cleanup_error'] = str(cleanup_error)
    else:
        values = dict(state='cancelled' if cancel_requested else 'complete', finished=time.time(), cleanup_required=False)
        message(('名单应用已取消，原名单已恢复。' if action == 'psportal_apply' else '已停止，网络恢复完成。') if cancel_requested else '操作完成。')
    best_effort_update(job_id, **values)
    if values['state'] == 'failed':
        record_failure(port.RUNTIME, port.PERSIST, 'management', values['error'], job_id)
    try:
        (JOBS / ('cancel.' + job_id)).unlink(missing_ok=True)
    except OSError as exc:
        message('停止标记清理失败：' + str(exc), error=True)
    return 1 if values['state'] == 'failed' else 0


def main():
    os.umask(0o077)
    if os.geteuid() != 0:
        raise RuntimeError('rpcd must run this plugin as root')
    if sys.argv[1:] == ['list']:
        print(json.dumps(METHODS))
        return 0
    if len(sys.argv) == 3 and sys.argv[1] == 'worker':
        if len(sys.argv[2]) != 32 or any(c not in '0123456789abcdef' for c in sys.argv[2]):
            raise ValueError('Invalid job ID')
        return worker(sys.argv[2])
    if len(sys.argv) != 3 or sys.argv[1] != 'call':
        raise ValueError('Invalid rpcd invocation')
    try:
        request_limit = rules.LIST_BYTES * 12 + 65536
        raw = sys.stdin.read(request_limit + 1)
        if len(raw) > request_limit:
            raise ValueError('管理请求超过容量限制')
        request = json.loads(raw or '{}')
        if not isinstance(request, dict):
            raise ValueError('Invalid request')
        print(json.dumps(dispatch(sys.argv[2], request), ensure_ascii=False))
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
