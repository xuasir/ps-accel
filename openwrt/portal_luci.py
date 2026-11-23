#!/usr/bin/env python3
"""Narrow rpcd API and asynchronous LuCI jobs; no caller-supplied commands/paths."""
from contextlib import contextmanager
import datetime
import fcntl
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
from profiles import public_profiles

JOBS = port.RUNTIME / 'luci'
SERVICE = '/etc/init.d/ps-accel'
CLI = '/usr/sbin/ps-accel'
START_TIMEOUT = 80
STOP_TIMEOUT = 120
CHILD_TIMEOUTS = {'configure': 120, 'baseline': 180, 'try': 210, 'doctor': 45,
                  'repair': 45, 'profile': 30, 'start': 20, 'stop': 20}
TERMINAL_STATES = {'complete', 'cancelled', 'failed'}
READ_ERRORS = (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError)
METHODS = {'status': {}, 'details': {}, 'logs': {'kind': ''},
           'configure': {'bridge': '', 'address': '', 'ps5_ip': '', 'portal_ip': '', 'profile': ''},
           'profile': {'profile': ''}, 'diagnostics': {},
           'baseline': {}, 'trial': {}, 'start': {'autostart': 0}, 'stop': {}, 'repair': {}, 'doctor': {}}


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
        port.atomic(JOBS / 'job.json', job)


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
            'last_modified': report.get('last_mutation'), 'job': job,
            'counts': counts, 'sample_time': report.get('time') if stats_fresh else None,
            'control_mbps': report.get('control_mbps', 0) if running and stats_fresh else 0,
            'uptime_seconds': elapsed if running and managed else report.get('uptime_seconds', 0) if running else 0,
            'observability': observability,
            'foreign_relay': bool(lock_owner and lock_owner != own_engine),
            'recovery_errors': recovery.get('errors', report.get('errors', []))}


def details():
    """Static configuration and full baseline validation, refreshed on changes."""
    revision = port.configuration_revision()
    warnings = []
    config = {key: '65' if key == 'profile' else '' for key in port.Settings.__dataclass_fields__}
    values = {}
    try:
        values = port.uci_values()
        config.update({key: values.get(key, config[key]) for key in config})
        baseline = port.baseline_state(port.Settings(**config).validate())
    except READ_ERRORS as exc:
        baseline = {'valid': False, 'reason': '配置读取或校验失败，请检查设备配置'}
        warnings.append(str(exc))
    autostart = False
    try:
        if values.get('enabled') == '1':
            autostart = port.command(SERVICE, 'enabled', check=False, timeout=3).returncode == 0
    except READ_ERRORS as exc:
        warnings.append('开机启动状态读取失败：' + str(exc))
    return {'ok': True, 'config': config, 'configured': (port.PERSIST / 'auto-config.json').exists(),
            'details_revision': revision, 'details_warnings': warnings,
            'bridges': sorted(p.parent.name for p in port.SYSNET.glob('*/bridge') if p.is_dir()),
            'autostart': autostart, 'baseline_saved': (port.PERSIST / 'baseline.json').exists(),
            'baseline_valid': baseline['valid'], 'baseline_reason': baseline['reason'],
            'environment': port.environment(), 'profiles': public_profiles()}


def logs(kind):
    path = JOBS / 'job.log' if kind == 'log' else port.RUNTIME / 'events.log'
    return {'ok': True, 'kind': kind, 'text': tail(path)}


def redact(text):
    text = re.sub(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b', '[设备 MAC]', str(text))
    return re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IPv4 地址]', text)


def diagnostics():
    current = dict(details(), **status())
    job = current['job']
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
            'privacy': '诊断文件使用状态摘要，设备 IP、MAC、原始日志与会话报文保留在路由器本地。'}


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
    if method == 'profile' and (not isinstance(request['profile'], str) or request['profile'] not in port.PROFILES):
        raise ValueError('请选择有效的目标码率档位')
    if method == 'logs' and request['kind'] not in ('log', 'events'):
        raise ValueError('请选择任务输出或中继事件日志')
    if method == 'start' and (type(request['autostart']) is not int or request['autostart'] not in (0, 1)):
        raise ValueError('Invalid autostart setting')
    return request


def dispatch(method, request):
    request = validate(method, request)
    if method == 'status':
        return status()
    if method == 'details':
        return details()
    if method == 'logs':
        return logs(request['kind'])
    if method == 'diagnostics':
        return diagnostics()
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
        port.atomic(JOBS / 'job.json', job)
        worker_process = None
        try:
            with (JOBS / 'job.log').open('w') as output:
                worker_process = subprocess.Popen([sys.executable, '-u', str(Path(__file__).resolve()), 'worker', job_id],
                                                 stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                                                 start_new_session=True, close_fds=True)
            job.update(pid=worker_process.pid, identity=process_identity(worker_process.pid))
            if not job['identity'] and worker_process.poll() is None:
                raise RuntimeError('后台任务标识获取失败。')
            port.atomic(JOBS / 'job.json', job)
        except BaseException as exc:
            # The worker is waiting for this lock, so it has not entered its action.
            if worker_process is not None:
                try:
                    terminate_child(worker_process, grace=5)
                except Exception as cleanup_error:
                    job['cleanup_error'] = str(cleanup_error)
            job.update(state='failed', error=str(exc), finished=time.time())
            try:
                port.atomic(JOBS / 'job.json', job)
            except Exception as record_error:
                message('任务状态记录失败：' + str(record_error), error=True)
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
            port.atomic(JOBS / 'job.json', job)
        action, request = job['action'], validate(job['action'], job['request'])
        if action == 'configure':
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
            port.verify_baseline(port.Settings.load())
            checked('uci', 'set', 'ps_accel.main.enabled=1')
            checked('uci', 'commit', 'ps_accel')
            checked(SERVICE, 'enable' if request['autostart'] else 'disable')
            start_managed_service(job_id)
        elif action == 'stop':
            stop_service(job_id, job.get('orphan'))
    except Exception as exc:
        error = exc
        message(str(exc), error=True)

    # Cancellation and action errors share the same recovery path. A completed
    # rollback keeps its restored service; a failed cleanup ends with a retryable job.
    cancel_requested = cancelled(job_id)
    saved = optional(JOBS / 'job.json')
    owns_job = not saved.get('id') or saved['id'] == job_id
    needs_cleanup = owns_job and (cancel_requested or (error is not None and saved.get('cleanup_required')
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
        message('已停止，网络恢复完成。' if cancel_requested else '操作完成。')
    best_effort_update(job_id, **values)
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
        request = json.loads(sys.stdin.read(8193) or '{}')
        if not isinstance(request, dict):
            raise ValueError('Invalid request')
        print(json.dumps(dispatch(sys.argv[2], request), ensure_ascii=False))
    except Exception as exc:
        print(json.dumps({'ok': False, 'error': str(exc)}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
