#!/usr/bin/env python3
"""Experimental automatic Portal-to-PS5 relay. Video stays on the direct path."""
import argparse
import collections
import datetime
import hashlib
import json
import logging
import os
from pathlib import Path
import queue
import signal
import subprocess
import sys
import threading
import time
from scapy.all import ARP, Ether
import portal_active_probe as probe
import portal_auto_platform as net
from profiles import PROFILES
from telemetry import Telemetry
from observability import new_incident
from stream_quality import StreamQuality, unavailable_quality

ROOT = Path(__file__).resolve().parent
LOG = logging.getLogger('portal-auto')
HEARTBEAT_TIMEOUT = 30  # Allows a bounded Windows forwarding-state query.


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def atomic_json(path, value):
    temp = path.with_name(path.name + f'.{os.getpid()}.tmp')
    temp.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    temp.replace(path)


def config(path):
    c = json.loads(path.read_text(encoding='utf-8-sig'))
    if set(c) != {'network', 'profile', 'ps5_mac', 'portal_mac'} or c['profile'] not in PROFILES:
        raise ValueError('Invalid enrollment/profile. Run configure.')
    net.win.validate_config(c['network'])
    for k in ('ps5_mac', 'portal_mac'):
        c[k] = net.win.normal_mac(c[k])
    if c['ps5_mac'] == c['portal_mac']:
        raise ValueError('Peer MAC addresses must differ')
    return c


def fingerprint(c):
    binding = {key: value for key, value in c.items() if key != 'profile'}
    digest = hashlib.sha256(json.dumps(binding, sort_keys=True).encode())
    for name in ('portal_auto.py', 'portal_auto_platform.py', 'portal_active_probe.py', 'portal_windows_network.py', 'protocol.py', 'profiles.py', 'telemetry.py', 'observability.py', 'stream_quality.py'):
        digest.update((ROOT / name).read_bytes())
    return digest.hexdigest()


def baseline_valid(c, runtime):
    try:
        receipt = json.loads((runtime / 'auto-baseline.json').read_text())
        return receipt['fingerprint'] == fingerprint(c) and receipt['forwarded_out'] > 0 and receipt['restored'] is True
    except (OSError, ValueError, KeyError, TypeError):
        return False


def portal_arp(state, repair=False):
    return Ether(src=state['own_mac'], dst=state['portal_mac']) / ARP(
        op=2, psrc=state['config']['ps5_ip'], pdst=state['config']['portal_ip'],
        hwsrc=state['ps5_mac'] if repair else state['own_mac'], hwdst=state['portal_mac'])


def outbound(frame, state, active=True):
    if len(frame) < 34 or frame[6:12] != bytes.fromhex(state['portal_mac'].replace(':', '')):
        return None
    result = probe.transform(frame, state, active)
    return result if result and result[2] == 'out' else None


def restore_peer(state):
    sock = None
    errors = []
    try:
        net.configure(state['config'])
        sock = net.open_socket()
        for _ in range(5):
            net.send(sock, portal_arp(state, True))
            time.sleep(.1)
    except Exception as exc:
        errors.append(str(exc))
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception as exc:
                errors.append('恢复套接字关闭失败：' + str(exc))
    return errors


def pipe_reader(pipe, messages, ready_line=False):
    try:
        if ready_line:
            messages.put(pipe.readline().strip())
        else:
            while pipe.read(1):
                messages.put(True)
            messages.put(False)
    except OSError:
        messages.put(False)


def guardian(runtime, parent, preferences=None):
    state = json.loads((runtime / 'restore-state.json').read_text())
    lock = net.Lock(runtime, existing=True)
    owner = net.Parent(parent)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, signal.SIG_IGN)
    messages = queue.Queue()
    threading.Thread(target=pipe_reader, args=(sys.stdin.buffer, messages), daemon=True).start()
    # Verify the recovery adapter can be opened before allowing any redirection.
    net.configure(state['config'])
    test_socket = net.open_socket()
    test_socket.close()
    print('GUARD_READY', flush=True)
    reason = 'relay_closed'
    try:
        while True:
            try:
                if not messages.get(timeout=HEARTBEAT_TIMEOUT):
                    break
            except queue.Empty:
                reason = 'heartbeat_timeout'
                owner.stop()
                break
        errors = restore_peer(state)
        if not errors:
            (runtime / 'recovery-required').unlink(missing_ok=True)
        lock.close(parent, repaired=not errors)
        try:
            reports = (Telemetry(runtime) if preferences is None else
                       Telemetry(runtime, preferences=preferences, persist=preferences.parent))
            reports.recovery({'time': utc(), 'parent': parent, 'reason': reason, 'errors': errors})
            if errors:
                reports.incident(new_incident('guardian', '; '.join(errors), reports.preferences.value.tag))
            reports.close()
        except Exception:
            pass
        return 1 if errors else 0
    finally:
        owner.close()


def health_worker(results):
    try:
        net.health()
        results.put(None)
    except Exception as exc:
        results.put(str(exc))


def run(c, runtime, active=True, seconds=None, generation='', preferences=None, require_baseline=True):
    if (runtime / 'recovery-required').exists():
        raise RuntimeError('Previous relay recovery is unconfirmed. Run repair before restarting.')
    if active and require_baseline and not baseline_valid(c, runtime):
        raise RuntimeError('Run a successful baseline with this config/version first.')
    state = net.state_for(c)
    probe.network = net
    probe.PATCH_DELTA = PROFILES[c['profile']]
    probe.OFFSET = 334
    lock = net.Lock(runtime)
    telemetry = None
    try:
        telemetry = (Telemetry(runtime) if preferences is None else
                     Telemetry(runtime, preferences=preferences, persist=preferences.parent))
        LOG.addHandler(telemetry.handler)
    except Exception:
        pass
    LOG.propagate = False
    guard = rx = tx = None
    counts = collections.Counter()
    running = True
    errors = []
    seen = collections.OrderedDict()
    started = time.monotonic()
    last_mutation = None
    last_rate_time = started
    last_rate_bytes = 0
    quality = StreamQuality()
    def quality_snapshot(now, running=True):
        nonlocal quality
        if quality is not None:
            try:
                if running:
                    quality.receive_statistics(net.receive_statistics(rx), now)
                return quality.snapshot(now, c['profile'], active, running)
            except Exception:
                quality = None
        return unavailable_quality(c['profile'], running)

    def stop(_sig, _frame):
        nonlocal running
        running = False
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, stop)
    try:
        atomic_json(runtime / 'restore-state.json', state)
        (runtime / 'recovery-required').write_text(str(os.getpid()))
        filt = f'ether dst {state["own_mac"]} and ether src {state["portal_mac"]} and ip and src host {net.PORTAL} and dst host {net.PS5}'
        rx, tx = net.open_socket(filt), net.open_socket()
        guard_args = [sys.executable, '-u', str(ROOT / 'portal_auto.py'), 'guardian',
                      '--runtime', str(runtime), '--parent', str(os.getpid())]
        if preferences is not None:
            guard_args += ['--preferences', str(preferences)]
        guard = subprocess.Popen(guard_args,
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, **net.spawn_options())
        ready = queue.Queue()
        threading.Thread(target=pipe_reader, args=(guard.stdout, ready, True), daemon=True).start()
        if ready.get(timeout=10) != b'GUARD_READY':
            raise RuntimeError('Recovery guardian failed before redirection')
        atomic_json(runtime / 'engine-ready.json', {'pid': os.getpid(), 'generation': generation, 'ready': True})
        LOG.info('中继就绪，模式=%s，目标码率=%s Mbps', 'active' if active else 'baseline',
                 c['profile'], extra={'essential': True})
        print('AUTO READY' if active else 'BASELINE READY: connect Portal now and check picture/controls.', flush=True)
        next_arp = next_beat = next_status = 0
        next_health = time.monotonic() + 30
        health_results = queue.Queue()
        health_pending = False
        while running and (seconds is None or time.monotonic() - started < seconds):
            now = time.monotonic()
            if (runtime / 'disabled').exists():
                break
            if guard.poll() is not None:
                raise RuntimeError('Recovery guardian exited')
            if now >= next_beat:
                guard.stdin.write(b'.'); guard.stdin.flush()
                next_beat = now + 1
            if health_pending:
                try:
                    health_error = health_results.get_nowait()
                    health_pending = False
                    next_health = now + 30
                    if health_error:
                        raise RuntimeError(health_error)
                except queue.Empty:
                    pass
            if now >= next_health and not health_pending:
                # PowerShell may take seconds. Keep relaying while its bounded
                # read-only health query runs, then stop on any reported error.
                threading.Thread(target=health_worker, args=(health_results,), daemon=True).start()
                health_pending = True
            if now >= next_arp:
                net.send(tx, portal_arp(state))
                next_arp = now + 1
            if now >= next_status:
                control_mbps = (counts['forwarded_bytes'] - last_rate_bytes) * 8 / max(now - last_rate_time, .001) / 1e6
                snapshot = {'time': utc(), 'state': 'running', 'pid': os.getpid(),
                    'guardian_pid': guard.pid, 'mode': 'active' if active else 'baseline', 'profile': c['profile'],
                    'counts': dict(counts), 'last_mutation': last_mutation,
                    'uptime_seconds': round(now - started, 1), 'control_mbps': round(control_mbps, 3),
                    'quality': quality_snapshot(now),
                    'limit': 'control_mbps 记录 Portal 到 PS5 的中继流量；视频回程使用设备直达路径。'}
                if telemetry is not None:
                    telemetry.snapshot(snapshot)
                last_rate_time, last_rate_bytes = now, counts['forwarded_bytes']
                next_status = now + min(2, telemetry.snapshot_interval if telemetry is not None else 2)
            frame = net.receive(rx)
            if not frame:
                continue
            processing_started = time.monotonic()
            result = outbound(frame, state, active)
            if not result:
                continue
            forwarded, payload, _, changed = result
            net.send(tx, forwarded)
            counts['forwarded_out'] += 1
            counts['forwarded_bytes'] += len(forwarded)
            if quality is not None:
                try:
                    observed_at = time.monotonic()
                    quality.observe_frame(frame, payload, observed_at, changed)
                    quality.forwarded(observed_at, (time.monotonic() - processing_started) * 1000)
                except Exception:
                    # Quality collection has no authority over forwarding/recovery.
                    quality = None
            if changed:
                counts['modified_packets_including_retransmits'] += 1
                ident = (payload[1:5], payload[17:21])
                if ident not in seen:
                    seen[ident] = now
                    if len(seen) > 256:
                        seen.popitem(last=False)
                    counts['unique_modified_startups'] += 1
                    last_mutation = utc()
                    LOG.info('已修改新连接请求，目标码率=%s Mbps', c['profile'], extra={'essential': True})
    except Exception as exc:
        LOG.error('中继运行失败：%s', str(exc), extra={'essential': True})
        if telemetry is not None:
            telemetry.incident(new_incident('relay', str(exc), telemetry.preferences.value.tag))
        raise
    finally:
        if guard is not None:
            try:
                guard.stdin.close()
            except OSError:
                pass
            try:
                rc = guard.wait(timeout=HEARTBEAT_TIMEOUT + 5)
                if rc:
                    errors = restore_peer(state)
                    if not errors:
                        (runtime / 'recovery-required').unlink(missing_ok=True)
            except subprocess.TimeoutExpired:
                errors = ['Guardian still running; recovery lock retained']
        else:
            # No guardian means no ARP redirection has been sent.
            (runtime / 'recovery-required').unlink(missing_ok=True)
        for sock in (rx, tx):
            if sock is not None:
                sock.close()
        lock.close(os.getpid(), repaired=not errors)
        snapshot = {'time': utc(), 'state': 'stopped' if not errors else 'recovery_failed',
                   'counts': dict(counts), 'last_mutation': last_mutation, 'errors': errors,
                   'mode': 'active' if active else 'baseline', 'profile': c['profile'],
                   'uptime_seconds': round(time.monotonic() - started, 1), 'control_mbps': 0,
                   'quality': quality_snapshot(time.monotonic(), running=False)}
        if telemetry is not None:
            telemetry.snapshot(snapshot)
            if errors:
                LOG.error('中继恢复失败：%s', '; '.join(errors), extra={'essential': True})
                telemetry.incident(new_incident('recovery', '; '.join(errors), telemetry.preferences.value.tag))
            else:
                LOG.info('中继已停止，恢复完成，转发包数=%s', counts['forwarded_out'], extra={'essential': True})
            LOG.removeHandler(telemetry.handler)
            telemetry.close()
        if errors:
            raise RuntimeError('; '.join(errors))
    if not active and counts['forwarded_out']:
        atomic_json(runtime / 'auto-baseline.json', {'time': utc(), 'fingerprint': fingerprint(c),
                    'forwarded_out': counts['forwarded_out'], 'restored': True,
                    'limit': 'Transport observed, not proof of picture quality or input responsiveness.'})
    return dict(counts)


def choose_windows_interface():
    adapters = [x for x in net.conf.ifaces.values() if x.mac and x.ip and x.ip != '0.0.0.0']
    if not adapters:
        raise RuntimeError('No addressed LAN adapters found. Check Npcap and your LAN connection.')
    print('Select the adapter connected to your PS5/Portal LAN. Use its menu number.')
    for index, adapter in enumerate(adapters, 1):
        print(f'{index}: {adapter.name} ({adapter.description}) - {adapter.ip}')
    try:
        number = int(input('LAN adapter number: ').strip())
    except ValueError:
        raise ValueError('Enter the adapter menu number, not a PC IP address or GUID.') from None
    if not 1 <= number <= len(adapters):
        raise ValueError('Adapter number is outside the displayed list.')
    return adapters[number - 1].network_name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['configure', 'baseline', 'run', 'stop', 'status', 'repair', 'guardian', 'verify-baseline'])
    parser.add_argument('--config', type=Path, default=ROOT / 'auto-config.json')
    parser.add_argument('--runtime', type=Path, default=ROOT / 'auto-runtime')
    parser.add_argument('--profile', choices=PROFILES, default='65')
    parser.add_argument('--seconds', type=int)
    parser.add_argument('--parent', type=int)
    parser.add_argument('--generation', default='')
    parser.add_argument('--preferences', type=Path)
    parser.add_argument('--configured-start', action='store_true')
    args = parser.parse_args()
    runtime = args.runtime.resolve()
    if args.command == 'status':
        for name in ('status.json', 'recovery.json', 'error.json'):
            path = runtime / name
            if path.exists():
                print(name + ':\n' + path.read_text())
        print('Disabled:', (runtime / 'disabled').exists(), 'Recovery required:', (runtime / 'recovery-required').exists())
        print('Check the OS service/task state too; a timestamped report can be stale after a crash.')
        return 0
    net.require_admin()
    runtime.mkdir(parents=True, exist_ok=True)
    LOG.setLevel(logging.INFO)
    LOG.addHandler(logging.NullHandler())
    LOG.propagate = False
    if args.command == 'stop':
        (runtime / 'disabled').touch()
        print('Stop requested. Allow up to 35 seconds for recovery; check status.')
        return 0
    if args.command == 'guardian':
        return guardian(runtime, args.parent, args.preferences)
    if args.command == 'configure':
        if sys.platform == 'win32':
            interface = choose_windows_interface()
        else:
            print('Interfaces:', ', '.join(str(x) for x in net.conf.ifaces.values()))
            interface = input('LAN interface name (for example eth0 or en0, not a PC IP): ').strip()
        c = {'network': {'interface': interface,
                        'ps5_ip': input('PS5 IPv4: ').strip(), 'portal_ip': input('Portal IPv4: ').strip()},
             'profile': args.profile}
        state = net.state_for(c, enroll=True)
        c.update(network=state['config'], ps5_mac=state['ps5_mac'], portal_mac=state['portal_mac'])
        atomic_json(args.config, c)
        print('Enrolled two devices locally. Do not upload auto-config.json.')
        return 0
    if args.command == 'repair':
        # Only after the OS reports the relay stopped. Existing guardians hold locks.
        if input('Confirm relay service and guardian are stopped (type STOPPED): ') != 'STOPPED':
            return 1
        state = json.loads((runtime / 'restore-state.json').read_text())
        errors = restore_peer(state)
        if errors:
            raise RuntimeError('; '.join(errors))
        (runtime / 'recovery-required').unlink(missing_ok=True)
        if sys.platform != 'win32':
            Path('/var/run/portal-lab-capture.lock').unlink(missing_ok=True)
        print('Repair packets sent. Reconnect Portal; verify its connection.')
        return 0
    if args.command == 'verify-baseline':
        if not baseline_valid(config(args.config), runtime):
            raise RuntimeError('Run configure and baseline with this version first')
        print('Baseline receipt matches this configuration and code.')
        return 0
    if (runtime / 'disabled').exists():
        print('Disabled. Use the documented Start command to remove the stop marker.')
        return 0
    c = config(args.config)
    return 0 if run(c, runtime, active=args.command == 'run',
                    seconds=(60 if args.command == 'baseline' else args.seconds),
                    generation=args.generation, preferences=args.preferences,
                    require_baseline=not args.configured_start) is not None else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        LOG.exception('Automatic relay failed')
        print(f'ERROR: {exc}', file=sys.stderr)
        sys.exit(1)
