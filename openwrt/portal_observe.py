#!/usr/bin/env python3
"""Low-priority passive LAN observer, supervised separately from the relay."""
import fcntl
import os
import re
import signal
import socket
import sys
import time

import portal_openwrt as port
from domain_tracker import DomainTracker
from observability import (OBSERVATION_LIMIT, correlate, merge_events, read_bounded,
                           read_domain_events, read_incidents, save_incident, utc)
from telemetry import Telemetry

SNAPLEN = 4096
PACKETS_PER_SECOND = 500


def proxy_snapshot(name):
    try:
        value = read_bounded(port.RUNTIME / 'psportal' / name)
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def enrolled_devices():
    if (port.PERSIST / 'devices.json').exists():
        binding = port.device_binding()
        if not binding:
            raise ValueError('请在设备配置确认 Portal / PS5 的内网地址')
        config = binding['config']
        return config['bridge'], {role: {'ip': config[role + '_ip'], 'mac': binding[role + '_mac']}
                                  for role in ('ps5', 'portal')}
    settings = port.Settings.load()
    value = read_bounded(port.PERSIST / 'auto-config.json', 16384)
    if value.get('network') != settings.engine():
        raise ValueError('设备配对与主路由配置待同步')
    def normal_mac(value):
        if (not isinstance(value, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value)
                or int(value[:2], 16) & 1 or value == '00:00:00:00:00:00'):
            raise ValueError('设备 MAC 配对无效')
        return value.lower()
    devices = {device: {'ip': getattr(settings, device + '_ip'),
                        'mac': normal_mac(value[device + '_mac'])} for device in ('ps5', 'portal')}
    if devices['ps5']['mac'] == devices['portal']['mac']:
        raise ValueError('设备 MAC 必须分别配对')
    return settings.bridge, devices


def capture_filter(devices):
    macs = ' or '.join('(ether host ' + info['mac'] + ' and (ip6 or host ' + info['ip'] + '))'
                       for info in devices.values())
    # TCP payload capture is restricted to the first visible ClientHello record.
    # Encrypted application/video payloads fail the kernel filter.
    traffic = ('udp port 53 or tcp port 53 or icmp or icmp6 or '
               '(ip and tcp and (tcp[13] & 0x06 != 0 or '
               '(dst port 443 and tcp[((tcp[12] & 0xf0) >> 2)] = 22))) or '
               '(ip6 and (ip6[6] = 6) and (ip6[53] & 0x06 != 0 or '
               '(dst port 443 and ip6[40 + ((ip6[52] & 0xf0) >> 2)] = 22)))')
    return '(' + macs + ') and (' + traffic + ')'


def open_capture(bridge, devices):
    if sys.platform != 'linux':
        raise RuntimeError('设备域名采集需要 Linux/OpenWrt LAN 网桥')
    from scapy.arch.linux import attach_filter
    result = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    try:
        result.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        result.bind((bridge, 0))
        attach_filter(result, capture_filter(devices), bridge)
        result.settimeout(.5)
        return result
    except BaseException:
        result.close()
        raise


class ObserverTelemetry(Telemetry):
    def __init__(self):
        self.next_incident_scan = 0
        super().__init__(port.RUNTIME, capacity=128, rotate_bytes=262144,
                         preferences=port.PERSIST / 'observability.json',
                         event_name='domains.jsonl', report_name='domains', persist=port.PERSIST)

    def write_report(self, name, payload):
        history = payload.get('_history', [])
        public = {key: value for key, value in payload.items() if key != '_history'}
        super().write_report(name, public)
        if time.monotonic() < self.next_incident_scan:
            return
        self.next_incident_scan = time.monotonic() + 5
        pending = [incident for incident in read_incidents(port.PERSIST)
                   if not incident.get('captured_at') and time.time() >= incident['epoch'] + 15]
        logs = read_domain_events(port.RUNTIME) if pending else []
        for incident in pending:
            initial = incident.get('evidence', {}).get('events', [])
            evidence = correlate(incident, merge_events(logs, initial, history))
            evidence['coverage_start'] = public.get('coverage_start')
            evidence['coverage_limited'] = (public.get('coverage_start', time.time()) > incident['epoch'] - 180
                                            or public.get('state') != 'observing'
                                            or bool(public.get('capture_drops') or public.get('rate_drops')
                                                    or public.get('health', {}).get('capacity_drops')
                                                    or public.get('health', {}).get('malformed')
                                                    or public.get('health', {}).get('snaplen_limited')))
            save_incident(port.PERSIST, dict(incident, evidence=evidence, captured_at=utc(),
                capture_health=public.get('health', {}),
                core_evidence={'epoch': time.time(),
                    'connections': proxy_snapshot('connections.json').get('connections', [])[:16],
                    'probes': proxy_snapshot('probes.json').get('targets', [])[:4]}))


def run():
    os.umask(0o077)
    port.RUNTIME.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (port.RUNTIME / 'observer.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('设备域名观察服务已运行') from None
        recorder = ObserverTelemetry()
        sock, tracker, binding, memory_inventory = None, None, None, None
        last_domains = None
        running = True
        next_config = next_report = next_inventory = next_new_inventory = 0
        next_tick, rate_start, rate_count, rate_drops, capture_drops = 0, time.monotonic(), 0, 0, 0
        state, error = 'waiting', ''

        def stop(_sig, _frame):
            nonlocal running
            running = False
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, stop)
        try:
            while running:
                now = time.monotonic()
                preferences = recorder.preferences.value
                enabled = recorder.preferences.initialized and preferences.domains
                if enabled != last_domains:
                    last_domains = enabled
                    next_config = next_report = 0
                if now >= next_config:
                    next_config = now + 10
                    try:
                        current = enrolled_devices() if enabled else None
                        if current != binding or (enabled and sock is None):
                            if tracker is not None:
                                tracker.tick(closing=True)
                                memory_inventory = tracker.inventory()
                                recorder.inventory(memory_inventory)
                            if sock is not None:
                                sock.close()
                            sock, tracker, binding = None, None, None
                            if current is not None:
                                inventory = memory_inventory
                                if inventory is None:
                                    try:
                                        inventory = read_bounded(port.PERSIST / 'domains.json')
                                    except (OSError, ValueError):
                                        pass
                                sock = open_capture(*current)
                                tracker = DomainTracker(current[1], recorder.event, preferences, inventory)
                                binding = current
                        if recorder.preferences.initialized:
                            state, error = ('observing' if enabled else 'disabled'), ''
                        else:
                            state, error = 'waiting', recorder.preferences.last_error or '等待日志策略读取'
                    except Exception as exc:
                        state, error = 'waiting', str(exc)[:300]
                        if sock is not None:
                            sock.close()
                        sock = None
                if tracker is not None:
                    tracker.preferences = preferences
                    if now >= next_tick:
                        tracker.tick()
                        next_tick = now + 1
                if now >= next_report:
                    if sock is not None:
                        try:
                            # Linux PACKET_STATISTICS resets its counters on read.
                            import struct
                            capture_drops += struct.unpack('II', sock.getsockopt(263, 6, 8))[1]
                        except OSError:
                            pass
                    report = tracker.report() if tracker is not None else {'time': utc(), 'domains': [], 'recent': [], 'health': {}}
                    report.update(state=state, error=error, pid=os.getpid(), identity=port.process_identity(os.getpid()),
                                  bridge=binding[0] if binding else '', mode=preferences.mode,
                                  tag=preferences.tag, limit=OBSERVATION_LIMIT,
                                  rate_drops=rate_drops, capture_drops=capture_drops, snaplen=SNAPLEN)
                    if tracker is not None:
                        report['_history'] = list(tracker.recent)
                    recorder.snapshot(report)
                    next_report = now + preferences.snapshot_interval
                if tracker is not None and tracker.dirty and (
                        now >= next_inventory or (tracker.new_names and now >= next_new_inventory)):
                    recorder.inventory(tracker.inventory())
                    tracker.dirty, tracker.new_names = False, False
                    next_inventory, next_new_inventory = now + 300, now + 60
                if sock is None:
                    time.sleep(.5)
                    continue
                try:
                    frame = sock.recv(SNAPLEN)
                except socket.timeout:
                    continue
                except OSError as exc:
                    error, state, next_config = str(exc)[:300], 'waiting', 0
                    sock.close()
                    sock = None
                    continue
                now = time.monotonic()
                if now - rate_start >= 1:
                    rate_start, rate_count = now, 0
                rate_count += 1
                if rate_count > PACKETS_PER_SECOND:
                    rate_drops += 1
                    time.sleep(min(.05, max(0, 1 - (now - rate_start))))
                    continue
                if len(frame) >= SNAPLEN:
                    tracker.health['snaplen_limited'] = tracker.health.get('snaplen_limited', 0) + 1
                tracker.feed(frame)
        finally:
            if sock is not None:
                sock.close()
            if tracker is not None:
                tracker.tick(closing=True)
                recorder.inventory(tracker.inventory())
            recorder.snapshot({'time': utc(), 'state': 'stopped', 'pid': os.getpid(), 'domains': [],
                               'limit': OBSERVATION_LIMIT})
            recorder.close(timeout=.2)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(run())
    except Exception as exc:
        print('域名观察服务：' + str(exc), file=sys.stderr)
        sys.exit(1)
