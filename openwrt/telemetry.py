"""Bounded background diagnostics; the forwarding thread performs no log I/O."""
from collections import deque
import json
import logging
import os
from pathlib import Path
import threading
import time

from observability import PreferenceCache, atomic_json, save_incident


class QueuedLogHandler(logging.Handler):
    def __init__(self, telemetry):
        super().__init__()
        self.telemetry = telemetry
        self.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))

    def emit(self, record):
        try:
            self.telemetry.log(record, self)
        except Exception as exc:
            self.telemetry.failed(exc)


class Telemetry:
    def __init__(self, runtime, capacity=128, rotate_bytes=1048576, preferences=None,
                 event_name='events.log', report_name='status', persist=None):
        if capacity < 1 or rotate_bytes < 2:
            raise ValueError('Diagnostics require positive queue and file limits')
        self.runtime = Path(runtime)
        self.capacity = capacity
        self.rotate_bytes = rotate_bytes
        if event_name not in ('events.log', 'domains.jsonl') or report_name not in ('status', 'domains'):
            raise ValueError('Invalid diagnostics filename')
        self.event_name, self.report_name = event_name, report_name
        self.preferences = PreferenceCache(preferences)
        self.persist = persist
        self.condition = threading.Condition()
        self.events = deque()
        self.incidents = deque()
        self.repeats = {}
        self.pending = None
        self.pending_recovery = None
        self.pending_inventory = None
        self.closed = False
        self.errors = 0
        self.dropped_logs = 0
        self.coalesced_snapshots = 0
        self.suppressed_logs = 0
        self.last_error = ''
        self.handler = QueuedLogHandler(self)
        self.preference_stop = threading.Event()
        self.preference_thread = None
        if self.preferences.path is not None:
            self.preference_thread = threading.Thread(target=self.preference_worker,
                                                       name='ps-accel-preferences', daemon=True)
            self.preference_thread.start()
        self.thread = threading.Thread(target=self.worker, name='ps-accel-diagnostics', daemon=True)
        self.thread.start()

    def health(self):
        with self.condition:
            return {'write_errors': self.errors, 'dropped_logs': self.dropped_logs,
                    'coalesced_snapshots': self.coalesced_snapshots, 'last_error': self.last_error,
                    'suppressed_logs': self.suppressed_logs, 'mode': self.preferences.value.mode,
                    'snapshot_interval': self.snapshot_interval,
                    'preference_error': self.preferences.last_error}

    @property
    def snapshot_interval(self):
        return self.preferences.value.snapshot_interval

    def log(self, record, handler):
        if self.preferences.value.mode == 'verbose':
            self.event(handler.format(record))
            return
        if record.levelno < logging.WARNING and not getattr(record, 'essential', False):
            with self.condition:
                self.suppressed_logs += 1
            return
        # Keep the first occurrence immediately; count repeats without timestamp
        # formatting or disk I/O. The worker emits bounded one-minute summaries.
        message = record.getMessage()[:512]
        key = (record.levelno, message)
        now = time.monotonic()
        with self.condition:
            if key in self.repeats:
                value = self.repeats[key]
                value['count'] += 1
                value['last'] = now
                self.suppressed_logs += 1
                return
            if len(self.repeats) >= 64:
                oldest = next(iter(self.repeats))
                value = self.repeats.pop(oldest)
                if value['count']:
                    self.event(self.repeat_message(oldest, value))
            self.repeats[key] = {'count': 0, 'first': now, 'last': now}
        self.event(handler.format(record))

    @staticmethod
    def repeat_message(key, value):
        return ('重复事件合并：' + key[1] + '；额外出现 ' + str(value['count']) +
                ' 次；跨度 ' + str(round(value['last'] - value['first'], 1)) + ' 秒')

    def incident(self, payload):
        if self.persist is None:
            return
        with self.condition:
            if self.closed:
                return
            if len(self.incidents) >= 16:
                self.incidents.popleft()
                self.dropped_logs += 1
            self.incidents.append(payload)
            self.condition.notify()

    def failed(self, error, dropped=0):
        with self.condition:
            self.errors += 1
            self.dropped_logs += dropped
            self.last_error = str(error)[:300]

    def snapshot(self, payload):
        with self.condition:
            if self.closed:
                return
            if self.pending is not None:
                self.coalesced_snapshots += 1
            self.pending = payload
            self.condition.notify()

    def recovery(self, payload):
        with self.condition:
            if self.closed:
                return
            self.pending_recovery = payload
            self.condition.notify()

    def inventory(self, payload):
        with self.condition:
            if not self.closed and self.persist is not None:
                self.pending_inventory = payload
                self.condition.notify()

    def event(self, message):
        with self.condition:
            if self.closed:
                return
            if len(self.events) >= self.capacity:
                self.events.popleft()
                self.dropped_logs += 1
            self.events.append(str(message)[:4096])
            self.condition.notify()

    def write_report(self, name, payload):
        self.runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.runtime / (name + '.json')
        temp = self.runtime / (name + '.' + str(os.getpid()) + '.tmp')
        value = dict(payload, observability=self.health())
        # Domain snapshots stay compact so the maximum inventory fits the RPC
        # reader's 1 MiB limit. Relay status retains its readable formatting.
        options = {'separators': (',', ':')} if name == 'domains' else {'indent': 2}
        content = json.dumps(value, ensure_ascii=False, allow_nan=False, **options) + '\n'
        if name == 'domains':
            recent = list(value.get('recent', []))
            initial_count = len(recent)
            while len(content.encode('utf-8')) > 1048576 and recent:
                for _ in range(max(1, len(recent) // 4)):
                    index = next((i for i, event in enumerate(recent) if not event.get('problem')), 0)
                    recent.pop(index)
                value.update(recent=recent, snapshot_truncated=True,
                             trimmed_context_events=initial_count - len(recent))
                content = json.dumps(value, ensure_ascii=False, allow_nan=False, **options) + '\n'
            if len(content.encode('utf-8')) > 1048576:
                raise ValueError('域名清单超过快照上限')
        temp.write_text(content, encoding='utf-8')
        temp.chmod(0o600)
        temp.replace(path)

    def write_status(self, payload):
        self.write_report('status', payload)

    def write_recovery(self, payload):
        self.write_report('recovery', payload)

    def write_events(self, messages):
        self.runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.runtime / self.event_name
        chunk = bytearray()

        def append_chunk():
            if path.exists() and path.stat().st_size + len(chunk) > self.rotate_bytes:
                path.with_name(self.event_name + '.2').unlink(missing_ok=True)
                backup = path.with_name(self.event_name + '.1')
                if backup.exists():
                    backup.replace(path.with_name(self.event_name + '.2'))
                path.replace(backup)
            with path.open('ab') as output:
                output.write(chunk)
            path.chmod(0o600)

        for message in messages:
            # Respect the file limit even for a full queue of multibyte text.
            line = message.encode('utf-8', errors='replace')[:self.rotate_bytes - 1]
            line = line.decode('utf-8', errors='ignore').encode('utf-8') + b'\n'
            if chunk and len(chunk) + len(line) > self.rotate_bytes:
                append_chunk()
                chunk.clear()
            chunk.extend(line)
        if chunk:
            append_chunk()

    def preference_worker(self):
        # Switch updates must remain available while diagnostics storage stalls.
        while not self.preference_stop.is_set():
            if self.preferences.refresh() and self.event_name == 'events.log':
                self.event('日志策略已更新：' + self.preferences.value.mode)
            self.preference_stop.wait(2)

    def worker(self):
        while True:
            with self.condition:
                self.condition.wait_for(lambda: self.closed or self.pending is not None
                                        or self.pending_recovery is not None or self.pending_inventory is not None
                                        or self.events or self.incidents,
                                        timeout=2)
                now = time.monotonic()
                for key, value in list(self.repeats.items()):
                    if self.closed or now - value['first'] >= 60 or self.preferences.value.mode == 'verbose':
                        if value['count']:
                            if len(self.events) >= self.capacity:
                                self.events.popleft()
                                self.dropped_logs += 1
                            self.events.append(self.repeat_message(key, value))
                        del self.repeats[key]
                if (self.closed and self.pending is None and self.pending_recovery is None
                        and self.pending_inventory is None and not self.events and not self.incidents):
                    return
                snapshot, recovery, messages, incidents = (self.pending, self.pending_recovery,
                                                           list(self.events), list(self.incidents))
                inventory = self.pending_inventory
                self.pending = None
                self.pending_recovery = None
                self.pending_inventory = None
                self.events.clear()
                self.incidents.clear()
            if messages:
                try:
                    self.write_events(messages)
                except Exception as exc:
                    self.failed(exc, len(messages))
            if snapshot is not None:
                try:
                    if self.report_name == 'status':
                        self.write_status(snapshot)
                    else:
                        self.write_report(self.report_name, snapshot)
                except Exception as exc:
                    self.failed(exc)
            for incident in incidents:
                try:
                    save_incident(self.persist, incident)
                except Exception as exc:
                    self.failed(exc)
            if inventory is not None:
                try:
                    atomic_json(Path(self.persist) / 'domains.json', inventory)
                except Exception as exc:
                    self.failed(exc)
            if recovery is not None:
                try:
                    self.write_recovery(recovery)
                except Exception as exc:
                    self.failed(exc)

    def close(self, timeout=.2):
        deadline = time.monotonic() + max(0, timeout)
        with self.condition:
            self.closed = True
            self.condition.notify()
        self.preference_stop.set()
        self.thread.join(timeout=max(0, deadline - time.monotonic()))
        if self.preference_thread is not None:
            self.preference_thread.join(timeout=max(0, deadline - time.monotonic()))
