"""Bounded background diagnostics; the forwarding thread performs no log I/O."""
from collections import deque
import json
import logging
import os
from pathlib import Path
import threading


class QueuedLogHandler(logging.Handler):
    def __init__(self, telemetry):
        super().__init__()
        self.telemetry = telemetry
        self.setFormatter(logging.Formatter('%(asctime)s %(levelname)s %(message)s'))

    def emit(self, record):
        try:
            self.telemetry.event(self.format(record))
        except Exception as exc:
            self.telemetry.failed(exc)


class Telemetry:
    def __init__(self, runtime, capacity=128, rotate_bytes=1048576):
        if capacity < 1 or rotate_bytes < 2:
            raise ValueError('Diagnostics require positive queue and file limits')
        self.runtime = Path(runtime)
        self.capacity = capacity
        self.rotate_bytes = rotate_bytes
        self.condition = threading.Condition()
        self.events = deque()
        self.pending = None
        self.pending_recovery = None
        self.closed = False
        self.errors = 0
        self.dropped_logs = 0
        self.coalesced_snapshots = 0
        self.last_error = ''
        self.handler = QueuedLogHandler(self)
        self.thread = threading.Thread(target=self.worker, name='ps-accel-diagnostics', daemon=True)
        self.thread.start()

    def health(self):
        with self.condition:
            return {'write_errors': self.errors, 'dropped_logs': self.dropped_logs,
                    'coalesced_snapshots': self.coalesced_snapshots, 'last_error': self.last_error}

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
        temp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        temp.chmod(0o600)
        temp.replace(path)

    def write_status(self, payload):
        self.write_report('status', payload)

    def write_recovery(self, payload):
        self.write_report('recovery', payload)

    def write_events(self, messages):
        self.runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
        path = self.runtime / 'events.log'
        chunk = bytearray()

        def append_chunk():
            if path.exists() and path.stat().st_size + len(chunk) > self.rotate_bytes:
                path.with_name('events.log.2').unlink(missing_ok=True)
                backup = path.with_name('events.log.1')
                if backup.exists():
                    backup.replace(path.with_name('events.log.2'))
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

    def worker(self):
        while True:
            with self.condition:
                self.condition.wait_for(lambda: self.closed or self.pending is not None
                                        or self.pending_recovery is not None or self.events)
                if self.closed and self.pending is None and self.pending_recovery is None and not self.events:
                    return
                snapshot, recovery, messages = self.pending, self.pending_recovery, list(self.events)
                self.pending = None
                self.pending_recovery = None
                self.events.clear()
            if messages:
                try:
                    self.write_events(messages)
                except Exception as exc:
                    self.failed(exc, len(messages))
            if snapshot is not None:
                try:
                    self.write_status(snapshot)
                except Exception as exc:
                    self.failed(exc)
            if recovery is not None:
                try:
                    self.write_recovery(recovery)
                except Exception as exc:
                    self.failed(exc)

    def close(self, timeout=.2):
        with self.condition:
            self.closed = True
            self.condition.notify()
        self.thread.join(timeout=timeout)
