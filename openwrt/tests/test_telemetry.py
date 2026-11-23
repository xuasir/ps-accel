import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from telemetry import Telemetry


def wait_until(predicate, timeout=2):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(.005)
    return bool(predicate())


class TelemetryTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def test_blocked_writer_keeps_a_bounded_queue_and_latest_snapshot(self):
        entered, release = threading.Event(), threading.Event()

        def blocked(_self, _messages):
            entered.set()
            release.wait(5)

        with patch.object(Telemetry, 'write_events', blocked):
            recorder = Telemetry(self.root, capacity=3)
            try:
                recorder.event('writer is blocked')
                self.assertTrue(entered.wait(2))
                for index in range(10):
                    recorder.event('entry-' + str(index))
                for index in range(25):
                    recorder.snapshot({'sequence': index})
                with recorder.condition:
                    self.assertEqual(list(recorder.events), ['entry-7', 'entry-8', 'entry-9'])
                    self.assertEqual(recorder.pending['sequence'], 24)
                self.assertEqual(recorder.health()['dropped_logs'], 7)
                self.assertEqual(recorder.health()['coalesced_snapshots'], 24)
            finally:
                release.set()
                recorder.close(timeout=2)
        self.assertEqual(json.loads((self.root / 'status.json').read_text())['sequence'], 24)

    def test_write_errors_are_counted_and_later_snapshots_can_recover(self):
        original = Telemetry.write_status

        def fail_first(recorder, payload):
            if payload.get('sequence') == 1:
                raise OSError('status storage unavailable')
            original(recorder, payload)

        with patch.object(Telemetry, 'write_events', side_effect=OSError('log storage unavailable')):
            with patch.object(Telemetry, 'write_status', fail_first):
                recorder = Telemetry(self.root)
                try:
                    recorder.event('an event')
                    recorder.snapshot({'sequence': 1})
                    self.assertTrue(wait_until(lambda: recorder.health()['write_errors'] >= 2))
                    self.assertTrue(recorder.thread.is_alive())
                    recorder.snapshot({'sequence': 2})
                finally:
                    recorder.close(timeout=2)
        saved = json.loads((self.root / 'status.json').read_text())
        self.assertEqual(saved['sequence'], 2)
        self.assertEqual(saved['observability']['write_errors'], 2)
        self.assertEqual(saved['observability']['dropped_logs'], 1)

    def test_log_rotation_bounds_multibyte_batches_and_keeps_two_backups(self):
        recorder = Telemetry(self.root, rotate_bytes=100)
        for index in range(18):
            recorder.event('记录-' + str(index) + ' 中文事件 ' + 'x' * 20)
        recorder.close(timeout=2)
        files = sorted(self.root.glob('events.log*'))
        self.assertEqual({file.name for file in files}, {'events.log', 'events.log.1', 'events.log.2'})
        for file in files:
            self.assertLessEqual(file.stat().st_size, 100)
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            file.read_text(encoding='utf-8')
        self.assertIn('记录-17 ', (self.root / 'events.log').read_text())

    def test_oversized_event_is_bounded_and_valid_utf8(self):
        recorder = Telemetry(self.root, rotate_bytes=128)
        recorder.event('中' * 10000)
        recorder.close(timeout=2)
        self.assertLessEqual((self.root / 'events.log').stat().st_size, 128)
        self.assertTrue((self.root / 'events.log').read_text().endswith('\n'))

    def test_close_returns_with_a_blocked_writer(self):
        entered, release = threading.Event(), threading.Event()

        def blocked(_self, _payload):
            entered.set()
            release.wait(5)

        with patch.object(Telemetry, 'write_status', blocked):
            recorder = Telemetry(self.root)
            try:
                recorder.snapshot({'state': 'running'})
                self.assertTrue(entered.wait(2))
                start = time.monotonic()
                recorder.close(timeout=.02)
                self.assertLess(time.monotonic() - start, .5)
                self.assertTrue(recorder.thread.is_alive())
                recorder.event('ignored after close')
                self.assertEqual(len(recorder.events), 0)
            finally:
                release.set()
                recorder.thread.join(timeout=2)
        self.assertFalse(recorder.thread.is_alive())

    def test_recovery_report_uses_background_io_and_private_permissions(self):
        recorder = Telemetry(self.root)
        recorder.recovery({'reason': 'relay_closed', 'errors': []})
        recorder.close(timeout=2)
        path = self.root / 'recovery.json'
        self.assertEqual(json.loads(path.read_text())['reason'], 'relay_closed')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
