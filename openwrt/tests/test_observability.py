import json
import logging
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import observability as obs
from telemetry import Telemetry
from test_telemetry import wait_until


class LogPolicyTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def record(self, level, message, essential=False):
        record = logging.LogRecord('test', level, '', 0, message, (), None)
        record.essential = essential
        return record

    def test_compact_keeps_essential_events_and_coalesces_repeated_errors(self):
        recorder = Telemetry(self.root)
        recorder.handler.handle(self.record(logging.INFO, 'routine sample'))
        recorder.handler.handle(self.record(logging.INFO, 'relay ready', True))
        for _ in range(100):
            recorder.handler.handle(self.record(logging.ERROR, 'DNS failure'))
        recorder.close(timeout=2)
        output = (self.root / 'events.log').read_text()
        self.assertNotIn('routine sample', output)
        self.assertIn('relay ready', output)
        self.assertIn('额外出现 99 次', output)
        self.assertEqual(recorder.health()['suppressed_logs'], 100)
        self.assertEqual(recorder.snapshot_interval, 10)

    def test_runtime_mode_change_preserves_relay_state_and_enables_verbose_logs(self):
        path = self.root / 'preferences.json'
        recorder = Telemetry(self.root, preferences=path)
        try:
            obs.save_preferences(path, 'verbose', True, 'Portal 升级')
            self.assertTrue(wait_until(lambda: recorder.snapshot_interval == 2, timeout=3))
            recorder.handler.handle(self.record(logging.INFO, 'routine sample'))
            recorder.snapshot({'state': 'running', 'sequence': 42})
        finally:
            recorder.close(timeout=2)
        self.assertIn('routine sample', (self.root / 'events.log').read_text())
        saved = json.loads((self.root / 'status.json').read_text())
        self.assertEqual(saved['sequence'], 42)
        self.assertEqual(saved['observability']['mode'], 'verbose')

    def test_capture_switch_and_mode_refresh_while_diagnostics_writer_is_blocked(self):
        path = self.root / 'preferences.json'
        obs.save_preferences(path, 'compact', True, '')
        entered, release = threading.Event(), threading.Event()

        def blocked(_self, _messages):
            entered.set()
            release.wait(5)

        with patch.object(Telemetry, 'write_events', blocked):
            recorder = Telemetry(self.root, preferences=path, event_name='domains.jsonl', report_name='domains')
            try:
                self.assertTrue(wait_until(lambda: recorder.preferences.initialized))
                recorder.event('{"kind":"dns_query"}')
                self.assertTrue(entered.wait(2))
                obs.save_preferences(path, 'verbose', False, '升级')
                self.assertTrue(wait_until(lambda: not recorder.preferences.value.domains, timeout=3))
                self.assertEqual(recorder.snapshot_interval, 2)
                self.assertEqual(recorder.preferences.value.tag, '升级')
                started = time.monotonic()
                recorder.close(timeout=.02)
                self.assertLess(time.monotonic() - started, .5)
            finally:
                release.set()
                recorder.close(timeout=2)

    def test_blocked_preference_read_keeps_status_writes_and_close_available(self):
        entered, release = threading.Event(), threading.Event()
        original = obs.load_preferences

        def blocked(path):
            entered.set()
            release.wait(5)
            return original(path)

        with patch.object(obs, 'load_preferences', side_effect=blocked):
            recorder = Telemetry(self.root, preferences=self.root / 'preferences.json')
            try:
                self.assertTrue(entered.wait(2))
                recorder.snapshot({'state': 'running', 'sequence': 42})
                self.assertTrue(wait_until(lambda: (self.root / 'status.json').exists()))
                self.assertFalse(recorder.preferences.initialized)
                started = time.monotonic()
                recorder.close(timeout=.02)
                self.assertLess(time.monotonic() - started, .5)
            finally:
                release.set()
                recorder.close(timeout=2)
        self.assertEqual(json.loads((self.root / 'status.json').read_text())['sequence'], 42)

    def test_corrupt_preferences_keep_the_last_working_mode(self):
        path = self.root / 'preferences.json'
        obs.save_preferences(path, 'verbose', True, '')
        cache = obs.PreferenceCache(path)
        cache.refresh()
        path.write_text('{broken')
        self.assertFalse(cache.refresh())
        self.assertEqual(cache.value.mode, 'verbose')
        self.assertTrue(cache.last_error)

    def test_preference_read_and_log_storage_blocking_keep_queue_calls_bounded(self):
        entered, release = threading.Event(), threading.Event()
        original = obs.load_preferences

        def blocked(path):
            entered.set()
            release.wait(5)
            return original(path)

        with patch.object(obs, 'load_preferences', side_effect=blocked):
            recorder = Telemetry(self.root, preferences=self.root / 'preferences.json')
            try:
                self.assertTrue(entered.wait(2))
                started = time.monotonic()
                for index in range(1000):
                    recorder.handler.handle(self.record(logging.WARNING, 'same error'))
                    recorder.snapshot({'sequence': index})
                recorder.close(timeout=.02)
                self.assertLess(time.monotonic() - started, .5)
                self.assertLessEqual(len(recorder.events), 128)
            finally:
                release.set()
                recorder.thread.join(timeout=2)
        self.assertEqual(json.loads((self.root / 'status.json').read_text())['sequence'], 999)

    def test_repeat_cache_stays_bounded_with_many_distinct_errors(self):
        recorder = Telemetry(self.root, capacity=4)
        for index in range(300):
            recorder.handler.handle(self.record(logging.WARNING, 'error-' + str(index)))
        self.assertLessEqual(len(recorder.repeats), 64)
        recorder.close(timeout=2)

    def test_domain_json_lines_remain_structured_during_mode_changes(self):
        path = self.root / 'preferences.json'
        obs.save_preferences(path, 'verbose', True, '升级')
        recorder = Telemetry(self.root, preferences=path, event_name='domains.jsonl', report_name='domains')
        recorder.event(json.dumps({'kind': 'dns_error', 'domain': 'api.sony.example'}, ensure_ascii=False))
        recorder.close(timeout=2)
        for line in (self.root / 'domains.jsonl').read_text().splitlines():
            self.assertEqual(json.loads(line)['kind'], 'dns_error')


class IncidentStorageTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def test_tag_time_changes_only_when_the_cohort_label_changes(self):
        path = self.root / 'observability.json'
        with patch.object(obs.time, 'time', return_value=100):
            first = obs.save_preferences(path, 'compact', True, '升级前')
        with patch.object(obs.time, 'time', return_value=200):
            same = obs.save_preferences(path, 'verbose', False, '升级前')
            changed = obs.save_preferences(path, 'compact', True, '升级后')
        self.assertEqual(first.tag_since, same.tag_since)
        self.assertEqual(changed.tag_since, 200)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_failure_history_survives_reload_and_rotates_at_32_records(self):
        for index in range(40):
            obs.save_incident(self.root, obs.new_incident('manual', '失败-' + str(index), epoch=1000 + index))
        values = obs.read_incidents(self.root)
        self.assertEqual(len(values), 32)
        self.assertEqual(values[0]['note'], '失败-39')
        self.assertEqual(len(list((self.root / 'incidents').glob('*.json'))), 32)
        self.assertTrue(all(item.stat().st_mode & 0o777 == 0o600 for item in (self.root / 'incidents').glob('*.json')))

    def test_failure_window_includes_actual_errors_and_success_evidence(self):
        incident = obs.new_incident('manual', '失败', epoch=1000)
        events = [dict(epoch=epoch, time=obs.utc(epoch), kind=kind, device='portal', domains=[name], problem=problem)
                  for epoch, kind, name, problem in (
                      (819, 'dns_error', 'outside.example', True),
                      (820, 'dns_ok', 'resolved.example', False),
                      (995, 'dns_error', 'new.sony.example', True),
                      (1005, 'tcp_timeout', 'new.sony.example', True),
                      (1016, 'dns_error', 'outside.example', True))]
        with patch.object(obs.time, 'time', return_value=1020):
            value = obs.correlate(incident, events)
        self.assertEqual(value['event_count'], 3)
        self.assertEqual(value['candidates'][0]['domain'], 'new.sony.example')
        self.assertEqual(value['candidates'][0]['errors'], 2)
        self.assertTrue(value['evidence_complete'])
        self.assertEqual(value['candidates'][1]['errors'], 0)

    def test_partial_memory_history_keeps_only_the_missing_compact_summary_count(self):
        incident = obs.new_incident('manual', '失败', epoch=1000)
        first = {'epoch': 900, 'time': obs.utc(900), 'device': 'portal', 'kind': 'dns_error',
                 'domains': ['blocked.sony.example'], 'problem': True, 'rcode': 3}
        last = dict(first, epoch=940, time=obs.utc(940))
        summary = dict(last, repeated=True, first_epoch=900, last_epoch=940, count=4)
        merged = obs.merge_events([first, summary], [first, last])
        evidence = obs.correlate(incident, merged)
        self.assertEqual(evidence['candidates'][0]['errors'], 5)
        self.assertEqual(next(item for item in merged if item.get('repeated'))['count'], 3)
        self.assertEqual(summary['count'], 4)

    def test_failure_context_retains_earlier_errors_when_successes_fill_the_window(self):
        incident = obs.new_incident('manual', '失败', epoch=1000)
        events = [{'epoch': 900, 'time': obs.utc(900), 'device': 'portal', 'kind': 'dns_error',
                   'domains': ['blocked.sony.example'], 'problem': True, 'rcode': 3}]
        events.extend({'epoch': 901 + index, 'time': obs.utc(901 + index), 'device': 'portal',
                       'kind': 'dns_ok', 'domains': ['working.sony.example'], 'problem': False}
                      for index in range(100))
        evidence = obs.correlate(incident, events)
        self.assertEqual(evidence['event_count'], 101)
        self.assertEqual(len(evidence['events']), 80)
        self.assertTrue(evidence['truncated'])
        self.assertEqual(evidence['events'][0]['rcode'], 3)

    def test_failure_write_failure_is_isolated_and_later_records_recover(self):
        recorder = Telemetry(self.root / 'runtime', persist=self.root / 'persist')
        with patch('telemetry.save_incident', side_effect=OSError('storage blocked')):
            recorder.incident(obs.new_incident('relay', 'one'))
            self.assertTrue(wait_until(lambda: recorder.health()['write_errors'] == 1))
        recorder.incident(obs.new_incident('relay', 'two'))
        recorder.close(timeout=2)
        self.assertEqual(obs.read_incidents(self.root / 'persist')[0]['note'], 'two')

    def test_invalid_preferences_do_not_discard_an_automatic_failure(self):
        (self.root / 'observability.json').write_text('[]')
        obs.record_failure(self.root / 'runtime', self.root, 'management', '真实错误')
        self.assertEqual(obs.read_incidents(self.root)[0]['note'], '真实错误')


if __name__ == '__main__':
    unittest.main()
