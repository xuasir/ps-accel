from pathlib import Path
import signal
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from scapy.all import DNS, DNSQR
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import observability as obs
import portal_observe as observer
import portal_openwrt as port
from test_domains import DEVICES, dns_frame


class ObserverServiceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        for name in ('RUNTIME', 'PERSIST'):
            value = self.root / name.lower()
            value.mkdir()
            p = patch.object(port, name, value)
            p.start()
            self.addCleanup(p.stop)

    def test_blocked_observer_storage_keeps_capture_running_and_shutdown_bounded(self):
        entered, release = threading.Event(), threading.Event()
        signals, recorders, received = {}, [], []
        original = observer.ObserverTelemetry

        def recorder():
            value = original()
            recorders.append(value)
            return value

        def blocked(_self, _name, _payload):
            entered.set()
            release.wait(5)

        class Capture:
            closed = False
            def recv(self, _size):
                if not received:
                    if not entered.wait(2):
                        raise AssertionError('diagnostics worker did not enter its write')
                index = len(received)
                received.append(index)
                if index == 20:
                    signals[signal.SIGTERM](signal.SIGTERM, None)
                return dns_frame(DNS(id=index, qd=DNSQR(qname='observed' + str(index) + '.sony.example')))
            def getsockopt(self, *_args):
                return b'\0' * 8
            def close(self):
                self.closed = True

        capture = Capture()
        try:
            with (patch.object(original, 'write_report', blocked),
                  patch.object(observer, 'ObserverTelemetry', side_effect=recorder),
                  patch.object(observer, 'enrolled_devices', return_value=('br-lan', DEVICES)),
                  patch.object(observer, 'open_capture', return_value=capture),
                  patch.object(observer.signal, 'signal', side_effect=lambda sig, fn: signals.update({sig: fn})),
                  patch.object(observer.os, 'umask'),
                  patch.object(port, 'command', side_effect=AssertionError('relay command invoked'))):
                started = time.monotonic()
                self.assertEqual(observer.run(), 0)
                self.assertLess(time.monotonic() - started, 1)
            self.assertEqual(len(received), 21)
            self.assertTrue(capture.closed)
            self.assertTrue(recorders[0].thread.is_alive())
        finally:
            release.set()
            for value in recorders:
                value.thread.join(timeout=2)
        inventory = obs.read_bounded(port.PERSIST / 'domains.json')
        self.assertEqual(len(inventory['domains']), 21)

    def test_disabled_observer_stays_idle_without_device_queries_or_packet_capture(self):
        obs.save_preferences(port.PERSIST / 'observability.json', 'compact', False, '')
        signals = {}
        original = observer.ObserverTelemetry

        def recorder():
            value = original()
            value.preferences.refresh()
            return value

        def sleep(_seconds):
            signals[signal.SIGTERM](signal.SIGTERM, None)

        with (patch.object(observer, 'ObserverTelemetry', side_effect=recorder),
              patch.object(observer, 'enrolled_devices', side_effect=AssertionError('device query invoked')),
              patch.object(observer, 'open_capture', side_effect=AssertionError('capture opened')),
              patch.object(observer.signal, 'signal', side_effect=lambda sig, fn: signals.update({sig: fn})),
              patch.object(observer.os, 'umask'), patch.object(observer.time, 'sleep', side_effect=sleep)):
            self.assertEqual(observer.run(), 0)

    def test_runtime_capture_toggle_preserves_inventory_even_while_storage_is_blocked(self):
        entered, release = threading.Event(), threading.Event()
        signals, recorders, captures = {}, [], []
        original = observer.ObserverTelemetry

        def recorder():
            value = original()
            value.preferences.refresh()
            recorders.append(value)
            return value

        def blocked(_self, _name, _payload):
            entered.set()
            release.wait(5)

        def preferences(enabled):
            obs.save_preferences(port.PERSIST / 'observability.json', 'compact', enabled, '')
            recorders[0].preferences.refresh()

        class Capture:
            closed = False
            def __init__(self, index):
                self.index = index
            def recv(self, _size):
                if self.index == 0:
                    if not entered.wait(2):
                        raise AssertionError('diagnostics worker did not enter its write')
                    preferences(False)
                else:
                    signals[signal.SIGTERM](signal.SIGTERM, None)
                return dns_frame(DNS(id=self.index, qd=DNSQR(qname='toggle' + str(self.index) + '.sony.example')))
            def getsockopt(self, *_args):
                return b'\0' * 8
            def close(self):
                self.closed = True

        def capture(*_args):
            value = Capture(len(captures))
            captures.append(value)
            return value

        def idle(_seconds):
            self.assertFalse(recorders[0].preferences.value.domains)
            self.assertEqual(len(captures), 1)
            self.assertTrue(captures[0].closed)
            preferences(True)

        try:
            with (patch.object(original, 'write_report', blocked),
                  patch.object(observer, 'ObserverTelemetry', side_effect=recorder),
                  patch.object(observer, 'enrolled_devices', return_value=('br-lan', DEVICES)) as enrollment,
                  patch.object(observer, 'open_capture', side_effect=capture),
                  patch.object(observer.signal, 'signal', side_effect=lambda sig, fn: signals.update({sig: fn})),
                  patch.object(observer.os, 'umask'), patch.object(observer.time, 'sleep', side_effect=idle),
                  patch.object(port, 'command', side_effect=AssertionError('relay command invoked'))):
                started = time.monotonic()
                self.assertEqual(observer.run(), 0)
                self.assertLess(time.monotonic() - started, 1)
                self.assertEqual(enrollment.call_count, 2)
            self.assertEqual(len(captures), 2)
            self.assertTrue(all(value.closed for value in captures))
        finally:
            release.set()
            for value in recorders:
                value.thread.join(timeout=2)
        inventory = obs.read_bounded(port.PERSIST / 'domains.json')
        self.assertEqual({item['domain'] for item in inventory['domains']},
                         {'toggle0.sony.example', 'toggle1.sony.example'})

    def test_startup_waits_for_the_saved_capture_switch_before_querying_devices(self):
        obs.save_preferences(port.PERSIST / 'observability.json', 'compact', False, '')
        entered, release = threading.Event(), threading.Event()
        signals, recorders = {}, []
        original_recorder, original_load = observer.ObserverTelemetry, obs.load_preferences

        def blocked_load(path):
            entered.set()
            release.wait(5)
            return original_load(path)

        def recorder():
            value = original_recorder()
            recorders.append(value)
            return value

        def idle(_seconds):
            self.assertTrue(entered.wait(2))
            signals[signal.SIGTERM](signal.SIGTERM, None)

        try:
            with (patch.object(obs, 'load_preferences', side_effect=blocked_load),
                  patch.object(observer, 'ObserverTelemetry', side_effect=recorder),
                  patch.object(observer, 'enrolled_devices', side_effect=AssertionError('premature device query')) as enrollment,
                  patch.object(observer, 'open_capture', side_effect=AssertionError('premature capture')) as capture,
                  patch.object(observer.signal, 'signal', side_effect=lambda sig, fn: signals.update({sig: fn})),
                  patch.object(observer.os, 'umask'), patch.object(observer.time, 'sleep', side_effect=idle)):
                self.assertEqual(observer.run(), 0)
                enrollment.assert_not_called()
                capture.assert_not_called()
        finally:
            release.set()
            for value in recorders:
                value.thread.join(timeout=2)


if __name__ == '__main__':
    unittest.main()
