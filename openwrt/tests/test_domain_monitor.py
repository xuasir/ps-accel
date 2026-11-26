import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from scapy.all import DNS, DNSQR, DNSRR, Ether, IP, Raw, UDP

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import domain_monitor as monitoring
import observability as obs
import portal_luci as api
import portal_openwrt as port
from domain_tracker import DomainTracker
from test_domains import DEVICES, EPOCH, dns_frame, tcp_frame
from test_stream_quality import big, control, feedback


def stream_frame(payload):
    return bytes(Ether(src=DEVICES['portal']['mac'], dst=DEVICES['ps5']['mac']) /
                 IP(src=DEVICES['portal']['ip'], dst=DEVICES['ps5']['ip']) /
                 UDP(sport=50000, dport=9296) / Raw(payload))


class ConnectionBatchTests(unittest.TestCase):
    def setUp(self):
        self.tracker = DomainTracker(DEVICES, lambda _line: None, obs.LogPreferences(), epoch=EPOCH)

    def resolve(self, name, epoch=EPOCH, ident=1, rcode=0):
        self.tracker.feed(dns_frame(DNS(id=ident, qd=DNSQR(qname=name))), epoch)
        reply = DNS(id=ident, qr=1, rcode=rcode, qd=DNSQR(qname=name))
        if not rcode:
            reply.an = DNSRR(rrname=name, rdata='1.1.1.1', ttl=120)
        self.tracker.feed(dns_frame(reply, True), epoch + .1)

    def test_batches_isolate_counts_and_keep_a_recovered_dns_failure(self):
        self.resolve('retry.example', rcode=3)
        self.resolve('retry.example', EPOCH + 2, ident=2)
        first = self.tracker.monitor.snapshot()['batches'][0]
        self.assertTrue(first['domains'][0]['dns_failed'])
        self.assertEqual(first['domains'][0]['last_dns_result'], 'dns_ok')
        self.tracker.tick(EPOCH + 63)
        self.resolve('retry.example', EPOCH + 65, ident=3)
        batches = self.tracker.monitor.snapshot()['batches']
        self.assertEqual(len(batches), 2)
        self.assertFalse(batches[0]['domains'][0]['dns_failed'])
        self.assertEqual(batches[0]['domains'][0]['counts'], {'dns_query': 1, 'dns_ok': 1})
        self.assertEqual(batches[1]['state'], 'archived')
        self.assertEqual(batches[1]['domains'][0]['counts']['dns_error'], 1)

    def test_pending_dns_replies_and_timeouts_stay_in_their_original_batch(self):
        self.tracker.feed(dns_frame(DNS(id=1, qd=DNSQR(qname='previous.example'))), EPOCH)
        old_id = self.tracker.monitor.current_id
        new_id = self.tracker.monitor.begin(EPOCH + 1, source='manual')
        reply = DNS(id=1, qr=1, rcode=3, qd=DNSQR(qname='previous.example'))
        self.tracker.feed(dns_frame(reply, True), EPOCH + 2)
        self.tracker.feed(dns_frame(DNS(id=2, qd=DNSQR(qname='current.example'))), EPOCH + 3)
        self.tracker.tick(EPOCH + 12)
        batches = {batch['id']: batch for batch in self.tracker.monitor.snapshot()['batches']}
        self.assertEqual([row['domain'] for row in batches[old_id]['domains']], ['previous.example'])
        self.assertEqual([row['domain'] for row in batches[new_id]['domains']], ['current.example'])
        self.assertEqual(batches[new_id]['domains'][0]['counts']['dns_timeout'], 1)

    def test_stream_markers_split_reconnects_and_feedback_keeps_the_batch_open(self):
        self.resolve('auth.example')
        first_id = self.tracker.monitor.current_id
        self.tracker.feed(stream_frame(big()), EPOCH + 1)
        self.tracker.feed(stream_frame(big()), EPOCH + 2)
        self.assertEqual(self.tracker.monitor.current_id, first_id)
        self.assertEqual(len(self.tracker.monitor.batches), 1)
        self.tracker.feed(stream_frame(feedback()), EPOCH + 35)
        self.tracker.tick(EPOCH + 64)
        self.assertEqual(self.tracker.monitor.current_id, first_id)
        self.tracker.feed(stream_frame(big(2)), EPOCH + 65)
        self.assertNotEqual(self.tracker.monitor.current_id, first_id)
        self.assertEqual(len(self.tracker.monitor.batches), 2)
        self.tracker.feed(stream_frame(control(b'\x08\x08\x52\x02\x0a\x00', 3)), EPOCH + 66)
        self.assertIsNone(self.tracker.monitor.current_id)
        self.assertEqual(self.tracker.monitor.snapshot()['batches'][0]['end_reason'], 'disconnected')
        self.assertNotIn('payload', json.dumps(self.tracker.monitor.snapshot()))

    def test_tcp_failure_and_empty_aaaa_response_keep_dns_failure_counts_precise(self):
        self.resolve('connected.example')
        self.tracker.feed(tcp_frame(), EPOCH + 1)
        self.tracker.feed(tcp_frame('RA', True, ack=101), EPOCH + 2)
        query = DNS(id=2, qd=DNSQR(qname='connected.example', qtype='AAAA'))
        self.tracker.feed(dns_frame(query), EPOCH + 3)
        self.tracker.feed(dns_frame(DNS(id=2, qr=1, qd=query.qd), True), EPOCH + 4)
        row = self.tracker.monitor.snapshot()['batches'][0]['domains'][0]
        self.assertFalse(row['dns_failed'])
        self.assertEqual(row['counts']['tcp_reset'], 1)
        self.assertEqual(row['counts']['dns_empty'], 1)

    def test_restore_retains_resolution_addresses_and_binds_history_to_the_device_pair(self):
        self.resolve('persisted.example')
        saved = json.loads(json.dumps(self.tracker.monitor.snapshot()))
        restored = monitoring.DomainMonitor(DEVICES, saved)
        batch = restored.snapshot()['batches'][0]
        self.assertEqual(batch['state'], 'archived')
        self.assertEqual(batch['domains'][0]['addresses'][0]['address'], '1.1.1.1')
        changed = dict(DEVICES, portal=dict(DEVICES['portal'], mac='02:00:00:00:00:99'))
        self.assertEqual(monitoring.DomainMonitor(changed, saved).snapshot()['batches'], [])

    def test_history_and_event_limits_preserve_failures_and_the_newest_batch(self):
        monitor = self.tracker.monitor
        monitor.record({'epoch': EPOCH, 'time': obs.utc(EPOCH), 'device': 'portal', 'kind': 'dns_error',
                        'domains': ['failed.example'], 'rcode': 3})
        for index in range(monitoring.MAX_BATCH_EVENTS + 10):
            monitor.record({'epoch': EPOCH + index / 100, 'time': obs.utc(EPOCH), 'device': 'portal',
                            'kind': 'dns_ok', 'domains': ['ok.example']})
        first = monitor.snapshot()['batches'][0]
        self.assertEqual(len(first['events']), monitoring.MAX_BATCH_EVENTS)
        self.assertEqual(first['events'][0]['kind'], 'dns_error')
        with patch.object(monitoring, 'MAX_HISTORY_BYTES', 32768):
            for index in range(40):
                monitor.begin(EPOCH + 100 * (index + 1))
                for number in range(12):
                    monitor.record({'epoch': EPOCH + 100 * (index + 1), 'time': obs.utc(EPOCH),
                                    'device': 'portal', 'kind': 'dns_ok', 'domains': [
                                        ('a' * 60 + '.') * 3 + str(number) + '.example']})
            saved = monitor.snapshot()
        self.assertLessEqual(len(json.dumps(saved, ensure_ascii=False, separators=(',', ':')).encode()), 32768)
        self.assertLessEqual(len(saved['batches']), monitoring.MAX_BATCHES)
        self.assertEqual(saved['batches'][0]['id'], monitor.current_id)


class DomainMonitorApiTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        for name in ('PERSIST', 'RUNTIME'):
            folder = Path(temp.name) / name.lower()
            folder.mkdir()
            patched = patch.object(port, name, folder)
            patched.start()
            self.addCleanup(patched.stop)
        obs.atomic_json(port.PERSIST / 'devices.json', {'config': {role + '_ip': info['ip'] for role, info in DEVICES.items()},
                        **{role + '_mac': info['mac'] for role, info in DEVICES.items()}})
        obs.atomic_json(port.RUNTIME / 'domains.json', {'time': obs.utc(), 'state': 'observing', 'pid': 123,
                                                     'identity': 'live', 'domains': []})

    def test_selected_batch_reads_only_its_domains_and_uses_persisted_history_when_capture_stops(self):
        monitor = monitoring.DomainMonitor(DEVICES)
        now = time.time()
        old_id = monitor.begin(now - 120)
        monitor.record({'epoch': now - 120, 'time': obs.utc(now - 120), 'device': 'portal',
                        'kind': 'dns_error', 'domains': ['old.example'], 'rcode': 3})
        new_id = monitor.begin(now - 1)
        monitor.record({'epoch': now - 1, 'time': obs.utc(now - 1), 'device': 'ps5',
                        'kind': 'dns_ok', 'domains': ['new.example']})
        obs.atomic_json(port.RUNTIME / 'domain-batches.json', monitor.snapshot())
        obs.atomic_json(port.PERSIST / 'domain-batches.json', monitor.snapshot())
        with patch.object(api, 'alive', return_value=True), patch.object(port, 'command', side_effect=AssertionError('command')):
            old = api.dispatch('domain_monitor', {'batch': old_id, 'incident': ''})
            latest = api.dispatch('domain_monitor', {'batch': '', 'incident': ''})
        self.assertEqual([row['domain'] for row in old['domains']], ['old.example'])
        self.assertEqual(latest['batch']['id'], new_id)
        self.assertEqual(old['batches'][1]['failed_count'], 1)
        obs.save_preferences(port.PERSIST / 'observability.json', 'compact', False, '')
        self.assertEqual(api.domain_monitor(new_id)['batch']['state'], 'archived')

    def test_manual_batch_queues_independently_and_returns_a_pending_selection(self):
        tracker = DomainTracker(DEVICES, lambda _line: None, obs.LogPreferences(), epoch=time.time() - 1)
        with patch.object(api, 'alive', return_value=True), patch.object(api, 'control_lock', side_effect=AssertionError('job lock')):
            started = api.dispatch('domain_batch_start', {})
            selected = api.dispatch('domain_monitor', {'batch': started['id'], 'incident': ''})
        request = obs.read_bounded(port.RUNTIME / 'domain-batch-request.json')
        self.assertEqual(request['id'], started['id'])
        self.assertEqual(request['device_macs'], monitoring.device_macs(DEVICES))
        self.assertEqual(selected['batch']['state'], 'pending')
        self.assertEqual(selected['domains'], [])
        self.assertTrue(tracker.start_batch(request))
        self.assertFalse(tracker.start_batch(request))
        self.assertEqual(tracker.monitor.current_id, started['id'])
        with patch.object(api, 'alive', return_value=False), self.assertRaises(RuntimeError):
            api.start_domain_batch()
        for value in ('../config', None, 12, 'a' * 33):
            with self.assertRaises(ValueError):
                api.validate('domain_monitor', {'batch': value, 'incident': ''})
        self.assertEqual(api.validate('domain_monitor', {'batch': 'inventory', 'incident': ''})['batch'], 'inventory')


if __name__ == '__main__':
    unittest.main()
