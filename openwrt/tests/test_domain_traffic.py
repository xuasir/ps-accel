import copy
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from domain_monitor import DomainMonitor
import domain_monitor
from observability import utc
import proxy_telemetry
import passwall_rules
from types import SimpleNamespace
from test_domains import DEVICES
from test_proxy_alignment import CORE, SOURCES, MANIFEST, connection


def sample(epoch, up, down, *, ident='one', host='traffic.example', started=102, route='selected', generation='core-one'):
    return {'epoch': epoch, 'generation': generation, 'state': 'observing', 'sampled_cores': 1,
            'policy_scope': {'domains': 'traffic.example', 'exclusions': ''}, 'health': {},
            'connections': [{'id': ident, 'core': 'core', 'device': 'portal', 'domain': host, 'address': '1.1.1.1',
                'source_ip': DEVICES['portal']['ip'], 'started_epoch': started, 'last_epoch': epoch,
                'bytes_up': up, 'bytes_down': down, 'route': route, 'active': True}]}


class DomainTrafficTests(unittest.TestCase):
    def setUp(self):
        self.monitor = DomainMonitor(DEVICES, epoch=100)
        self.monitor.begin(100)

    def row(self):
        return self.monitor.snapshot()['batches'][0]['domains'][0]

    def test_cumulative_core_counters_are_added_once_as_batch_increments(self):
        first = sample(104, 100, 1000)
        self.monitor.observe_connections(first, 104)
        self.monitor.observe_connections(sample(108, 300, 3000), 108)
        self.monitor.observe_connections(sample(108, 300, 3000), 109)
        traffic = self.row()['traffic']
        self.assertEqual((traffic['upload_bytes'], traffic['download_bytes']), (300, 3000))
        self.assertEqual((traffic['proxy_upload_bytes'], traffic['proxy_download_bytes']), (300, 3000))
        self.assertEqual(traffic['connections'], 1)
        self.assertEqual(traffic['proxy_rate'], 550)
        self.assertEqual(self.monitor.snapshot()['batches'][0]['traffic']['download_bytes'], 3000)

    def test_existing_connections_start_from_a_new_baseline_at_the_batch_boundary(self):
        self.monitor.observe_connections(sample(104, 100, 1000), 104)
        old_id = self.monitor.current_id
        self.monitor.begin(106, source='manual')
        self.monitor.observe_connections(sample(108, 300, 3000), 108)
        self.monitor.observe_connections(sample(112, 370, 3700), 112)
        batches = self.monitor.snapshot()['batches']
        self.assertEqual(batches[1]['id'], old_id)
        self.assertEqual(batches[1]['traffic']['download_bytes'], 1000)
        self.assertEqual(batches[1]['traffic']['proxy_rate'], 0)
        self.assertEqual(batches[1]['traffic']['proxy_active_connections'], 0)
        self.assertEqual(batches[0]['traffic']['download_bytes'], 700)
        self.assertTrue(batches[0]['traffic']['coverage_limited'])

    def test_invalid_samples_and_counter_resets_preserve_the_previous_totals(self):
        self.monitor.observe_connections(sample(104, 100, 1000), 104)
        self.monitor.observe_connections(sample(106, float('nan'), 1001), 106)
        self.monitor.observe_connections(sample(108, 105, 1005), 108)
        self.monitor.observe_connections(sample(110, 0, 0), 110)
        self.monitor.observe_connections(sample(112, 7, 8), 112)
        traffic = self.row()['traffic']
        self.assertEqual((traffic['upload_bytes'], traffic['download_bytes']), (112, 1013))
        self.assertTrue(traffic['coverage_limited'])

    def test_observer_restart_uses_existing_connection_counters_as_a_baseline(self):
        self.monitor.observe_connections(sample(104, 100, 1000), 104)
        saved = self.monitor.snapshot()
        restarted = DomainMonitor(DEVICES, saved, epoch=200)
        restarted.begin(200)
        restarted.observe_connections(sample(202, 100000, 1000000), 202)
        restarted.observe_connections(sample(204, 100010, 1000020, generation='core-two'), 204)
        traffic = restarted.snapshot()['batches'][0]['traffic']
        self.assertEqual((traffic['upload_bytes'], traffic['download_bytes']), (10, 20))
        self.assertEqual(restarted.snapshot()['batches'][1]['traffic']['download_bytes'], 1000)

    def test_actual_proxy_and_direct_increments_preserve_the_proxy_history(self):
        self.monitor.observe_connections(sample(104, 100, 1000), 104)
        self.monitor.observe_connections(sample(108, 200, 2000, route='direct'), 108)
        traffic = self.row()['traffic']
        self.assertEqual((traffic['direct_upload_bytes'], traffic['direct_download_bytes']), (100, 1000))
        self.assertEqual(traffic['proxy_download_bytes'], 1000)
        self.assertTrue(traffic['has_proxy'])
        self.assertEqual(traffic['proxy_active_connections'], 0)
        self.assertEqual(traffic['last_route'], 'direct')
        self.monitor.observe_connections(sample(110, 50, 500, ident='two', started=109, route='other_proxy'), 110)
        self.assertEqual(self.row()['traffic']['proxy_download_bytes'], 1500)

    def test_closed_cached_connections_stop_the_rate_and_keep_the_accumulated_bytes(self):
        first = sample(104, 100, 1000)
        self.monitor.observe_connections(first, 104)
        closed = copy.deepcopy(first)
        closed['epoch'] = 108
        closed['connections'][0]['active'] = False
        self.monitor.observe_connections(closed, 108)
        traffic = self.row()['traffic']
        self.assertEqual(traffic['download_bytes'], 1000)
        self.assertEqual((traffic['proxy_rate'], traffic['active_connections']), (0, 0))
        self.monitor.observe_connections(sample(110, 200, 2000), 130)
        self.assertEqual(self.row()['traffic']['download_bytes'], 1000)
        self.assertEqual(self.monitor.traffic_state, 'waiting')

    def test_idle_existing_connections_create_a_batch_when_payload_activity_resumes(self):
        self.monitor.observe_connections(sample(104, 100, 1000), 104)
        self.monitor.tick(165)
        self.monitor.observe_connections(sample(166, 100, 1000), 166)
        self.assertIsNone(self.monitor.current_id)
        self.monitor.observe_connections(sample(168, 140, 1400), 168)
        batches = self.monitor.snapshot()['batches']
        self.assertEqual(len(batches), 2)
        self.assertEqual(batches[0]['traffic']['download_bytes'], 400)
        self.assertEqual(batches[1]['traffic']['download_bytes'], 1000)

    def test_ambiguous_domain_attribution_keeps_proxy_bytes_in_the_batch_total(self):
        self.monitor.record({'epoch': 100, 'time': utc(100), 'device': 'portal', 'kind': 'dns_ok', 'domains': ['one.example', 'two.example']})
        self.monitor.observe_connections(sample(104, 100, 128 * 1024**2, host=''), 104,
                                         resolve=lambda *_args: ['one.example', 'two.example'])
        batch = self.monitor.snapshot()['batches'][0]
        self.assertEqual(batch['unattributed_traffic']['proxy_download_bytes'], 128 * 1024**2)
        self.assertEqual(batch['traffic']['proxy_download_bytes'], 128 * 1024**2)
        self.assertTrue(all(row['traffic']['download_bytes'] == 0 for row in batch['domains']))
        self.assertEqual(batch['traffic']['proxy_active_connections'], 1)

    def test_persisted_batch_stats_and_snapshot_copies_keep_the_record_stable(self):
        self.monitor.observe_connections(sample(104, 100, 1000), 104)
        snapshot = self.monitor.snapshot()
        frozen = json.dumps(snapshot)
        self.monitor.observe_connections(sample(108, 200, 2000), 108)
        self.assertEqual(json.dumps(snapshot), frozen)
        restored = DomainMonitor(DEVICES, snapshot)
        saved = restored.snapshot()['batches'][0]
        self.assertEqual(saved['state'], 'archived')
        self.assertEqual(saved['traffic']['proxy_download_bytes'], 1000)
        self.assertEqual(saved['traffic']['proxy_rate'], 0)

    def test_pruning_domain_details_preserves_batch_totals_and_large_proxy_domains(self):
        report = sample(104, 100, 1000)
        report['connections'] += sample(104, 50, 500, ident='direct', host='direct.example', route='direct')['connections']
        self.monitor.observe_connections(report, 104)
        size = len(json.dumps(self.monitor.snapshot(), ensure_ascii=False, separators=(',', ':')).encode())
        with patch.object(domain_monitor, 'MAX_HISTORY_BYTES', size - 1):
            batch = self.monitor.snapshot()['batches'][0]
        self.assertEqual([row['domain'] for row in batch['domains']], ['traffic.example'])
        self.assertEqual(batch['traffic']['download_bytes'], 1500)
        self.assertEqual(batch['unattributed_traffic']['direct_download_bytes'], 500)
        self.monitor.observe_connections(sample(108, 110, 1100), 108)
        self.assertEqual(self.monitor.snapshot()['batches'][0]['traffic']['download_bytes'], 1600)

    def test_a_returning_evicted_connection_uses_a_baseline_without_recounting_its_history(self):
        with patch.object(domain_monitor, 'MAX_TRAFFIC_CONNECTIONS', 1):
            self.monitor.observe_connections(sample(104, 100, 1000), 104)
            self.monitor.observe_connections(sample(108, 50, 500, ident='two', started=107), 108)
            self.monitor.observe_connections(sample(110, 110, 1100), 110)
            self.monitor.observe_connections(sample(112, 120, 1200), 112)
        self.assertEqual(self.row()['traffic']['download_bytes'], 1600)
        self.assertTrue(self.row()['traffic']['coverage_limited'])


class CoreTrafficEvidenceTests(unittest.TestCase):
    def test_capture_pause_publishes_a_disabled_native_sampling_state(self):
        signals, snapshots = {}, []
        def save(_path, value):
            snapshots.append(value)
            if value.get('state') == 'disabled':
                signals[passwall_rules.signal.SIGTERM]()
        with (patch.object(passwall_rules, 'device_sources', return_value=SOURCES),
              patch.object(passwall_rules, 'live_cores', return_value=[{'type': 'sing-box', 'config': CORE}]),
              patch.object(passwall_rules, 'configuration', return_value=({}, None, {}, MANIFEST['config'], 'revision')),
              patch.object(passwall_rules, 'load_preferences', side_effect=[SimpleNamespace(domains=True), SimpleNamespace(domains=False)]),
              patch.object(passwall_rules, 'ConnectionTracker') as tracker,
              patch.object(passwall_rules.port, 'atomic', side_effect=save),
              patch.object(passwall_rules.time, 'sleep'),
              patch.object(passwall_rules.signal, 'signal', side_effect=lambda sig, callback: signals.update({sig: callback}))):
            tracker.return_value.generation = 'core-test'
            tracker.return_value.sample.return_value = sample(104, 100, 1000)
            passwall_rules.watch()
        self.assertEqual([value['state'] for value in snapshots], ['observing', 'disabled'])
        self.assertEqual(snapshots[-1]['sampled_cores'], 0)

    def test_core_start_time_and_udp_proxy_chain_are_preserved(self):
        core = copy.deepcopy(CORE)
        core['outbounds'].append({'type': 'vless', 'tag': 'node-other'})
        raw = connection(chain=['node-other'])
        raw['start'] = utc(99)
        raw['metadata']['network'] = 'udp'
        with patch.object(proxy_telemetry, 'api_connections', return_value=[raw]):
            report = proxy_telemetry.ConnectionTracker().sample([{'config': core}], SOURCES, MANIFEST, epoch=100)
        row = report['connections'][0]
        self.assertEqual(row['started_epoch'], 99)
        self.assertEqual(row['network'], 'udp')
        self.assertEqual(row['route'], 'other_proxy')
        self.assertTrue(row['via_proxy'])
        self.assertFalse(row['expected_proxy'])

    def test_malformed_core_counters_preserve_the_last_valid_connection_sample(self):
        tracker = proxy_telemetry.ConnectionTracker()
        raw = connection()
        with patch.object(proxy_telemetry, 'api_connections', return_value=[raw]):
            first = tracker.sample([{'config': CORE}], SOURCES, MANIFEST, epoch=100)
        raw['upload'] = None
        with patch.object(proxy_telemetry, 'api_connections', return_value=[raw]):
            second = tracker.sample([{'config': CORE}], SOURCES, MANIFEST, epoch=102)
        self.assertEqual(second['connections'][0]['bytes_up'], first['connections'][0]['bytes_up'])
        self.assertEqual(second['connections'][0]['last_epoch'], 100)
        self.assertEqual(second['health']['malformed'], 1)


if __name__ == '__main__':
    unittest.main()
