from dataclasses import replace
import ctypes
import json
from pathlib import Path
import struct
import sys
import unittest

from scapy.all import DNS, DNSQR, DNSRR, Dot1Q, Ether, ICMP, IP, IPv6, Raw, TCP, UDP

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import domain_tracker as tracking
from observability import LogPreferences, correlate, merge_events, new_incident
from portal_observe import capture_filter

DEVICES = {'ps5': {'ip': '10.0.0.100', 'mac': '02:00:00:00:00:02'},
           'portal': {'ip': '10.0.0.101', 'mac': '02:00:00:00:00:03'}}
ROUTER = '02:00:00:00:00:01'
EPOCH = 1800000000


def dns_frame(message, response=False, device='portal', sport=41000, server='10.0.0.1', tcp=False, seq=1):
    peer = DEVICES[device]
    network = IP(src=server if response else peer['ip'], dst=peer['ip'] if response else server)
    layer = TCP(sport=53 if response else sport, dport=sport if response else 53, flags='PA', seq=seq) if tcp else \
        UDP(sport=53 if response else sport, dport=sport if response else 53)
    data = bytes(message)
    if tcp:
        data = struct.pack('!H', len(data)) + data
    return bytes(Ether(src=ROUTER if response else peer['mac'], dst=peer['mac'] if response else ROUTER) /
                 network / layer / Raw(data))


def tcp_frame(flags='S', response=False, address='1.1.1.1', seq=100, ack=0, data=b'', ipv6=False, sport=42000):
    peer = DEVICES['portal']
    local = 'fd00::101' if ipv6 else peer['ip']
    network = (IPv6 if ipv6 else IP)(src=address if response else local, dst=local if response else address)
    return bytes(Ether(src=ROUTER if response else peer['mac'], dst=peer['mac'] if response else ROUTER) / network /
                 TCP(sport=443 if response else sport, dport=sport if response else 443,
                     flags=flags, seq=seq, ack=ack) / Raw(data))


def client_hello(name='api.sony.example'):
    encoded = name.encode('ascii')
    server_name = b'\0' + struct.pack('!H', len(encoded)) + encoded
    extension = struct.pack('!H', len(server_name)) + server_name
    extensions = struct.pack('!HH', 0, len(extension)) + extension
    hello = b'\x03\x03' + b'\0' * 32 + b'\0\0\2\x13\1\1\0' + struct.pack('!H', len(extensions)) + extensions
    handshake = b'\1' + len(hello).to_bytes(3, 'big') + hello
    return b'\x16\x03\1' + struct.pack('!H', len(handshake)) + handshake


class DomainEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.lines = []
        self.preferences = LogPreferences(tag='Portal 升级', tag_since=EPOCH)
        self.tracker = tracking.DomainTracker(DEVICES, self.lines.append, self.preferences, epoch=EPOCH)

    def events(self, kind=None):
        items = [json.loads(line) for line in self.lines]
        return [item for item in items if kind is None or item['kind'] == kind]

    def resolve(self, name='api.sony.example', address='1.1.1.1', ttl=60, ident=1, epoch=EPOCH):
        query = DNS(id=ident, qd=DNSQR(qname=name))
        response = DNS(id=ident, qr=1, qd=DNSQR(qname=name), an=DNSRR(rrname=name, rdata=address, ttl=ttl))
        self.tracker.feed(dns_frame(query), epoch)
        self.tracker.feed(dns_frame(response, True), epoch + .1)

    def test_dns_reply_binds_addresses_and_remembers_first_observation(self):
        self.resolve()
        self.assertEqual(self.tracker.mapped('portal', '1.1.1.1', EPOCH + 1), ['api.sony.example'])
        first = self.tracker.report(EPOCH + 1)['domains'][0]
        self.assertEqual(first['first_epoch'], EPOCH)
        self.assertTrue(first['new_since_tag'])
        self.assertEqual(first['counts']['dns_ok'], 1)
        self.assertEqual(first['addresses'][0]['ttl'], 60)

    def test_compressed_cname_chain_accepts_its_addresses_and_ignores_unrelated_records(self):
        query = DNS(id=4, qd=DNSQR(qname='api.sony.example'))
        question = bytes(DNSQR(qname='api.sony.example'))
        header = struct.pack('!6H', 4, 0x8100, 1, 2, 0, 1)
        alias_offset = len(header) + len(question) + 12
        # RFC 1035 wire pointers, including a target offset ending in byte 0x2e.
        response = (header + question + b'\xc0\x0c' + struct.pack('!HHIH', 5, 1, 20, 7) +
                    b'\x04edge\xc0\x10' + (0xc000 | alias_offset).to_bytes(2, 'big') +
                    struct.pack('!HHIH', 1, 1, 120, 4) + b'\x01\x01\x01\x01' +
                    b'\x09unrelated\xc0\x15' + struct.pack('!HHIH', 1, 1, 60, 4) + b'\x08\x08\x08\x08')
        self.tracker.feed(dns_frame(query), EPOCH)
        self.tracker.feed(dns_frame(response, True), EPOCH + 1)
        self.assertEqual(set(self.tracker.mapped('portal', '1.1.1.1', EPOCH + 2)),
                         {'api.sony.example', 'edge.sony.example'})
        self.assertFalse(self.tracker.mapped('portal', '8.8.8.8', EPOCH + 2))
        self.assertFalse(self.tracker.mapped('portal', '1.1.1.1', EPOCH + 22))

    def test_dns_error_codes_are_preserved_for_diagnosis(self):
        for rcode in (2, 3, 5):
            name = 'new' + str(rcode) + '.sony.example'
            self.tracker.feed(dns_frame(DNS(id=rcode, qd=DNSQR(qname=name))), EPOCH)
            self.tracker.feed(dns_frame(DNS(id=rcode, qr=1, rcode=rcode, qd=DNSQR(qname=name)), True), EPOCH + 1)
        self.assertEqual([item['rcode'] for item in self.events('dns_error')], [2, 3, 5])
        self.assertTrue(all(item['problem'] for item in self.events('dns_error')))

    def test_dns_empty_aaaa_answer_is_separate_from_resolution_failure(self):
        query = DNS(id=1, qd=DNSQR(qname='api.sony.example', qtype='AAAA'))
        response = DNS(id=1, qr=1, qd=DNSQR(qname='api.sony.example', qtype='AAAA'))
        self.tracker.feed(dns_frame(query), EPOCH)
        self.tracker.feed(dns_frame(response, True), EPOCH + 1)
        self.assertFalse(self.events('dns_error'))
        self.assertFalse(self.events('dns_empty')[0]['problem'])

    def test_responses_require_matching_server_port_question_and_query_type(self):
        self.tracker.feed(dns_frame(DNS(id=9, qd=DNSQR(qname='api.sony.example'))), EPOCH)
        responses = [dns_frame(DNS(id=9, qr=1, qd=DNSQR(qname='other.example')), True),
                     dns_frame(DNS(id=9, qr=1, qd=DNSQR(qname='api.sony.example', qtype='AAAA')), True),
                     dns_frame(DNS(id=9, qr=1, qd=DNSQR(qname='api.sony.example')), True, sport=41001),
                     dns_frame(DNS(id=9, qr=1, qd=DNSQR(qname='api.sony.example')), True, server='10.0.0.2')]
        for frame in responses:
            self.tracker.feed(frame, EPOCH + 1)
        self.assertEqual(len(self.tracker.pending_dns), 1)
        self.assertFalse(self.events('dns_ok'))
        self.assertFalse(self.events('dns_empty'))

    def test_duplicate_queries_count_retries_and_generate_one_observation_timeout(self):
        frame = dns_frame(DNS(id=8, qd=DNSQR(qname='blocked.sony.example')))
        for delay in (0, 1, 2, 3):
            self.tracker.feed(frame, EPOCH + delay)
        self.tracker.tick(EPOCH + 9)
        self.tracker.tick(EPOCH + 20)
        errors = self.events('dns_timeout')
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]['retries'], 3)
        self.assertTrue(errors[0]['observation_only'])

    def test_truncated_dns_reply_does_not_create_false_address_bindings(self):
        self.tracker.feed(dns_frame(DNS(id=2, qd=DNSQR(qname='large.sony.example'))), EPOCH)
        self.tracker.feed(dns_frame(DNS(id=2, qr=1, tc=1, qd=DNSQR(qname='large.sony.example')), True), EPOCH + 1)
        self.tracker.tick(EPOCH + 10)
        self.assertEqual(len(self.events('dns_truncated')), 1)
        self.assertFalse(self.events('dns_timeout'))
        self.assertFalse(self.events('dns_error'))

    def test_dns_name_pointer_cycles_and_truncation_are_bounded(self):
        message = struct.pack('!6H', 1, 0x100, 1, 0, 0, 0) + b'\xc0\x0c\0\1\0\1'
        with self.assertRaises(ValueError):
            tracking.parse_dns(message)
        for length in range(len(message)):
            self.tracker.feed(dns_frame(message[:length]), EPOCH)
        self.assertGreater(self.tracker.health['malformed'], 0)
        self.assertFalse(self.tracker.domains)

    def test_unpaired_mac_or_changed_ipv4_is_excluded(self):
        frame = Ether(dns_frame(DNS(id=1, qd=DNSQR(qname='private.example'))))
        frame.src = '02:00:00:00:00:99'
        self.tracker.feed(bytes(frame), EPOCH)
        frame.src = DEVICES['portal']['mac']
        frame[IP].src = '10.0.0.99'
        self.tracker.feed(bytes(frame), EPOCH)
        self.assertFalse(self.tracker.domains)

    def test_ipv6_dns_and_tcp_use_the_enrolled_mac(self):
        query = DNS(id=5, qd=DNSQR(qname='v6.sony.example', qtype='AAAA'))
        response = DNS(id=5, qr=1, qd=DNSQR(qname='v6.sony.example', qtype='AAAA'),
                       an=DNSRR(rrname='v6.sony.example', type='AAAA', rdata='2606:4700:4700::1111', ttl=60))
        for reply, message in ((False, query), (True, response)):
            frame = Ether(src=ROUTER if reply else DEVICES['portal']['mac'], dst=DEVICES['portal']['mac'] if reply else ROUTER) / \
                IPv6(src='fd00::1' if reply else 'fd00::101', dst='fd00::101' if reply else 'fd00::1') / \
                UDP(sport=53 if reply else 40000, dport=40000 if reply else 53) / message
            self.tracker.feed(bytes(frame), EPOCH + reply)
        self.tracker.feed(tcp_frame(address='2606:4700:4700::1111', ipv6=True), EPOCH + 2)
        self.tracker.feed(tcp_frame('SA', True, address='2606:4700:4700::1111', ipv6=True, ack=101), EPOCH + 3)
        self.assertEqual(self.events('tcp_ok')[0]['domains'], ['v6.sony.example'])

    def test_tcp_success_requires_matching_initial_sequence_and_acknowledgement(self):
        self.resolve()
        self.tracker.feed(tcp_frame(), EPOCH + 1)
        self.tracker.feed(tcp_frame('SA', True, ack=999), EPOCH + 2)
        self.assertFalse(self.events('tcp_ok'))
        self.tracker.feed(tcp_frame('SA', True, ack=101), EPOCH + 3)
        self.assertEqual(self.events('tcp_ok')[0]['domains'], ['api.sony.example'])
        self.tracker.tick(EPOCH + 20)
        self.assertFalse(self.events('tcp_timeout'))

    def test_tcp_failure_keeps_domain_at_attempt_time_after_dns_ttl_expires(self):
        self.resolve(ttl=2)
        self.tracker.feed(tcp_frame(), EPOCH + 1)
        self.tracker.feed(tcp_frame(), EPOCH + 2)
        self.tracker.tick(EPOCH + 12)
        self.assertEqual(self.events('tcp_timeout')[0]['domains'], ['api.sony.example'])
        self.assertEqual(self.events('tcp_timeout')[0]['retries'], 1)
        self.assertFalse(self.tracker.mapped('portal', '1.1.1.1', EPOCH + 12))

    def test_rst_is_a_connection_failure_for_the_matching_pending_attempt(self):
        self.resolve()
        self.tracker.feed(tcp_frame(), EPOCH + 1)
        self.tracker.feed(tcp_frame('RA', True, ack=101), EPOCH + 2)
        self.assertEqual(self.events('tcp_reset')[0]['domains'], ['api.sony.example'])
        self.tracker.feed(tcp_frame('RA', True, ack=101), EPOCH + 3)
        self.assertEqual(len(self.events('tcp_reset')), 1)

    def test_shared_address_reports_candidate_domains_instead_of_guessing_one(self):
        self.resolve('first.sony.example')
        self.resolve('second.sony.example', ident=2, epoch=EPOCH + 1)
        self.tracker.feed(tcp_frame(), EPOCH + 2)
        self.tracker.feed(tcp_frame('RA', True, ack=101), EPOCH + 3)
        self.assertEqual(set(self.events('tcp_reset')[0]['domains']), {'first.sony.example', 'second.sony.example'})

    def test_dns_success_preserves_a_tcp_failure_until_a_new_handshake_succeeds(self):
        self.resolve()
        self.tracker.feed(tcp_frame(), EPOCH + 1)
        self.tracker.feed(tcp_frame('RA', True, ack=101), EPOCH + 2)
        self.resolve(ident=2, epoch=EPOCH + 3)
        row = self.tracker.domains[('portal', 'api.sony.example')]
        self.assertEqual(row['last_problem'], 'tcp_reset')
        self.tracker.feed(tcp_frame(seq=200), EPOCH + 4)
        self.tracker.feed(tcp_frame('SA', True, ack=201), EPOCH + 5)
        self.assertEqual(row['last_problem'], '')

    def test_icmp_unreachable_is_matched_to_pending_connection(self):
        self.resolve()
        self.tracker.feed(tcp_frame(), EPOCH + 1)
        quoted = IP(src=DEVICES['portal']['ip'], dst='1.1.1.1') / TCP(sport=42000, dport=443, flags='S', seq=100)
        frame = Ether(src=ROUTER, dst=DEVICES['portal']['mac']) / IP(src='10.0.0.1', dst=DEVICES['portal']['ip']) / \
            ICMP(type=3, code=13) / Raw(bytes(quoted)[:28])
        self.tracker.feed(bytes(frame), EPOCH + 2)
        self.assertEqual(self.events('unreachable')[0]['domains'], ['api.sony.example'])
        self.assertEqual(self.events('unreachable')[0]['code'], 13)

    def test_visible_tls_sni_supplements_dns_without_saving_payload(self):
        self.tracker.feed(tcp_frame(), EPOCH)
        self.tracker.feed(tcp_frame('PA', data=client_hello()), EPOCH + 1)
        self.tracker.tick(EPOCH + 20)
        self.assertEqual(self.events('tls_sni')[0]['domains'], ['api.sony.example'])
        self.assertFalse(self.events('tcp_timeout'))
        self.assertNotIn('payload', json.dumps(self.tracker.report()))
        for size in range(0, len(client_hello())):
            self.assertIsNone(tracking.tls_name(client_hello()[:size]))

    def test_dns_over_tcp_reassembles_bounded_segments(self):
        query = bytes(DNS(id=6, qd=DNSQR(qname='tcp.sony.example')))
        data = struct.pack('!H', len(query)) + query
        for seq, chunk in ((100, data[:5]), (105, data[5:])):
            frame = Ether(src=DEVICES['portal']['mac'], dst=ROUTER) / IP(src=DEVICES['portal']['ip'], dst='10.0.0.1') / \
                TCP(sport=40000, dport=53, flags='PA', seq=seq) / Raw(chunk)
            self.tracker.feed(bytes(frame), EPOCH)
        self.assertEqual(self.events('dns_query')[0]['domains'], ['tcp.sony.example'])
        response = DNS(id=6, qr=1, qd=DNSQR(qname='tcp.sony.example'), an=DNSRR(rrname='tcp.sony.example', rdata='1.1.1.1'))
        self.tracker.feed(dns_frame(response, True, sport=40000, tcp=True), EPOCH + 1)
        self.assertEqual(self.events('dns_ok')[0]['domains'], ['tcp.sony.example'])

    def test_invalid_or_out_of_order_tcp_stream_releases_its_buffer(self):
        query = bytes(DNS(id=6, qd=DNSQR(qname='tcp.sony.example')))
        data = struct.pack('!H', len(query)) + query
        for seq, chunk in ((100, data[:5]), (999, data[5:])):
            frame = Ether(src=DEVICES['portal']['mac'], dst=ROUTER) / IP(src=DEVICES['portal']['ip'], dst='10.0.0.1') / \
                TCP(sport=40000, dport=53, flags='PA', seq=seq) / Raw(chunk)
            self.tracker.feed(bytes(frame), EPOCH)
        self.assertFalse(self.tracker.streams)
        self.assertFalse(self.events('dns_query'))

    def test_packet_parser_handles_vlan_and_rejects_fragmented_or_truncated_packets(self):
        frame = Ether(src=DEVICES['portal']['mac'], dst=ROUTER) / Dot1Q(vlan=1) / \
            IP(src=DEVICES['portal']['ip'], dst='10.0.0.1') / UDP(sport=40000, dport=53) / DNS(qd=DNSQR(qname='vlan.example'))
        self.tracker.feed(bytes(frame), EPOCH)
        self.assertIn(('portal', 'vlan.example'), self.tracker.domains)
        frame[IP].flags = 'MF'
        self.assertIsNone(tracking.parse_frame(bytes(frame)))
        frame[IP].flags = 0
        self.assertIsNone(tracking.parse_frame(bytes(frame)[:-1]))

    def test_compact_merges_repeated_successes_and_verbose_keeps_each_access(self):
        for index in range(10):
            self.resolve(ident=index + 1, epoch=EPOCH + index)
        self.assertEqual(len(self.events('dns_ok')), 1)
        self.assertEqual(self.tracker.domains[('portal', 'api.sony.example')]['counts']['dns_ok'], 10)
        self.tracker.tick(EPOCH + 70)
        self.assertEqual(self.events('dns_ok')[-1]['count'], 9)
        self.tracker.preferences = replace(self.preferences, mode='verbose')
        self.resolve(ident=20, epoch=EPOCH + 71)
        self.resolve(ident=21, epoch=EPOCH + 72)
        self.assertEqual(len(self.events('dns_ok')), 4)

    def test_compact_failure_summaries_and_memory_samples_count_each_error_once(self):
        for index in range(3):
            query = DNS(id=index + 1, qd=DNSQR(qname='blocked.sony.example'))
            reply = DNS(id=index + 1, qr=1, rcode=3, qd=DNSQR(qname='blocked.sony.example'))
            self.tracker.feed(dns_frame(query), EPOCH + index)
            self.tracker.feed(dns_frame(reply, True), EPOCH + index + .1)
        self.tracker.tick(EPOCH + 61)
        incident = new_incident('manual', 'Portal 连接失败', epoch=EPOCH + 62)
        evidence = correlate(incident, merge_events(self.events(), list(self.tracker.recent)))
        self.assertEqual(evidence['candidates'][0]['errors'], 3)
        self.assertEqual(len([event for event in evidence['events'] if event['kind'] == 'dns_error']), 3)

    def test_a_new_upgrade_tag_keeps_its_own_first_event_in_compact_mode(self):
        self.resolve()
        self.tracker.preferences = replace(self.preferences, tag='Portal 下一版', tag_since=EPOCH + 1)
        self.resolve(ident=2, epoch=EPOCH + 2)
        self.assertEqual([event['tag'] for event in self.events('dns_ok')], ['Portal 升级', 'Portal 下一版'])

    def test_closing_capture_flushes_repeats_without_reporting_uncaptured_timeouts(self):
        self.tracker.feed(dns_frame(DNS(id=1, qd=DNSQR(qname='pending.sony.example'))), EPOCH)
        self.tracker.feed(tcp_frame(), EPOCH)
        self.tracker.tick(EPOCH + 20, closing=True)
        self.assertFalse(self.events('dns_timeout'))
        self.assertFalse(self.events('tcp_timeout'))

    def test_snapshot_keeps_an_earlier_dns_error_ahead_of_routine_accesses(self):
        query = DNS(id=1, qd=DNSQR(qname='blocked.sony.example'))
        reply = DNS(id=1, qr=1, rcode=3, qd=DNSQR(qname='blocked.sony.example'))
        self.tracker.feed(dns_frame(query), EPOCH)
        self.tracker.feed(dns_frame(reply, True), EPOCH + .1)
        for index in range(50):
            self.resolve(ident=index + 2, epoch=EPOCH + index + 1)
        report = self.tracker.report(EPOCH + 52)
        self.assertEqual(len(report['recent']), 80)
        self.assertTrue(any(event['kind'] == 'dns_error' and event['rcode'] == 3 for event in report['recent']))

    def test_bounded_queries_streams_domains_and_history_under_many_new_names(self):
        for index in range(600):
            self.tracker.feed(dns_frame(DNS(id=index, qd=DNSQR(qname='new' + str(index) + '.example'))), EPOCH)
        self.assertLessEqual(len(self.tracker.pending_dns), 128)
        self.assertLessEqual(len(self.tracker.domains), 512)
        self.assertLessEqual(len(self.tracker.recent), 512)
        self.assertLessEqual(len(self.tracker.repeats), 128)
        self.assertGreater(self.tracker.health['capacity_drops'], 0)

    def test_inventory_preserves_first_seen_for_the_same_device_across_restart(self):
        self.resolve()
        inventory = json.loads(json.dumps(self.tracker.inventory()))
        restored = tracking.DomainTracker(DEVICES, self.lines.append, self.preferences, inventory, EPOCH + 100)
        self.assertEqual(restored.domains[('portal', 'api.sony.example')]['first_epoch'], EPOCH)
        self.assertFalse(restored.mapped('portal', '1.1.1.1', EPOCH + 101))
        changed = dict(DEVICES, portal=dict(DEVICES['portal'], mac='02:00:00:00:00:04'))
        replacement = tracking.DomainTracker(changed, self.lines.append, self.preferences, inventory)
        self.assertFalse(replacement.domains)


class KernelFilterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from scapy.arch.common import compile_filter
            from scapy.data import DLT_EN10MB
            from scapy.libs import winpcapy
            cls.program = compile_filter(capture_filter(DEVICES), linktype=DLT_EN10MB)
            cls.lib = winpcapy
            cls.accept = winpcapy._lib.pcap_offline_filter
            cls.accept.argtypes = [ctypes.POINTER(winpcapy.bpf_program), ctypes.POINTER(winpcapy.pcap_pkthdr), ctypes.c_void_p]
            cls.accept.restype = ctypes.c_uint
        except (ImportError, OSError) as exc:
            raise unittest.SkipTest('libpcap required: ' + str(exc))

    @classmethod
    def tearDownClass(cls):
        cls.lib.pcap_freecode(ctypes.byref(cls.program))

    def accepts(self, frame):
        header = self.lib.pcap_pkthdr()
        header.caplen = header.len = len(frame)
        return bool(self.accept(ctypes.byref(self.program), ctypes.byref(header), ctypes.create_string_buffer(frame)))

    def test_kernel_accepts_dns_syn_reset_and_first_tls_hello(self):
        for frame in (dns_frame(DNS(qd=DNSQR(qname='api.sony.example'))), tcp_frame(),
                      tcp_frame('SA', True, ack=101), tcp_frame('RA', True, ack=101),
                      tcp_frame('PA', data=client_hello()),
                      tcp_frame(address='2606:4700:4700::1111', ipv6=True),
                      tcp_frame('PA', data=client_hello(), address='2606:4700:4700::1111', ipv6=True)):
            self.assertTrue(self.accepts(frame))

    def test_kernel_excludes_video_encrypted_application_data_and_other_devices(self):
        video = bytes(Ether(src=DEVICES['portal']['mac'], dst=ROUTER) /
                      IP(src=DEVICES['portal']['ip'], dst=DEVICES['ps5']['ip']) / UDP(sport=40000, dport=9296) / Raw(b'video' * 100))
        encrypted = tcp_frame('PA', data=b'\x17\x03\x03\0\x05abcde')
        unpaired = Ether(tcp_frame())
        unpaired.src = '02:00:00:00:00:99'
        wrong_ip = Ether(tcp_frame())
        wrong_ip[IP].src = '10.0.0.99'
        for frame in (video, encrypted, bytes(unpaired), bytes(wrong_ip)):
            self.assertFalse(self.accepts(frame))


if __name__ == '__main__':
    unittest.main()
