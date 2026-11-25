import json
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from stream_quality import StreamQuality, public_quality

FLOW = (50000, 9296)


def feedback(received=97, lost=3, nonce=1):
    return struct.pack('!BHHH4sI', 5, 0, received, lost, b'auth', nonce)


def control(message, sequence=1, flags=1, tag=b'tagg'):
    body = sequence.to_bytes(4, 'big') + b'\0' * 5 + message
    return b'\0' + tag + b'\0' * 8 + bytes((0, flags)) + (len(body) + 4).to_bytes(2, 'big') + body


def big(sequence=1):
    # A valid first-fragment prefix declaring a larger nested BIG payload.
    return control(b'\x08\0\x12\x64\x08\x14', sequence, flags=0)


def enhanced_quality():
    quality = StreamQuality()
    quality.observe(big(), FLOW, 0, changed=True)
    return quality


def feed_seconds(quality, losses, start=0):
    for second, lost in enumerate(losses, start):
        for index in range(5):
            quality.observe(feedback(100 - lost, lost, second * 5 + index), FLOW, second + .1 + index * .2)


class StreamQualityTests(unittest.TestCase):
    def test_weighted_feedback_and_duplicate_reports(self):
        quality = StreamQuality()
        first = feedback(999, 1, 1)
        quality.observe(first, FLOW, .1)
        quality.observe(feedback(1, 1, 2), FLOW, .2)
        quality.observe(first, FLOW, .3)
        value = quality.snapshot(.4, '65')
        self.assertEqual((value['received'], value['lost'], value['feedback_samples']), (1000, 2, 2))
        self.assertAlmostEqual(value['loss_percent'], 2 / 1002 * 100, places=3)
        self.assertEqual(value['advice']['kind'], 'wait')

    def test_zero_samples_and_unknown_layouts_have_distinct_states(self):
        quality = StreamQuality()
        quality.observe(feedback(0, 0), FLOW, 0)
        value = quality.snapshot(.1, '65')
        self.assertEqual(value['state'], 'collecting')
        self.assertIsNone(value['loss_percent'])
        self.assertEqual(value['feedback_samples'], 0)
        self.assertEqual(value['advice']['kind'], 'wait')
        for index, packet in enumerate((b'\x05', feedback() + b'x', b'\x15' + feedback()[1:])):
            quality.observe(packet, FLOW, 1 + index * .1)
        value = quality.snapshot(1.5, '65')
        self.assertEqual(value['state'], 'unsupported')
        self.assertEqual(value['unknown_feedback'], 3)
        self.assertIsNone(value['advice']['profile'])

    def test_only_sustained_loss_recommends_one_lower_profile(self):
        quality = enhanced_quality()
        feed_seconds(quality, [3] * 6)
        self.assertEqual(quality.snapshot(5.95, '65')['advice']['kind'], 'wait')
        for current, target in (('200', '100'), ('100', '65'), ('65', '45'), ('45', '35')):
            with self.subTest(current=current):
                value = quality.snapshot(6.1, current)
                self.assertEqual(value['state'], 'degraded')
                self.assertEqual(value['advice']['profile'], target)
                self.assertEqual(value['advice']['sustained_seconds'], 6)
                self.assertEqual(value['advice']['loss_percent'], 3)
        self.assertEqual(quality.snapshot(6.1, '35')['advice']['kind'], 'minimum')
        baseline = quality.snapshot(6.1, '65', active=False)
        self.assertEqual(baseline['advice']['kind'], 'baseline')
        self.assertIsNone(baseline['advice']['profile'])
        spike = enhanced_quality()
        feed_seconds(spike, [20, 0, 0, 0, 0, 0])
        self.assertIsNone(spike.snapshot(6.1, '65')['advice']['profile'])
        quiet = enhanced_quality()
        feed_seconds(quiet, [0] * 6)
        self.assertEqual(quiet.snapshot(6.1, '65')['advice']['kind'], 'keep')

    def test_moderate_loss_requires_frame_reports_in_two_seconds(self):
        quality = enhanced_quality()
        feed_seconds(quality, [1] * 6)
        self.assertEqual(quality.snapshot(6.1, '65')['advice']['kind'], 'wait')
        quality = enhanced_quality()
        bad = control(b'\x08\x05\x32\x04\x08\x01\x10\x02', 10)
        for second in range(6):
            feed_seconds(quality, [1], start=second)
            if second == 3:
                quality.observe(bad, FLOW, 3.95)
                quality.observe(bad, FLOW, 3.96)
            if second == 4:
                quality.observe(control(b'\x08\x19', 11), FLOW, 4.95)
        value = quality.snapshot(6.1, '65')
        self.assertEqual((value['corrupt_reports'], value['idr_requests']), (1, 1))
        self.assertEqual(value['advice']['reason'], 'loss_and_frames')
        self.assertEqual(value['advice']['profile'], '45')
        # A truncated protobuf or a continuation never becomes a frame report.
        quality.observe(control(b'\x08\x05\x32\x08\x08\x01', 12), FLOW, 6.2)
        quality.observe(control(b'\x08\x19', 13, flags=2), FLOW, 6.3)
        self.assertEqual(quality.snapshot(6.4, '65')['idr_requests'], 1)

    def test_new_handshake_and_disconnect_reset_session_evidence(self):
        quality = StreamQuality()
        quality.observe(big(), FLOW, 0, changed=True)
        feed_seconds(quality, [3] * 6)
        quality.observe(big(), FLOW, 6)
        self.assertEqual(quality.snapshot(6.1, '65')['advice']['kind'], 'lower')
        quality.observe(big(2), FLOW, 6.2)
        quality.observe(feedback(nonce=100), (50001, 9296), 6.3)
        value = quality.snapshot(6.4, '65')
        self.assertEqual(value['client_version'], 20)
        self.assertEqual(value['feedback_samples'], 0)
        self.assertEqual(value['advice']['kind'], 'wait')
        quality.observe(control(b'\x08\x08\x52\x02\x0a\x00', 3), FLOW, 6.5)
        quality.observe(feedback(nonce=101), FLOW, 6.6)
        self.assertEqual(quality.snapshot(6.7, '65')['state'], 'disconnected')
        quality.observe(big(4), FLOW, 6.8)
        quality.observe(feedback(nonce=102), FLOW, 6.9)
        self.assertEqual(quality.snapshot(7, '65')['feedback_samples'], 1)

    def test_feedback_gap_and_rpc_report_age_withdraw_advice(self):
        quality = enhanced_quality()
        feed_seconds(quality, [3] * 6)
        value = quality.snapshot(6.1, '65')
        self.assertEqual(public_quality(value, .1, True, True)['advice']['kind'], 'lower')
        for age in (4.8, 7):
            exported = public_quality(value, age, True, True)
            self.assertEqual(exported['state'], 'stale')
            self.assertIsNone(exported['advice']['profile'])
        self.assertEqual(quality.snapshot(11, '65')['state'], 'stale')
        quality.observe(feedback(nonce=999), FLOW, 11.1)
        self.assertEqual(quality.snapshot(11.2, '65')['feedback_samples'], 1)
        self.assertEqual(quality.snapshot(11.2, '65')['advice']['kind'], 'wait')

    def test_relay_drops_and_repeated_stalls_take_priority(self):
        quality = enhanced_quality()
        feed_seconds(quality, [3] * 6)
        quality.receive_statistics((50, 2), 6)
        quality.receive_statistics((20, 1), 6.1)
        value = quality.snapshot(6.2, '65')
        self.assertEqual(value['advice']['kind'], 'check_relay')
        self.assertIsNone(value['advice']['profile'])
        self.assertEqual(value['relay']['dropped_total'], 3)
        quality.receive_statistics((5, 0), 20)
        self.assertEqual(quality.snapshot(20.1, '65')['relay']['dropped'], 0)
        self.assertEqual(quality.snapshot(20.1, '65')['relay']['dropped_total'], 3)
        stalls = StreamQuality()
        for i in range(100):
            stalls.forwarded(i / 100, 6 if i < 5 else .2)
        self.assertEqual(stalls.snapshot(1.1, '65')['state'], 'waiting')
        stalls.forwarded(1.2, 6)
        value = stalls.snapshot(1.3, '65')
        self.assertEqual(value['advice']['reason'], 'processing_stalls')
        self.assertEqual(value['relay']['processing_p95_ms'], 10)

    def test_existing_or_unmodified_stream_waits_for_an_enhanced_startup(self):
        quality = StreamQuality()
        feed_seconds(quality, [3] * 6)
        value = quality.snapshot(6.1, '65')
        self.assertEqual(value['advice']['reason'], 'waiting_startup')
        self.assertIsNone(value['advice']['profile'])
        quality.observe(big(2), FLOW, 6.2)
        feed_seconds(quality, [3] * 6, start=7)
        self.assertEqual(quality.snapshot(13.1, '65')['advice']['reason'], 'waiting_startup')
        quality.observe(big(2), FLOW, 13.2, changed=True)
        value = quality.snapshot(13.3, '65')
        self.assertTrue(value['request_observed'])
        self.assertEqual(value['advice']['profile'], '45')
        value['request_observed'] = False
        self.assertIsNone(public_quality(value, .1, True, True)['advice']['profile'])
        quality.observe(big(3), FLOW, 13.4)
        self.assertFalse(quality.snapshot(13.5, '65')['request_observed'])

    def test_bounded_memory_and_aggregate_export(self):
        quality = StreamQuality()
        for i in range(20000):
            quality.observe(feedback(nonce=i), FLOW, i / 1000)
        self.assertLessEqual(len(quality.buckets), 13)
        self.assertLessEqual(len(quality.seen), 256)
        value = quality.snapshot(20, '65')
        value.update(payload='private-payload', session_key='private-key', flow=FLOW)
        value['relay']['packet'] = 'private-packet'
        exported = public_quality(value, .1, True, True)
        self.assertNotIn('private-', json.dumps(exported))
        malformed = public_quality({'requested_profile': [], 'loss_percent': 10 ** 400,
                                    'relay': {'dropped': []}}, .1, True, True)
        self.assertIsNone(malformed['loss_percent'])
        self.assertIsNone(malformed['requested_profile'])


if __name__ == '__main__':
    unittest.main()
