"""Passive, bounded streaming feedback and read-only profile advice.

Wire offsets follow Chiaki-ng's Takion congestion/control formats. Client
reports can be clamped or cover several media types; they are feedback, not
an independent measurement of video throughput or end-to-end latency.
"""
from bisect import bisect_left
from collections import deque, OrderedDict
import math
import struct

from profiles import PROFILES
from protocol import fields, readvar

WINDOW_SECONDS = 12
FEEDBACK_TTL = 5
SUSTAINED_SECONDS = 6
HIGH_LOSS = .03
MODERATE_LOSS = .01
LATENCY_BOUNDS_MS = (.1, .25, .5, 1, 2, 5, 10, 20, 50, 100)


class Bucket:
    def __init__(self, second):
        self.second = second
        self.reset_client()
        self.rx_packets = self.rx_drops = self.processed = self.slow = 0
        self.latency = [0] * (len(LATENCY_BOUNDS_MS) + 1)
        self.max_ms = 0

    def reset_client(self):
        self.received = self.lost = self.reports = self.samples = 0
        self.corrupt = self.idr = self.unknown = 0


def control_event(data):
    """Read a BIG prefix, or one small, complete quality/control message."""
    if (len(data) < 28 or len(data) > 4096 or data[0] != 0 or data[13] != 0
            or data[14] not in (0, 1) or data[25] != 0
            or len(data) != int.from_bytes(data[15:17], 'big') + 13):
        return None
    identity = data[1:5] + data[17:21]
    try:
        # BIG can span several packets. Its first fragment contains the version;
        # the launch specification and all session keys stay opaque.
        if data[26:29] == b'\x08\x00\x12':
            size, pos = readvar(data, 29)
            start = pos
            tag, pos = readvar(data, pos)
            version, pos = readvar(data, pos)
            if tag == 8 and pos - start <= size <= 65535 and 1 <= version <= 255:
                return 'start', identity, version
            return None
        if data[14] != 1 or len(data) > 256 or data[26] != 8:
            return None
        kind, _ = readvar(data, 27)
        if kind not in (5, 8, 25):
            return None
        message = fields(data[26:])
        if message.get(1) != kind:
            return None
        if kind == 5:
            report = fields(message[6])
            if not all(type(report.get(k)) is int and 0 <= report[k] <= 0xffffffff for k in (1, 2)):
                return None
        elif kind == 8 and not isinstance(fields(message[10]).get(1), bytes):
            return None
        return {5: 'corrupt', 8: 'disconnect', 25: 'idr'}[kind], identity, None
    except (ValueError, TypeError, KeyError, IndexError):
        return None


class StreamQuality:
    def __init__(self):
        self.buckets = deque(maxlen=WINDOW_SECONDS + 1)
        self.seen = OrderedDict()
        self.startups = OrderedDict()
        self.flow = None
        self.client_version = None
        self.request_observed = False
        self.startup = None
        self.last_activity = self.first_feedback = self.last_feedback = self.last_unknown = None
        self.last_feedback_packets = 0
        self.closed = False
        self.rx_available = False
        self.rx_drops_total = 0

    def _bucket(self, now):
        second = int(now)
        while self.buckets and self.buckets[0].second <= second - WINDOW_SECONDS:
            self.buckets.popleft()
        if not self.buckets or self.buckets[-1].second != second:
            self.buckets.append(Bucket(second))
        return self.buckets[-1]

    def _new_session(self, flow, now, version=None, request_observed=False, startup=None):
        for bucket in self.buckets:
            bucket.reset_client()
        self.seen.clear()
        self.flow, self.client_version, self.last_activity = flow, version, now
        self.request_observed, self.startup = request_observed, startup
        self.first_feedback = self.last_feedback = self.last_unknown = None
        self.last_feedback_packets = 0
        self.closed = False

    def _duplicate(self, key, now):
        while self.seen and next(iter(self.seen.values())) <= now - WINDOW_SECONDS:
            self.seen.popitem(last=False)
        if key in self.seen:
            return True
        self.seen[key] = now
        if len(self.seen) > 256:
            self.seen.popitem(last=False)
        return False

    def observe_frame(self, frame, payload, now, changed=False):
        if payload is None:
            return
        ihl = (frame[14] & 15) * 4
        offset = 14 + ihl
        sport, dport, size = struct.unpack_from('!HHH', frame, offset)
        # Keep ambiguous UDP/IP tails outside the feedback parser.
        if size != len(payload) + 8 or size != int.from_bytes(frame[16:18], 'big') - ihl:
            return
        self.observe(payload, (sport, dport), now, changed)

    def observe(self, data, flow, now, changed=False):
        if not data:
            return
        event = control_event(data) if data[0] == 0 else None
        if event and event[0] == 'start':
            key = (flow, event[1])
            if key not in self.startups:
                self.startups[key] = True
                if len(self.startups) > 16:
                    self.startups.popitem(last=False)
                self._new_session(flow, now, event[2], changed, key)
            elif self.startup == key and changed:
                self.request_observed = True
            return
        is_feedback = data[0] & 15 == 5
        if self.flow is None or (flow != self.flow and self.last_activity is not None
                                 and now - self.last_activity > FEEDBACK_TTL and is_feedback):
            if not is_feedback:
                return
            self._new_session(flow, now)
        if flow != self.flow or self.closed:
            return
        self.last_activity = now
        if is_feedback:
            if len(data) != 15 or data[0] != 5 or data[1:3] != b'\0\0':
                self._bucket(now).unknown += 1
                self.last_unknown = now
                return
            if self.last_feedback is not None and now - self.last_feedback > FEEDBACK_TTL:
                # A quiet period breaks the evidence streak even on the same ports.
                self._new_session(flow, now, self.client_version, self.request_observed, self.startup)
            if self._duplicate(('feedback', data), now):
                return
            received, lost = struct.unpack_from('!HH', data, 3)
            bucket = self._bucket(now)
            bucket.reports += 1
            bucket.received += received
            bucket.lost += lost
            if received + lost:
                bucket.samples += 1
                if self.first_feedback is None:
                    self.first_feedback = now
            self.last_feedback = now
            self.last_feedback_packets = received + lost
        elif event and not self._duplicate(('control', event[1]), now):
            if event[0] == 'disconnect':
                self.closed = True
            else:
                bucket = self._bucket(now)
                if event[0] == 'corrupt':
                    bucket.corrupt += 1
                elif event[0] == 'idr':
                    bucket.idr += 1

    def forwarded(self, now, elapsed_ms):
        bucket = self._bucket(now)
        bucket.processed += 1
        bucket.slow += elapsed_ms >= 5
        bucket.latency[bisect_left(LATENCY_BOUNDS_MS, elapsed_ms)] += 1
        bucket.max_ms = max(bucket.max_ms, elapsed_ms)

    def receive_statistics(self, sample, now):
        # Linux PACKET_STATISTICS returns deltas and resets after each read.
        self.rx_available = sample is not None
        if sample is not None:
            packets, drops = sample
            bucket = self._bucket(now)
            bucket.rx_packets += packets
            bucket.rx_drops += drops
            self.rx_drops_total += drops

    def snapshot(self, now, profile, active=True, running=True):
        self._bucket(now)
        buckets = list(self.buckets)
        received = sum(b.received for b in buckets)
        lost = sum(b.lost for b in buckets)
        processed = sum(b.processed for b in buckets)
        histogram = [sum(b.latency[i] for b in buckets) for i in range(len(LATENCY_BOUNDS_MS) + 1)]
        p95 = None
        if processed:
            remaining = math.ceil(processed * .95)
            for index, count in enumerate(histogram):
                remaining -= count
                if remaining <= 0:
                    p95 = (LATENCY_BOUNDS_MS[index] if index < len(LATENCY_BOUNDS_MS)
                           else max(b.max_ms for b in buckets))
                    break
        age = None if self.last_feedback is None else max(0, now - self.last_feedback)
        fresh = (age is not None and age < FEEDBACK_TTL and not self.closed
                 and (self.last_unknown is None or self.last_unknown < self.last_feedback))
        relay = {'receive_stats_available': self.rx_available,
                 'received': sum(b.rx_packets for b in buckets), 'dropped': sum(b.rx_drops for b in buckets),
                 'dropped_total': self.rx_drops_total, 'processing_samples': processed,
                 'processing_p95_ms': round(p95, 3) if p95 is not None else None}
        value = {'state': 'waiting', 'source': 'client_feedback', 'window_seconds': WINDOW_SECONDS,
                 'requested_profile': profile, 'client_version': self.client_version,
                 'request_observed': self.request_observed,
                 'feedback_age_seconds': round(age, 2) if age is not None else None,
                 'feedback_fresh': fresh, 'received': received, 'lost': lost,
                 'loss_percent': round(lost * 100 / (received + lost), 3) if received + lost else None,
                 'feedback_reports': sum(b.reports for b in buckets),
                 'feedback_samples': sum(b.samples for b in buckets),
                 'corrupt_reports': sum(b.corrupt for b in buckets), 'idr_requests': sum(b.idr for b in buckets),
                 'unknown_feedback': sum(b.unknown for b in buckets), 'relay': relay}
        kind, reason, target = 'wait', 'waiting_feedback', None
        seconds = {b.second: b for b in buckets}
        evidence = [seconds.get(s) for s in range(int(now) - SUSTAINED_SECONDS, int(now))]
        enough = (self.last_feedback_packets > 0 and self.first_feedback is not None and now - self.first_feedback >= SUSTAINED_SECONDS
                  and all(b is not None and b.samples and b.received + b.lost >= 50 and not b.unknown for b in evidence)
                  and sum(b.received + b.lost for b in evidence if b is not None) >= 600)
        high = enough and all(b.lost / (b.received + b.lost) >= HIGH_LOSS for b in evidence)
        moderate = (enough and all(b.lost / (b.received + b.lost) >= MODERATE_LOSS for b in evidence)
                    and sum(bool(b.corrupt + b.idr) for b in evidence) >= 2)
        if not running:
            value['state'], kind, reason = 'stopped', 'stopped', 'relay_stopped'
            value['feedback_fresh'] = False
        elif relay['dropped'] or (processed >= 50 and sum(b.slow for b in buckets) / processed > .05):
            value['state'], kind = 'relay_overload', 'check_relay'
            reason = 'receive_drops' if relay['dropped'] else 'processing_stalls'
        elif self.closed:
            value['state'], kind, reason = 'disconnected', 'wait', 'session_ended'
        elif self.last_unknown is not None and (self.last_feedback is None or self.last_unknown >= self.last_feedback):
            value['state'], kind, reason = 'unsupported', 'wait', 'feedback_layout'
        elif age is not None and not fresh:
            value['state'], kind, reason = 'stale', 'wait', 'feedback_stale'
        elif fresh:
            value['state'], reason = 'collecting', 'collecting_evidence'
            if high or moderate:
                value['state'] = 'degraded'
                reason = 'sustained_loss' if high else 'loss_and_frames'
                profiles = list(PROFILES)
                index = profiles.index(profile)
                kind, target = ('lower', profiles[index - 1]) if index else ('minimum', None)
            elif enough and value['loss_percent'] < MODERATE_LOSS * 100:
                value['state'], kind, reason = 'healthy', 'keep', 'feedback_stable'
        if running and not active and kind in ('lower', 'minimum', 'keep'):
            kind, target = 'baseline', None
        if running and active and not self.request_observed and kind in ('lower', 'minimum', 'keep'):
            kind, reason, target = 'wait', 'waiting_startup', None
        value['advice'] = {'kind': kind, 'reason': reason, 'profile': target,
                           'loss_percent': round(sum(b.lost for b in evidence) * 100 /
                               sum(b.received + b.lost for b in evidence), 3) if high or moderate else None,
                           'sustained_seconds': SUSTAINED_SECONDS if high or moderate else 0}
        return value


def public_quality(value, report_age, running, stats_fresh, mode='active'):
    """Export aggregate fields only, and expire advice when RPC reads an old report."""
    value = value if isinstance(value, dict) else {}
    public = {}
    for key in ('window_seconds', 'client_version', 'feedback_age_seconds', 'received', 'lost', 'loss_percent',
                'feedback_reports', 'feedback_samples', 'corrupt_reports', 'idr_requests', 'unknown_feedback'):
        number = value.get(key)
        public[key] = number if type(number) in (int, float) and 0 <= number <= 1e18 and math.isfinite(number) else None
    public['window_seconds'] = WINDOW_SECONDS
    public['source'] = 'client_feedback'
    profile = value.get('requested_profile')
    public['requested_profile'] = profile if isinstance(profile, str) and profile in PROFILES else None
    public['state'] = value.get('state') if value.get('state') in (
        'waiting', 'collecting', 'healthy', 'degraded', 'relay_overload', 'disconnected',
        'unsupported', 'stale', 'stopped', 'unavailable') else 'waiting'
    public['feedback_fresh'] = value.get('feedback_fresh') is True
    public['request_observed'] = value.get('request_observed') is True
    public['report_fresh'] = bool(running and stats_fresh and report_age is not None and 0 <= report_age < FEEDBACK_TTL)
    relay = value.get('relay') if isinstance(value.get('relay'), dict) else {}
    public['relay'] = {'receive_stats_available': relay.get('receive_stats_available') is True}
    for key in ('received', 'dropped', 'dropped_total', 'processing_samples', 'processing_p95_ms'):
        number = relay.get(key)
        public['relay'][key] = number if type(number) in (int, float) and 0 <= number <= 1e18 and math.isfinite(number) else None
    advice = value.get('advice') if isinstance(value.get('advice'), dict) else {}
    kind = advice.get('kind') if advice.get('kind') in ('wait', 'lower', 'minimum', 'keep', 'baseline',
                                                      'check_relay', 'stopped', 'unavailable') else 'wait'
    reason = advice.get('reason') if advice.get('reason') in ('waiting_feedback', 'relay_stopped', 'receive_drops',
        'processing_stalls', 'session_ended', 'feedback_layout', 'feedback_stale', 'collecting_evidence',
        'sustained_loss', 'loss_and_frames', 'feedback_stable', 'collector_unavailable', 'waiting_startup') else 'waiting_feedback'
    target = advice.get('profile')
    profiles = list(PROFILES)
    index = profiles.index(public['requested_profile']) if public['requested_profile'] else 0
    if kind != 'lower' or not index or target != profiles[index - 1]:
        target = None
        if kind == 'lower':
            kind, reason = 'wait', 'collecting_evidence'
    if public['feedback_age_seconds'] is not None and report_age is not None:
        public['feedback_age_seconds'] = round(public['feedback_age_seconds'] + max(0, report_age), 2)
    if not running:
        public['state'], kind, reason, target = 'stopped', 'stopped', 'relay_stopped', None
        public['feedback_fresh'] = False
    elif not stats_fresh or report_age is None or not 0 <= report_age < FEEDBACK_TTL:
        public['state'], kind, reason, target = 'stale', 'wait', 'feedback_stale', None
        public['feedback_fresh'] = False
    elif public['feedback_age_seconds'] is not None and public['feedback_age_seconds'] >= FEEDBACK_TTL:
        public['feedback_fresh'] = False
        if kind in ('lower', 'minimum', 'keep', 'baseline') or public['state'] in ('collecting', 'healthy', 'degraded'):
            public['state'], kind, reason, target = 'stale', 'wait', 'feedback_stale', None
    if running and mode == 'baseline' and kind in ('lower', 'minimum', 'keep'):
        kind, target = 'baseline', None
    if running and mode != 'baseline' and not public['request_observed'] and kind in ('lower', 'minimum', 'keep'):
        kind, reason, target = 'wait', 'waiting_startup', None
    if not public['feedback_fresh'] and kind in ('lower', 'minimum', 'keep', 'baseline'):
        kind, reason, target = 'wait', 'collecting_evidence', None
    loss = advice.get('loss_percent')
    evidence = advice.get('sustained_seconds') == SUSTAINED_SECONDS and kind in ('lower', 'minimum', 'baseline')
    public['advice'] = {'kind': kind, 'reason': reason, 'profile': target,
                        'loss_percent': loss if evidence and type(loss) in (int, float) and 0 <= loss <= 100 else None,
                        'sustained_seconds': SUSTAINED_SECONDS if evidence else 0}
    return public


def unavailable_quality(profile, running=True):
    return {'state': 'unavailable' if running else 'stopped', 'requested_profile': profile,
            'feedback_fresh': False, 'advice': {'kind': 'unavailable' if running else 'stopped',
            'reason': 'collector_unavailable' if running else 'relay_stopped', 'profile': None}}
