"""Connection-scoped domain evidence, bounded independently of the inventory."""
from collections import OrderedDict
import json
import ipaddress
import math
import re
import uuid
import time

from observability import utc
from sony_domains import domain_info, scope_proxy
from stream_quality import control_event

MAX_BATCHES = 32
MAX_BATCH_DOMAINS = 512
MAX_BATCH_EVENTS = 512
MAX_HISTORY_BYTES = 786432
BATCH_IDLE_SECONDS = 60
DNS_FAILURES = {'dns_error', 'dns_timeout'}
EVIDENCE_KINDS = {'dns_query', 'dns_ok', 'dns_empty', 'dns_error', 'dns_timeout', 'dns_truncated',
                  'tcp_ok', 'tcp_reset', 'tcp_timeout', 'tls_sni', 'unreachable'}
TRAFFIC_BYTES = ('upload_bytes', 'download_bytes', 'proxy_upload_bytes', 'proxy_download_bytes',
                 'direct_upload_bytes', 'direct_download_bytes')
TRAFFIC_RATES = ('upload_rate', 'download_rate', 'proxy_rate', 'peak_proxy_rate')
MAX_TRAFFIC_CONNECTIONS = 1024


def number(value, default=0):
    return value if type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 2**63 - 1 else default


def empty_traffic(value=None):
    value = value if isinstance(value, dict) else {}
    result = {key: int(number(value.get(key))) for key in TRAFFIC_BYTES + ('connections', 'active_connections', 'proxy_active_connections')}
    result.update({key: number(value.get(key)) for key in TRAFFIC_RATES + ('last_sample_epoch',)})
    result.update({key: value.get(key) is True for key in ('sampled', 'has_proxy', 'proxy_rules_seen', 'coverage_limited')})
    result['source'] = 'passwall_core'
    result['last_route'] = value.get('last_route') if value.get('last_route') in (
        'proxy', 'selected', 'previous', 'other_proxy', 'direct', 'original', 'unknown') else 'unknown'
    return result


def freeze_traffic(batch):
    rows = batch['domains'].values() if isinstance(batch['domains'], dict) else batch['domains']
    for traffic in [batch.get('traffic', {}), batch.get('unattributed_traffic', {})] + [row.get('traffic', {}) for row in rows]:
        for key in ('upload_rate', 'download_rate', 'proxy_rate', 'active_connections', 'proxy_active_connections'):
            traffic[key] = 0


def device_macs(devices):
    return {role: info['mac'] for role, info in devices.items()}


def batch_summary(batch):
    rows = batch['domains'].values() if isinstance(batch['domains'], dict) else batch['domains']
    rows = list(rows)
    return {key: batch.get(key) for key in ('id', 'time', 'epoch', 'last_seen', 'last_epoch', 'ended_at',
            'state', 'source', 'end_reason', 'tag', 'stream_started_at', 'truncated')} | {
        'domain_count': len({row['domain'] for row in rows}),
        'failed_count': len({row['domain'] for row in rows if row.get('dns_failed')}),
        'traffic': empty_traffic(batch.get('traffic')),
        'event_count': batch.get('event_count', 0)}


class DomainMonitor:
    def __init__(self, devices, inventory=None, close_active=True, epoch=None):
        self.devices = devices
        self.batches = OrderedDict()
        self.current_id = None
        self.flow = None
        self.startups = OrderedDict()
        self.changed = False
        self.new_domains = False
        self.traffic_connections = OrderedDict()
        self.traffic_snapshot = None
        self.traffic_cache_limited = False
        self.observed_since = time.time() if epoch is None else epoch
        self.traffic_state = 'waiting'
        self.traffic_limit = '按批次累计本机已有连接接口的字节增量。设备直达流量与采样间完成的短连接影响覆盖。'
        self.traffic_core_types = []
        if not isinstance(inventory, dict) or inventory.get('device_macs') != device_macs(devices):
            return
        raw = inventory.get('batches', [])
        for batch in reversed(raw[:MAX_BATCHES] if isinstance(raw, list) else []):
            try:
                batch = dict(batch)
                if (not re.fullmatch('[0-9a-f]{32}', batch['id']) or
                        any(type(batch[key]) not in (int, float) or not math.isfinite(batch[key])
                            or batch[key] < 0 for key in ('epoch', 'last_epoch'))):
                    continue
                rows = batch.get('domains', [])
                batch['domains'] = OrderedDict(((row['device'], row['domain']), dict(row))
                    for row in (rows[:MAX_BATCH_DOMAINS] if isinstance(rows, list) else [])
                    if isinstance(row, dict) and row.get('device') in devices and
                    isinstance(row.get('domain'), str) and len(row['domain']) <= 253 and
                    re.fullmatch(r'[a-z0-9_.-]+', row['domain']) and isinstance(row.get('counts'), dict))
                for row in batch['domains'].values():
                    row['counts'] = {kind: count for kind, count in row['counts'].items()
                                    if kind in EVIDENCE_KINDS and type(count) is int and 0 <= count <= 10**12}
                    row['addresses'] = [dict(value) for value in row.get('addresses', [])[:8]
                                        if isinstance(value, dict)] if isinstance(row.get('addresses'), list) else []
                    row['qtypes'] = [value for value in row.get('qtypes', [])[:8] if type(value) is int]
                    row['traffic'] = empty_traffic(row.get('traffic'))
                batch['traffic'] = empty_traffic(batch.get('traffic'))
                batch['unattributed_traffic'] = empty_traffic(batch.get('unattributed_traffic'))
                events = batch.get('events', [])
                batch['events'] = [dict(event) for event in
                    (events[-MAX_BATCH_EVENTS:] if isinstance(events, list) else []) if isinstance(event, dict)]
                if close_active and batch.get('state') == 'collecting':
                    batch.update(state='archived', ended_at=batch['last_seen'], end_reason='observer_restart')
                    self.changed = True
                if batch.get('state') == 'archived':
                    freeze_traffic(batch)
                self.batches[batch['id']] = batch
            except (KeyError, TypeError, ValueError, AttributeError):
                continue

    def begin(self, epoch, tag='', source='activity', batch_id=None):
        self.finish('next_batch', epoch)
        ident = batch_id or uuid.uuid4().hex
        batch = {'id': ident, 'epoch': epoch, 'time': utc(epoch), 'last_epoch': epoch,
                 'last_seen': utc(epoch), 'state': 'collecting', 'source': source, 'tag': tag,
                 'domains': OrderedDict(), 'events': [], 'event_count': 0, 'truncated': False,
                 'traffic': empty_traffic(), 'unattributed_traffic': empty_traffic(), 'traffic_state': 'waiting'}
        self.batches[ident] = batch
        self.current_id = ident
        self.changed = True
        while len(self.batches) > MAX_BATCHES:
            self.batches.popitem(last=False)
        return ident

    def ensure(self, epoch, tag=''):
        self.tick(epoch)
        return self.current_id or self.begin(epoch, tag)

    def touch(self, epoch):
        if self.current_id:
            self.batches[self.current_id].update(last_epoch=epoch, last_seen=utc(epoch))

    def finish(self, reason, epoch=None):
        if self.current_id:
            batch = self.batches[self.current_id]
            batch.update(state='archived', ended_at=utc(batch['last_epoch'] if epoch is None else epoch),
                         end_reason=reason)
            freeze_traffic(batch)
            self.current_id = None
            self.flow = None
            self.changed = True

    def tick(self, epoch, closing=False):
        if closing:
            self.finish('capture_stopped', epoch)
        elif self.current_id and epoch - self.batches[self.current_id]['last_epoch'] >= BATCH_IDLE_SECONDS:
            self.finish('idle')

    def stream(self, packet, epoch, tag=''):
        portal, ps5 = self.devices.get('portal', {}), self.devices.get('ps5', {})
        if (packet.get('proto') != 17 or packet.get('src_mac') != portal.get('mac') or
                packet.get('src') != portal.get('ip') or packet.get('dst') != ps5.get('ip')):
            return False
        data = packet['payload']
        event = control_event(data)
        flow = (packet['sport'], packet['dport'])
        if event and event[0] == 'start':
            key = (flow, event[1])
            if key not in self.startups:
                self.startups[key] = True
                if len(self.startups) > 16:
                    self.startups.popitem(last=False)
                if self.current_id and self.batches[self.current_id].get('stream_started_at'):
                    self.finish('reconnected', epoch)
                ident = self.ensure(epoch, tag)
                self.batches[ident]['stream_started_at'] = utc(epoch)
                self.flow = flow
                self.changed = True
            if flow == self.flow:
                self.touch(epoch)
        elif event and event[0] == 'disconnect' and flow == self.flow:
            self.touch(epoch)
            self.finish('disconnected', epoch)
            self.flow = None
        elif len(data) == 15 and data[:3] == b'\x05\0\0':
            if self.flow is None or self.flow == flow:
                self.ensure(epoch, tag)
                self.flow = flow
                self.touch(epoch)
        return True

    def domain(self, batch, device, name, epoch):
        key = (device, name)
        if key not in batch['domains']:
            if len(batch['domains']) >= MAX_BATCH_DOMAINS:
                batch['truncated'] = True
                return None
            batch['domains'][key] = {'device': device, 'domain': name, 'first_epoch': epoch,
                'first_seen': utc(epoch), 'last_epoch': epoch, 'last_seen': utc(epoch),
                'counts': {}, 'addresses': [], 'qtypes': [], 'dns_failed': False, 'dns_failures': 0,
                'last_problem': '', 'last_dns_result': '', 'traffic': empty_traffic(), **domain_info(name)}
            self.new_domains = True
        return batch['domains'][key]

    def record(self, event):
        if event['kind'] not in EVIDENCE_KINDS or not event['domains']:
            return
        ident = event.get('batch_id') or self.ensure(event['epoch'], event.get('tag', ''))
        if ident not in self.batches:
            return
        batch = self.batches[ident]
        if ident == self.current_id:
            self.touch(event['epoch'])
        kind = event['kind']
        dns_failed = kind in DNS_FAILURES or (kind == 'unreachable' and event.get('dns_unreachable'))
        for name in event['domains']:
            row = self.domain(batch, event['device'], name, event['epoch'])
            if row is None:
                continue
            row.update(last_epoch=event['epoch'], last_seen=event['time'])
            row['counts'][kind] = row['counts'].get(kind, 0) + 1
            if event.get('qtype') and event['qtype'] not in row['qtypes'] and len(row['qtypes']) < 8:
                row['qtypes'].append(event['qtype'])
            if kind.startswith('dns_') or dns_failed:
                row['last_dns_result'] = kind
            if 'rcode' in event:
                row['last_rcode'] = event['rcode']
            if event.get('addresses'):
                row['addresses'] = [dict(value) for value in event['addresses'][:8]]
            if dns_failed:
                row['dns_failed'] = True
                row['dns_failures'] += 1
                row['last_problem'] = kind
        evidence = {key: event[key] for key in ('time', 'epoch', 'device', 'kind', 'domains', 'qtype', 'rcode',
            'addresses', 'address', 'port', 'retries', 'observation_only', 'dns_unreachable') if key in event}
        evidence['problem'] = bool(dns_failed or event.get('problem'))
        batch['events'].append(evidence)
        batch['event_count'] += 1
        if len(batch['events']) > MAX_BATCH_EVENTS:
            index = next((i for i, item in enumerate(batch['events']) if not item.get('problem')), 0)
            batch['events'].pop(index)
            batch['truncated'] = True

    def observe_connections(self, report, epoch, tag='', resolve=None):
        stamp = number(report.get('epoch'), None) if isinstance(report, dict) else None
        fresh = stamp is not None and 0 <= epoch - stamp < 15
        scope = report.get('policy_scope', {}) if fresh else {}
        rules_changed = False
        if fresh:
            self.traffic_limit = str(report.get('limit') or self.traffic_limit)[:600]
            self.traffic_core_types = list(report.get('core_types', []))[:8]
        if self.current_id and scope:
            for row in self.batches[self.current_id]['domains'].values():
                try:
                    covered = scope_proxy(row['domain'], scope, respect_switches=False)
                except (TypeError, ValueError, AttributeError):
                    covered = False
                if covered and not row['traffic']['proxy_rules_seen']:
                    row['traffic']['proxy_rules_seen'] = True
                    rules_changed = True
        valid = stamp is not None and 0 <= epoch - stamp < 15 and number(report.get('sampled_cores')) > 0
        if not valid:
            self.traffic_state = report.get('state') if fresh and report.get('state') in ('disabled', 'unavailable') else 'waiting'
            if self.current_id:
                self.batches[self.current_id]['traffic_state'] = self.traffic_state
            return rules_changed
        key = (report.get('generation', ''), stamp)
        if key == self.traffic_snapshot:
            return rules_changed
        previous_stamp = self.traffic_snapshot[1] if self.traffic_snapshot else None
        self.traffic_snapshot = key
        self.traffic_state = 'observing'
        rows = report.get('connections', [])
        if not isinstance(rows, list):
            return False
        health = report.get('health') if isinstance(report.get('health'), dict) else {}
        limited = bool(report.get('errors') or health.get('capacity_drops') or health.get('malformed'))
        for cached in self.traffic_connections.values():
            cached['rates'] = (0, 0)
        changed = rules_changed
        for item in rows[:512]:
            if not isinstance(item, dict) or item.get('device') not in self.devices or not isinstance(item.get('id'), str):
                continue
            ident, device = (str(item.get('core', '')), item['id']), item['device']
            previous = self.traffic_connections.get(ident)
            if item.get('source_ip'):
                try:
                    source = ipaddress.ip_address(item['source_ip'])
                    if source.version == 4 and str(source) != self.devices[device]['ip']:
                        continue
                except ValueError:
                    limited = True
                    continue
            if item.get('active') is False and previous:
                previous['active'] = False
            seen_at = number(item.get('last_epoch'), None)
            if seen_at != stamp:
                continue  # Cached rows from an unavailable core retain their baseline.
            upload, download = (number(item.get(field), None) for field in ('bytes_up', 'bytes_down'))
            if upload is None or download is None:
                limited = True
                continue
            started = number(item.get('started_epoch'), None)
            if previous and started is not None and previous.get('started_epoch') is not None and started != previous['started_epoch']:
                previous = None
            if previous and previous.get('generation') != report.get('generation', '') and (
                    started is None or previous.get('started_epoch') is None):
                previous = None
            host = str(item.get('domain') or '').lower().rstrip('.')
            if not host and previous:
                host = previous.get('domain', '')
            if not host and resolve:
                names = resolve(device, item.get('address', ''), stamp)
                if len(names) == 1:
                    host = names[0]
            try:
                ipaddress.ip_address(host)
                host = ''
            except ValueError:
                if len(host) > 253 or not re.fullmatch(r'[a-z0-9_.-]+', host):
                    host = ''
            up = max(0, upload - previous['upload']) if previous else 0
            down = max(0, download - previous['download']) if previous else 0
            regressed = bool(previous and (upload < previous['upload'] or download < previous['download']))
            gap = bool(previous and stamp - previous['epoch'] >= 15)
            if self.current_id is None and (up or down or previous is None and started is not None and started >= self.observed_since):
                boundary = previous['epoch'] if previous and (up or down) and not gap else stamp if previous else min(started, stamp)
                self.ensure(max(self.observed_since, boundary), tag)
            batch = self.batches.get(self.current_id)
            cache_limited = bool(previous is None and self.traffic_cache_limited and previous_stamp is not None and
                                 (started is None or started < previous_stamp))
            if previous is None and batch and started is not None and started >= batch['epoch'] and not cache_limited:
                up, down = upload, download
            boundary_limited = bool(batch and previous and previous.get('batch') != self.current_id and
                                    previous['epoch'] < batch['epoch'] and (started is None or started < batch['epoch']))
            if boundary_limited:
                up = down = 0
            via_proxy = item.get('via_proxy') is True or item.get('route') in ('proxy', 'selected', 'previous', 'other_proxy')
            duration = stamp - previous['epoch'] if previous else stamp - started if started is not None else 0
            rates = (up / max(1, duration), down / max(1, duration)) if duration >= 0 else (0, 0)
            cached = {'upload': upload, 'download': download, 'epoch': stamp, 'started_epoch': started,
                      'domain': host, 'device': device, 'batch': self.current_id,
                      'generation': report.get('generation', ''),
                      'active': item.get('active') is not False, 'rates': rates, 'via_proxy': via_proxy}
            self.traffic_connections[ident] = cached
            self.traffic_connections.move_to_end(ident)
            if len(self.traffic_connections) > MAX_TRAFFIC_CONNECTIONS:
                self.traffic_connections.popitem(last=False)
                self.traffic_cache_limited = True
                limited = True
            if batch is None:
                continue
            row = self.domain(batch, device, host, stamp) if host else None
            cached['unattributed'] = row is None
            traffic = row['traffic'] if row else batch['unattributed_traffic']
            route = item.get('route') if item.get('route') in ('proxy', 'selected', 'previous', 'other_proxy', 'direct', 'original') else 'unknown'
            changed = changed or not traffic['sampled'] or via_proxy and not traffic['has_proxy'] or traffic['last_route'] != route
            traffic['upload_bytes'] += int(up)
            traffic['download_bytes'] += int(down)
            if via_proxy:
                traffic['proxy_upload_bytes'] += int(up)
                traffic['proxy_download_bytes'] += int(down)
            elif item.get('route') == 'direct':
                traffic['direct_upload_bytes'] += int(up)
                traffic['direct_download_bytes'] += int(down)
            traffic.update(sampled=True, has_proxy=traffic['has_proxy'] or via_proxy, last_sample_epoch=stamp, last_route=route,
                           proxy_rules_seen=traffic['proxy_rules_seen'] or item.get('expected_proxy') is True,
                           coverage_limited=traffic['coverage_limited'] or limited or regressed or boundary_limited or gap or cache_limited or
                               previous is None and (started is None or started < batch['epoch']))
            if previous is None or previous.get('batch') != self.current_id or previous.get('domain') != host:
                traffic['connections'] += 1
            if up or down:
                self.touch(stamp)
                if row:
                    row.update(last_epoch=stamp, last_seen=utc(stamp))
                changed = True
        if self.current_id:
            batch = self.batches[self.current_id]
            for row in batch['domains'].values():
                traffic = row['traffic']
                try:
                    covered = scope_proxy(row['domain'], scope, respect_switches=False)
                except (TypeError, ValueError, AttributeError):
                    covered, limited = False, True
                if covered:
                    changed = changed or not traffic['proxy_rules_seen']
                    traffic['proxy_rules_seen'] = True
                active = [item for item in self.traffic_connections.values() if item.get('batch') == self.current_id and
                          item['device'] == row['device'] and item['domain'] == row['domain'] and item['active'] and
                          0 <= stamp - item['epoch'] < 15]
                traffic['active_connections'] = len(active)
                traffic['proxy_active_connections'] = sum(item['via_proxy'] for item in active)
                traffic['upload_rate'] = sum(item['rates'][0] for item in active)
                traffic['download_rate'] = sum(item['rates'][1] for item in active)
                traffic['proxy_rate'] = sum(sum(item['rates']) for item in active if item['via_proxy'])
                traffic['peak_proxy_rate'] = max(traffic['peak_proxy_rate'], traffic['proxy_rate'])
            unknown = [item for item in self.traffic_connections.values() if item.get('batch') == self.current_id and
                       item.get('unattributed') and item['active'] and 0 <= stamp - item['epoch'] < 15]
            unassigned = batch['unattributed_traffic']
            unassigned.update(active_connections=len(unknown), proxy_active_connections=sum(item['via_proxy'] for item in unknown),
                              upload_rate=sum(item['rates'][0] for item in unknown),
                              download_rate=sum(item['rates'][1] for item in unknown),
                              proxy_rate=sum(sum(item['rates']) for item in unknown if item['via_proxy']))
            unassigned['peak_proxy_rate'] = max(unassigned['peak_proxy_rate'], unassigned['proxy_rate'])
            totals = [row['traffic'] for row in batch['domains'].values()] + [batch['unattributed_traffic']]
            summary = empty_traffic(batch.get('traffic'))
            for field in TRAFFIC_BYTES + ('connections', 'active_connections', 'proxy_active_connections', 'upload_rate', 'download_rate', 'proxy_rate'):
                summary[field] = sum(item[field] for item in totals)
            summary.update(sampled=True, has_proxy=any(item['has_proxy'] for item in totals), last_sample_epoch=stamp,
                           coverage_limited=limited or any(item['coverage_limited'] for item in totals),
                           peak_proxy_rate=max(summary['peak_proxy_rate'], summary['proxy_rate']))
            batch.update(traffic=summary, traffic_state='observing')
        return changed or self.new_domains

    def snapshot(self):
        # Prune whole old batches before trimming details in the newest batch.
        while True:
            value = {'version': 1, 'device_macs': device_macs(self.devices),
                     'idle_seconds': BATCH_IDLE_SECONDS, 'batches': [dict(batch,
                        traffic=dict(batch.get('traffic', {})), unattributed_traffic=dict(batch.get('unattributed_traffic', {})),
                        domains=[dict(row, counts=dict(row['counts']), addresses=list(row['addresses']),
                                      qtypes=list(row['qtypes']), traffic=dict(row.get('traffic', {}))) for row in batch['domains'].values()],
                        events=list(batch['events'])) for batch in reversed(self.batches.values())]}
            if len(json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode()) <= MAX_HISTORY_BYTES:
                return value
            if len(self.batches) > 1:
                self.batches.popitem(last=False)
                continue
            batch = next(iter(self.batches.values()))
            batch['truncated'] = True
            if batch['events']:
                for _ in range(max(1, len(batch['events']) // 4)):
                    index = next((i for i, item in enumerate(batch['events']) if not item.get('problem')), 0)
                    batch['events'].pop(index)
            else:
                key = min(batch['domains'], key=lambda key: (
                    sum(batch['domains'][key]['traffic'][field] for field in ('proxy_upload_bytes', 'proxy_download_bytes')),
                    sum(batch['domains'][key]['traffic'][field] for field in ('upload_bytes', 'download_bytes'))))
                removed = batch['domains'].pop(key)
                traffic, bucket = removed['traffic'], batch['unattributed_traffic']
                for field in TRAFFIC_BYTES + ('connections', 'active_connections', 'proxy_active_connections') + TRAFFIC_RATES[:3]:
                    bucket[field] += traffic[field]
                bucket.update(sampled=bucket['sampled'] or traffic['sampled'], has_proxy=bucket['has_proxy'] or traffic['has_proxy'],
                              coverage_limited=True, last_sample_epoch=max(bucket['last_sample_epoch'], traffic['last_sample_epoch']))
                batch['traffic']['coverage_limited'] = True
                batch['traffic_details_trimmed'] = True
                for cached in self.traffic_connections.values():
                    if cached.get('batch') == batch['id'] and (cached['device'], cached['domain']) == key:
                        cached['unattributed'] = True

    def summaries(self):
        return [batch_summary(batch) for batch in reversed(self.batches.values())]
