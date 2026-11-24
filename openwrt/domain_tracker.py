"""Bounded passive DNS/TCP/TLS evidence for an enrolled PS5 and Portal pair."""
from collections import OrderedDict, deque
import ipaddress
import json
import math
import re
import struct
import time

from observability import OBSERVATION_LIMIT, event_context, event_key, utc
from sony_domains import domain_info

MAX_DOMAINS = 512
MAX_PENDING = 128
MAX_STREAMS = 32
MAX_DNS_BYTES = 8192
DNS_TIMEOUT = 8
TCP_TIMEOUT = 10
ERROR_KINDS = {'dns_error', 'dns_timeout', 'tcp_reset', 'tcp_timeout', 'unreachable'}


def host_name(value):
    value = value.lower().rstrip('.')
    if (not value or len(value) > 253 or not re.fullmatch(r'[a-z0-9_.-]+', value)
            or any(not part or len(part) > 63 for part in value.split('.'))):
        raise ValueError('Invalid domain name')
    return value


def dns_name(data, offset):
    parts, visited, end = [], set(), None
    for _ in range(128):
        if offset >= len(data) or offset in visited:
            raise ValueError('Truncated/cyclic DNS name')
        visited.add(offset)
        size = data[offset]
        if size & 0xc0 == 0xc0:
            if offset + 1 >= len(data):
                raise ValueError('Truncated DNS pointer')
            if end is None:
                end = offset + 2
            offset = ((size & 63) << 8) | data[offset + 1]
        elif size & 0xc0 or size > 63:
            raise ValueError('Invalid DNS label')
        elif size == 0:
            return host_name('.'.join(parts)), end if end is not None else offset + 1
        else:
            if offset + 1 + size > len(data):
                raise ValueError('Truncated DNS label')
            parts.append(data[offset + 1:offset + 1 + size].decode('ascii'))
            if sum(len(part) + 1 for part in parts) > 254:
                raise ValueError('Oversized DNS name')
            offset += size + 1
    raise ValueError('DNS name recursion limit')


def parse_dns(data):
    if not 12 <= len(data) <= MAX_DNS_BYTES:
        raise ValueError('Invalid DNS message length')
    ident, flags, questions, answers, authority, additional = struct.unpack('!6H', data[:12])
    if questions != 1 or flags & 0x7800 or answers + authority + additional > 64:
        raise ValueError('Unsupported DNS message')
    name, offset = dns_name(data, 12)
    if offset + 4 > len(data):
        raise ValueError('Truncated DNS question')
    qtype, qclass = struct.unpack('!HH', data[offset:offset + 4])
    if qclass != 1:
        raise ValueError('Unsupported DNS class')
    offset += 4
    records = []
    for index in range(answers + authority + additional):
        # Root owner names occur in OPT records. Skip them with the same bounds.
        if offset < len(data) and data[offset] == 0:
            owner, offset = '', offset + 1
        else:
            owner, offset = dns_name(data, offset)
        if offset + 10 > len(data):
            raise ValueError('Truncated DNS resource record')
        kind, klass, ttl, size = struct.unpack('!HHIH', data[offset:offset + 10])
        offset += 10
        end = offset + size
        if end > len(data):
            raise ValueError('Truncated DNS resource data')
        value = None
        if klass == 1 and kind in (1, 28) and size == (4 if kind == 1 else 16):
            value = str(ipaddress.ip_address(data[offset:end]))
        elif klass == 1 and kind == 5:
            value, consumed = dns_name(data, offset)
            if consumed != end:
                raise ValueError('Invalid CNAME length')
        if value is not None and index < answers + authority + additional:
            records.append({'owner': owner, 'type': kind, 'ttl': min(ttl, 86400), 'value': value,
                            'answer': index < answers})
        offset = end
    return {'id': ident, 'response': bool(flags & 0x8000), 'truncated': bool(flags & 0x0200),
            'rcode': flags & 15, 'name': name, 'qtype': qtype, 'records': records}


def dns_bindings(message):
    # Accept addresses only for the requested name and its answer CNAME chain.
    names, expiries = [message['name']], {message['name']: 86400}
    for _ in range(8):
        aliases = [record for record in message['records'] if record['type'] == 5 and record['answer']
                   and record['owner'] in names and record['value'] not in names]
        if not aliases:
            break
        for record in aliases[:8 - len(names)]:
            names.append(record['value'])
            expiries[record['value']] = min(expiries[record['owner']], record['ttl'])
        if len(names) >= 8:
            break
    addresses = []
    for record in message['records']:
        if record['type'] in (1, 28) and record['owner'] in names:
            addresses.append({'address': record['value'],
                              'ttl': min(expiries[record['owner']], record['ttl'])})
    return names, addresses[:8]


def parse_ip(data, quoted=False):
    if not data:
        return None
    version = data[0] >> 4
    if version == 4:
        if len(data) < 20:
            return None
        length, size = (data[0] & 15) * 4, struct.unpack('!H', data[2:4])[0]
        fragment = struct.unpack('!H', data[6:8])[0]
        if length < 20 or length > len(data) or size < length or fragment & 0x3fff:
            return None
        if not quoted and size > len(data):
            return None
        proto, src, dst = data[9], str(ipaddress.ip_address(data[12:16])), str(ipaddress.ip_address(data[16:20]))
        payload = data[length:min(len(data), size)]
    elif version == 6:
        if len(data) < 40:
            return None
        size = 40 + struct.unpack('!H', data[4:6])[0]
        if not quoted and size > len(data):
            return None
        proto, offset = data[6], 40
        src, dst = str(ipaddress.ip_address(data[8:24])), str(ipaddress.ip_address(data[24:40]))
        for _ in range(5):
            if proto not in (0, 43, 44, 60):
                break
            if offset + 8 > len(data):
                return None
            if proto == 44:
                if struct.unpack('!H', data[offset + 2:offset + 4])[0] & 0xfff9:
                    return None
                next_offset = offset + 8
            else:
                next_offset = offset + (data[offset + 1] + 1) * 8
            proto, offset = data[offset], next_offset
        if proto in (0, 43, 44, 60) or offset > len(data):
            return None
        payload = data[offset:min(len(data), size)]
    else:
        return None
    result = {'src': src, 'dst': dst, 'proto': proto, 'payload': payload}
    if proto in (6, 17) and len(payload) >= 8:
        result['sport'], result['dport'] = struct.unpack('!HH', payload[:4])
        if proto == 17:
            size = struct.unpack('!H', payload[4:6])[0]
            if size < 8 or (not quoted and size > len(payload)):
                return None
            result['payload'] = payload[8:size]
        elif len(payload) >= 20:
            offset = (payload[12] >> 4) * 4
            if offset < 20 or offset > len(payload):
                return None
            result.update(seq=struct.unpack('!I', payload[4:8])[0],
                          ack=struct.unpack('!I', payload[8:12])[0], flags=payload[13], payload=payload[offset:])
        elif not quoted:
            return None
    return result


def parse_frame(frame):
    if len(frame) < 14:
        return None
    kind, offset = struct.unpack('!H', frame[12:14])[0], 14
    for _ in range(2):
        if kind not in (0x8100, 0x88a8):
            break
        if offset + 4 > len(frame):
            return None
        kind, offset = struct.unpack('!H', frame[offset + 2:offset + 4])[0], offset + 4
    if kind not in (0x0800, 0x86dd):
        return None
    result = parse_ip(frame[offset:])
    if result is not None:
        result.update(src_mac=frame[6:12].hex(':'), dst_mac=frame[:6].hex(':'))
    return result


def tls_name(payload):
    """Inspect a complete first ClientHello only; retain no TLS/application bytes."""
    if len(payload) < 9 or payload[0] != 22 or payload[1] != 3:
        return None
    size = struct.unpack('!H', payload[3:5])[0]
    if size > 4096 or len(payload) < size + 5 or payload[5] != 1:
        return None
    handshake_size = int.from_bytes(payload[6:9], 'big')
    if handshake_size + 4 > size:
        return None
    data, offset = payload[9:9 + handshake_size], 34
    try:
        offset += 1 + data[offset]
        cipher_size = struct.unpack('!H', data[offset:offset + 2])[0]
        offset += 2 + cipher_size
        offset += 1 + data[offset]
        extensions_size = struct.unpack('!H', data[offset:offset + 2])[0]
        offset += 2
        end = offset + extensions_size
        if end != len(data):
            return None
        for _ in range(64):
            if offset + 4 > end:
                return None
            kind, size = struct.unpack('!HH', data[offset:offset + 4])
            offset += 4
            block = data[offset:offset + size]
            offset += size
            if offset > end:
                return None
            if kind == 0:
                if len(block) < 5 or struct.unpack('!H', block[:2])[0] != len(block) - 2:
                    return None
                if block[2] != 0 or struct.unpack('!H', block[3:5])[0] != len(block) - 5:
                    return None
                return host_name(block[5:].decode('ascii'))
            if offset == end:
                return None
    except (IndexError, struct.error, UnicodeError, ValueError):
        return None
    return None


class DomainTracker:
    def __init__(self, devices, emit, preferences, inventory=None, epoch=None):
        self.devices, self.emit, self.preferences = devices, emit, preferences
        self.started = time.time() if epoch is None else epoch
        self.domains = OrderedDict()
        self.pending_dns, self.pending_tcp, self.bindings, self.streams = (OrderedDict() for _ in range(4))
        self.repeats = OrderedDict()
        self.recent = deque(maxlen=512)
        self.dirty, self.new_names = False, False
        self.health = {'packets': 0, 'malformed': 0, 'capacity_drops': 0,
                       'suppressed_events': 0, 'tls_visibility_limited': 0, 'history_drops': 0}
        if isinstance(inventory, dict):
            raw_items = inventory.get('domains', [])
            for item in (raw_items[:MAX_DOMAINS] if isinstance(raw_items, list) else []):
                try:
                    item = dict(item)
                    host_name(item['domain'])
                    device = item['device']
                    if device not in devices or item.get('device_mac') != devices[device]['mac']:
                        continue
                    if type(item.get('first_epoch')) not in (int, float) or type(item.get('last_epoch')) not in (int, float):
                        continue
                    if any(not math.isfinite(item[key]) or item[key] < 0 for key in ('first_epoch', 'last_epoch')):
                        continue
                    item['counts'] = {key: int(value) for key, value in item.get('counts', {}).items()
                                      if key in ('dns_query', 'dns_ok', 'dns_empty', 'dns_error', 'dns_timeout',
                                                 'tcp_ok', 'tcp_reset', 'tcp_timeout', 'tls_sni', 'unreachable')
                                      and type(value) is int and value >= 0}
                    item['addresses'] = []  # TTL bindings require a fresh matching DNS reply.
                    problem = item.get('last_problem', '')
                    item['last_problem'] = problem if isinstance(problem, str) and problem in ERROR_KINDS else ''
                    dns_problem = item.get('dns_problem', item['last_problem'] if item['last_problem'].startswith('dns_') else '')
                    tcp_problem = item.get('tcp_problem', item['last_problem'] if not item['last_problem'].startswith('dns_') else '')
                    item['dns_problem'] = dns_problem if isinstance(dns_problem, str) and dns_problem in ('dns_error', 'dns_timeout') else ''
                    item['tcp_problem'] = tcp_problem if isinstance(tcp_problem, str) and tcp_problem in ('tcp_reset', 'tcp_timeout', 'unreachable') else ''
                    self.domains[(device, item['domain'])] = item
                except (KeyError, ValueError, TypeError, AttributeError):
                    continue

    def bounded(self, mapping, key, value, limit=MAX_PENDING):
        if key not in mapping and len(mapping) >= limit:
            mapping.popitem(last=False)
            self.health['capacity_drops'] += 1
        mapping[key] = value
        mapping.move_to_end(key)

    def role(self, packet):
        for device, info in self.devices.items():
            for outgoing, side in ((True, 'src'), (False, 'dst')):
                if packet[side + '_mac'] == info['mac']:
                    address = ipaddress.ip_address(packet[side])
                    if address.version == 6 or packet[side] == info['ip']:
                        return device, outgoing
        return None, None

    def domain(self, device, name, epoch):
        key = (device, name)
        if key not in self.domains:
            if len(self.domains) >= MAX_DOMAINS:
                self.domains.popitem(last=False)
                self.health['capacity_drops'] += 1
            self.domains[key] = {'device': device, 'device_mac': self.devices[device]['mac'], 'domain': name,
                                 'first_epoch': epoch, 'last_epoch': epoch, 'first_seen': utc(epoch),
                                 'last_seen': utc(epoch), 'counts': {}, 'addresses': [], 'last_problem': '',
                                 'dns_problem': '', 'tcp_problem': ''}
            self.new_names = True
            self.record(device, 'new_domain', [name], epoch, update=False)
        item = self.domains[key]
        item.update(last_epoch=epoch, last_seen=utc(epoch))
        self.domains.move_to_end(key)
        self.dirty = True
        return item

    def record(self, device, kind, names, epoch, update=True, **fields):
        names = list(dict.fromkeys(names))[:8]
        event = {'epoch': epoch, 'time': utc(epoch), 'device': device, 'kind': kind,
                 'domains': names, 'tag': self.preferences.tag, 'problem': kind in ERROR_KINDS, **fields}
        if update:
            for name in names:
                item = self.domain(device, name, epoch)
                item['counts'][kind] = item['counts'].get(kind, 0) + 1
                if event['problem']:
                    item['dns_problem' if kind.startswith('dns_') else 'tcp_problem'] = kind
                elif kind in ('dns_ok', 'dns_empty'):
                    item['dns_problem'] = ''
                elif kind == 'tcp_ok':
                    item['tcp_problem'] = ''
                item['last_problem'] = item['tcp_problem'] or item['dns_problem']
        if len(self.recent) >= self.recent.maxlen:
            self.health['history_drops'] += 1
        self.recent.append(event)
        key = event_key(event)
        if self.preferences.mode == 'compact' and key in self.repeats:
            previous = self.repeats[key]
            if epoch - previous['first_epoch'] < 60:
                previous['count'] += 1
                previous['last_epoch'] = epoch
                self.health['suppressed_events'] += 1
                return
            self.flush_repeat(key)
        if len(self.repeats) >= 128:
            self.flush_repeat(next(iter(self.repeats)))
        if self.preferences.mode == 'compact':
            self.repeats[key] = dict(event, first_epoch=epoch, last_epoch=epoch, count=0)
        self.emit(json.dumps(event, ensure_ascii=False, separators=(',', ':')))

    def flush_repeat(self, key):
        event = self.repeats.pop(key)
        if event['count']:
            event.update(epoch=event['last_epoch'], time=utc(event['last_epoch']),
                         count=event['count'], first_time=utc(event['first_epoch']), repeated=True)
            self.emit(json.dumps(event, ensure_ascii=False, separators=(',', ':')))

    def mapped(self, device, address, epoch):
        values = self.bindings.get((device, address), {})
        return [name for name, expiry in values.items() if expiry >= epoch][:8]

    @staticmethod
    def dns_key(packet, outgoing, ident):
        if outgoing:
            return packet['src'], packet['sport'], packet['dst'], packet['dport'], packet['proto'], ident
        return packet['dst'], packet['dport'], packet['src'], packet['sport'], packet['proto'], ident

    def dns(self, device, outgoing, packet, data, epoch):
        message = parse_dns(data)
        if message['response'] == outgoing:
            return
        key = (device, *self.dns_key(packet, outgoing, message['id']))
        if outgoing:
            previous = self.pending_dns.get(key)
            if previous and (previous['name'], previous['qtype']) == (message['name'], message['qtype']):
                previous['retries'] += 1
                return
            self.bounded(self.pending_dns, key, {'name': message['name'], 'qtype': message['qtype'],
                                                 'epoch': epoch, 'retries': 0, 'address': packet['dst']})
            self.record(device, 'dns_query', [message['name']], epoch, qtype=message['qtype'], address=packet['dst'])
            return
        previous = self.pending_dns.get(key)
        if (not previous or (previous['name'], previous['qtype']) != (message['name'], message['qtype'])
                or epoch - previous['epoch'] > DNS_TIMEOUT + 2):
            return
        del self.pending_dns[key]
        if message['truncated']:
            self.record(device, 'dns_truncated', [message['name']], epoch, qtype=message['qtype'],
                        address=packet['src'])
            return
        if message['rcode']:
            self.record(device, 'dns_error', [message['name']], epoch, rcode=message['rcode'],
                        qtype=message['qtype'], address=packet['src'], retries=previous['retries'])
            return
        names, addresses = dns_bindings(message)
        for name in names:
            item = self.domain(device, name, epoch)
            item['addresses'] = [dict(value, expires_at=utc(epoch + value['ttl'])) for value in addresses]
        for value in addresses:
            mapping_key = (device, value['address'])
            bindings = {name: expiry for name, expiry in self.bindings.get(mapping_key, {}).items() if expiry >= epoch}
            for name in names:
                bindings[name] = epoch + value['ttl']
            self.bounded(self.bindings, mapping_key, dict(list(bindings.items())[-8:]), MAX_DOMAINS)
        self.record(device, 'dns_ok' if addresses else 'dns_empty', names, epoch,
                    addresses=addresses, qtype=message['qtype'], retries=previous['retries'])

    def dns_tcp(self, device, outgoing, packet, epoch):
        data = packet['payload']
        key = (device, packet['src'], packet['sport'], packet['dst'], packet['dport'])
        if packet['flags'] & 7:
            self.streams.pop(key, None)
        if not data:
            return
        stream = self.streams.get(key)
        if stream:
            if packet['seq'] == stream['last_seq']:
                return
            if packet['seq'] != stream['next_seq']:
                self.streams.pop(key, None)
                self.health['capacity_drops'] += 1
                return
            stream['data'] += data
            stream.update(last_seq=packet['seq'], next_seq=(packet['seq'] + len(data)) & 0xffffffff, epoch=epoch)
        else:
            stream = {'data': data, 'last_seq': packet['seq'], 'next_seq': (packet['seq'] + len(data)) & 0xffffffff,
                      'epoch': epoch}
            self.bounded(self.streams, key, stream, MAX_STREAMS)
        if len(stream['data']) > MAX_DNS_BYTES + 2:
            self.streams.pop(key, None)
            self.health['capacity_drops'] += 1
            return
        for _ in range(4):
            data = stream['data']
            if len(data) < 2:
                return
            size = struct.unpack('!H', data[:2])[0]
            if not 12 <= size <= MAX_DNS_BYTES:
                self.streams.pop(key, None)
                raise ValueError('Invalid DNS TCP length')
            if len(data) < size + 2:
                return
            stream['data'] = data[size + 2:]
            self.dns(device, outgoing, packet, data[2:size + 2], epoch)
            if not stream['data']:
                return

    def tcp(self, device, outgoing, packet, epoch):
        flags = packet['flags']
        if outgoing:
            key = (device, packet['src'], packet['sport'], packet['dst'], packet['dport'])
        else:
            key = (device, packet['dst'], packet['dport'], packet['src'], packet['sport'])
        previous = self.pending_tcp.get(key)
        if outgoing and flags & 0x12 == 2:
            if previous and previous['seq'] == packet['seq']:
                previous['retries'] += 1
                return
            self.bounded(self.pending_tcp, key, {'seq': packet['seq'], 'epoch': epoch, 'retries': 0,
                                                'domains': self.mapped(device, packet['dst'], epoch)})
        elif not outgoing and previous and flags & 0x10 and packet['ack'] == (previous['seq'] + 1) & 0xffffffff:
            if flags & 4 or flags & 0x12 == 0x12:
                del self.pending_tcp[key]
                self.record(device, 'tcp_reset' if flags & 4 else 'tcp_ok',
                            previous['domains'] or self.mapped(device, packet['src'], epoch), epoch,
                            address=packet['src'], port=packet['sport'], retries=previous['retries'])
        if outgoing and packet['dport'] == 443 and packet['payload']:
            name = tls_name(packet['payload'])
            if name:
                if flags & 0x10 and not flags & 2:
                    self.pending_tcp.pop(key, None)
                self.record(device, 'tls_sni', [name], epoch, address=packet['dst'], port=443)
            elif packet['payload'][0] == 22:
                self.health['tls_visibility_limited'] += 1

    def unreachable(self, device, packet, epoch):
        data = packet['payload']
        if len(data) < 28 or data[0] != (3 if packet['proto'] == 1 else 1):
            return
        quoted = parse_ip(data[8:], quoted=True)
        if quoted is None or quoted.get('proto') not in (6, 17) or 'sport' not in quoted:
            return
        key = (device, quoted['src'], quoted['sport'], quoted['dst'], quoted['dport'])
        pending = self.pending_tcp.pop(key, None) if quoted['proto'] == 6 else None
        names = pending.get('domains', []) if pending else self.mapped(device, quoted['dst'], epoch)
        for dns_key, value in list(self.pending_dns.items()):
            if dns_key[:6] == (*key, quoted['proto']):
                names = list(dict.fromkeys(names + [value['name']]))[:8]
                del self.pending_dns[dns_key]
                pending = value
        if pending is not None:
            self.record(device, 'unreachable', names, epoch, address=quoted['dst'],
                        port=quoted['dport'], code=data[1])

    def feed(self, frame, epoch=None):
        epoch = time.time() if epoch is None else epoch
        self.health['packets'] += 1
        try:
            packet = parse_frame(frame)
            if packet is None:
                return
            device, outgoing = self.role(packet)
            if device is None:
                return
            if packet['proto'] in (6, 17) and 'sport' in packet:
                if (outgoing and packet['dport'] == 53) or (not outgoing and packet['sport'] == 53):
                    if packet['proto'] == 17:
                        self.dns(device, outgoing, packet, packet['payload'], epoch)
                    else:
                        self.dns_tcp(device, outgoing, packet, epoch)
                elif packet['proto'] == 6:
                    self.tcp(device, outgoing, packet, epoch)
            elif not outgoing and packet['proto'] in (1, 58):
                self.unreachable(device, packet, epoch)
        except (ValueError, UnicodeError, struct.error, KeyError, IndexError, TypeError):
            self.health['malformed'] += 1

    def tick(self, epoch=None, closing=False):
        epoch = time.time() if epoch is None else epoch
        for key, value in list(self.pending_dns.items()) if not closing else ():
            if epoch - value['epoch'] >= DNS_TIMEOUT:
                del self.pending_dns[key]
                self.record(key[0], 'dns_timeout', [value['name']], epoch, address=value['address'],
                            qtype=value['qtype'], retries=value['retries'], observation_only=True)
        for key, value in list(self.pending_tcp.items()) if not closing else ():
            if epoch - value['epoch'] >= TCP_TIMEOUT:
                del self.pending_tcp[key]
                self.record(key[0], 'tcp_timeout', value['domains'], epoch,
                            address=key[3], port=key[4], retries=value['retries'], observation_only=True)
        for key, value in list(self.streams.items()):
            if epoch - value['epoch'] >= DNS_TIMEOUT:
                del self.streams[key]
        for key, value in list(self.bindings.items()):
            if all(expiry < epoch for expiry in value.values()):
                del self.bindings[key]
        for key, value in list(self.repeats.items()):
            if closing or epoch - value['first_epoch'] >= 60 or self.preferences.mode == 'verbose':
                self.flush_repeat(key)

    def report(self, epoch=None):
        epoch = time.time() if epoch is None else epoch
        items = []
        for item in reversed(self.domains.values()):
            value = {key: item[key] for key in ('device', 'domain', 'first_epoch', 'last_epoch', 'first_seen',
                                               'last_seen', 'counts', 'addresses', 'last_problem')}
            value['counts'], value['addresses'] = dict(item['counts']), list(item['addresses'])
            value.update(domain_info(item['domain']))
            value['new_since_tag'] = bool(self.preferences.tag and item['first_epoch'] >= self.preferences.tag_since)
            items.append(value)
        return {'time': utc(epoch), 'epoch': epoch, 'started_at': utc(self.started), 'domains': items,
                'recent': event_context(list(self.recent)), 'health': dict(self.health),
                'pending_dns': len(self.pending_dns), 'pending_tcp': len(self.pending_tcp),
                'mode': self.preferences.mode, 'tag': self.preferences.tag, 'limit': OBSERVATION_LIMIT,
                'coverage_start': (self.recent[0]['epoch'] if self.health['history_drops'] and self.recent
                                   else self.started)}

    def inventory(self):
        # TTL bindings belong to the current capture session. Persist the durable
        # domain inventory; failure files retain the relevant resolution evidence.
        return {'version': 1, 'domains': [dict(item, counts=dict(item['counts']), addresses=[])
                                          for item in self.domains.values()]}
