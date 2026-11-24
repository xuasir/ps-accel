"""Local log preferences and bounded failure history, independent of relay locks."""
from dataclasses import asdict, dataclass
from bisect import bisect_right
import datetime
import json
import math
import os
from pathlib import Path
import re
import time
import uuid

MAX_INCIDENTS = 32
MAX_INCIDENT_BYTES = 65536
WINDOW_BEFORE = 180
WINDOW_AFTER = 15
OBSERVATION_LIMIT = ('仅记录已配对设备的可见 DNS、TCP 建连与 TLS 域名。'
                     '超时表示观测窗口内未收到响应；共享 IP 对应多个候选域名。'
                     '加密 DNS、TLS ECH、分段 ClientHello 与硬件加速可能影响覆盖，'
                     'HTTPS 内部业务错误需结合设备提示确认。')


def utc(epoch=None):
    return datetime.datetime.fromtimestamp(time.time() if epoch is None else epoch,
                                          datetime.timezone.utc).isoformat()


def read_bounded(path, limit=1048576):
    with Path(path).open('rb') as source:
        value = source.read(limit + 1)
    if len(value) > limit:
        raise ValueError('记录超过读取上限')
    return json.loads(value)


def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('x', encoding='utf-8') as output:
            os.chmod(temporary, 0o600)
            json.dump(value, output, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
            output.write('\n')
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


@dataclass(frozen=True)
class LogPreferences:
    mode: str = 'compact'
    domains: bool = True
    tag: str = ''
    tag_since: float = 0

    @property
    def snapshot_interval(self):
        return 10 if self.mode == 'compact' else 2

    def validate(self):
        if self.mode not in ('compact', 'verbose') or type(self.domains) is not bool:
            raise ValueError('请选择简洁或详细日志模式，并设置域名记录开关')
        if (not isinstance(self.tag, str) or len(self.tag) > 64
                or any(ord(character) < 32 or ord(character) == 127 for character in self.tag)):
            raise ValueError('排查标记最长 64 字，使用单行文本')
        if (type(self.tag_since) not in (float, int) or not math.isfinite(self.tag_since)
                or self.tag_since < 0):
            raise ValueError('排查标记时间无效')
        return self


def load_preferences(path):
    try:
        value = read_bounded(path, 16384)
    except FileNotFoundError:
        return LogPreferences()
    if not isinstance(value, dict) or set(value) != set(LogPreferences.__dataclass_fields__):
        raise ValueError('日志偏好文件格式无效')
    return LogPreferences(**value).validate()


def save_preferences(path, mode, domains, tag):
    try:
        previous = load_preferences(path)
    except (OSError, ValueError, TypeError):
        previous = LogPreferences()
    value = LogPreferences(mode, domains, tag.strip(),
                           time.time() if tag.strip() != previous.tag else previous.tag_since).validate()
    atomic_json(path, asdict(value))
    return value


class PreferenceCache:
    """Refresh only from a diagnostics worker; callers read an immutable value."""
    def __init__(self, path=None):
        self.path = Path(path) if path is not None else None
        self.value = LogPreferences(domains=self.path is None)
        self.initialized = self.path is None
        self.last_error = ''

    def refresh(self):
        if self.path is None:
            return False
        try:
            value = load_preferences(self.path)
            changed = value != self.value
            self.value, self.last_error = value, ''
            self.initialized = True
            return changed
        except (OSError, ValueError, TypeError) as exc:
            self.last_error = str(exc)[:300]
            return False


def new_incident(source, note, tag='', job_id='', epoch=None):
    stamp = time.time() if epoch is None else float(epoch)
    return {'id': uuid.uuid4().hex, 'source': source[:32], 'note': str(note)[:500],
            'tag': str(tag)[:64], 'job_id': str(job_id)[:32], 'epoch': stamp,
            'time': utc(stamp), 'window_before': WINDOW_BEFORE, 'window_after': WINDOW_AFTER}


def save_incident(persist, incident):
    if not re.fullmatch('[0-9a-f]{32}', incident.get('id', '')):
        raise ValueError('失败记录标识无效')
    incident = dict(incident)
    if isinstance(incident.get('evidence'), dict):
        evidence = dict(incident['evidence'])
        for key in ('events', 'candidates'):
            evidence[key] = list(evidence.get(key, [])) if isinstance(evidence.get(key), list) else []
        incident['evidence'] = evidence
        while len(json.dumps(incident, ensure_ascii=False, allow_nan=False).encode()) > 60000:
            if evidence['events']:
                # Preserve error details ahead of routine context when shrinking.
                index = next((i for i, item in enumerate(evidence['events']) if not item.get('problem')), 0)
                evidence['events'].pop(index)
            elif evidence['candidates']:
                evidence['candidates'].pop()
            else:
                break
            evidence['truncated'] = True
    data = json.dumps(incident, ensure_ascii=False, allow_nan=False).encode()
    if len(data) > MAX_INCIDENT_BYTES:
        raise ValueError('失败证据超过保存上限')
    folder = Path(persist) / 'incidents'
    atomic_json(folder / (incident['id'] + '.json'), incident)
    files = []
    for item in folder.glob('*.json'):
        try:
            files.append((item.stat().st_mtime_ns, item))
        except FileNotFoundError:
            continue
    for _, item in sorted(files, reverse=True)[MAX_INCIDENTS:]:
        item.unlink(missing_ok=True)
    return incident


def read_incidents(persist):
    items = []
    folder = Path(persist) / 'incidents'
    for path in sorted(folder.glob('*.json'), reverse=True)[:MAX_INCIDENTS * 2]:
        try:
            value = read_bounded(path, MAX_INCIDENT_BYTES)
            if (isinstance(value, dict) and re.fullmatch('[0-9a-f]{32}', value.get('id', ''))
                    and type(value.get('epoch')) in (int, float) and math.isfinite(value['epoch'])):
                if 'evidence' in value and not isinstance(value['evidence'], dict):
                    value.pop('evidence')
                items.append(value)
        except (OSError, ValueError, TypeError):
            continue
    return sorted(items, key=lambda item: item['epoch'], reverse=True)[:MAX_INCIDENTS]


def record_failure(runtime, persist, source, note, job_id=''):
    """Best-effort background persistence after a management action has ended."""
    from telemetry import Telemetry
    try:
        try:
            preferences = load_preferences(Path(persist) / 'observability.json')
        except (OSError, ValueError, TypeError):
            preferences = LogPreferences()
        recorder = Telemetry(runtime, persist=persist)
        recorder.incident(new_incident(source, note, preferences.tag, job_id))
        recorder.close(timeout=.2)
    except Exception:
        pass


def read_domain_events(runtime):
    items = []
    # Files rotate at 256 KiB. Bound reads even after manual file replacement.
    for suffix in ('.2', '.1', ''):
        path = Path(runtime) / ('domains.jsonl' + suffix)
        try:
            with path.open('rb') as source:
                data = source.read(262145)
            if len(data) > 262144:
                continue
            for line in data.splitlines():
                try:
                    value = json.loads(line)
                    if isinstance(value, dict) and type(value.get('epoch')) in (int, float):
                        items.append(value)
                except (ValueError, TypeError):
                    continue
        except OSError:
            continue
    return items[-2048:]


def merge_events(*sources):
    items, seen = [], set()
    for source in sources:
        if not isinstance(source, (list, tuple)):
            continue
        for item in source:
            if (not isinstance(item, dict) or type(item.get('epoch')) not in (int, float)
                    or not math.isfinite(item['epoch'])):
                continue
            try:
                key = json.dumps(item, sort_keys=True, ensure_ascii=False, allow_nan=False)
            except (ValueError, TypeError):
                continue
            if key not in seen:
                items.append(item)
                seen.add(key)
    items = sorted(items, key=lambda item: item['epoch'])[-2560:]
    samples = {}
    for item in items:
        if not item.get('repeated'):
            try:
                samples.setdefault(event_key(item), []).append(item['epoch'])
            except (KeyError, TypeError):
                continue
    merged = []
    for item in items:
        if item.get('repeated'):
            first, last, count = item.get('first_epoch'), item.get('last_epoch'), item.get('count')
            if (type(first) in (int, float) and type(last) in (int, float)
                    and math.isfinite(first) and math.isfinite(last) and first <= last
                    and type(count) is int and 0 < count <= 1000000):
                try:
                    epochs = samples.get(event_key(item), [])
                except (KeyError, TypeError):
                    epochs = []
                # A compact summary counts additional occurrences after its
                # first event. Detailed memory samples already cover some or all
                # of those occurrences, so retain only the missing count.
                covered = bisect_right(epochs, last) - bisect_right(epochs, first)
                if covered >= count:
                    continue
                if covered:
                    item = dict(item, count=count - covered)
        merged.append(item)
    return merged


def event_key(item):
    return (item['device'], item['kind'], tuple(item['domains']), item.get('tag', ''),
            item.get('address'), item.get('port'), item.get('rcode'), item.get('qtype'), item.get('code'))


def event_context(events, limit=80):
    """Keep recent error details ahead of routine context within a fixed budget."""
    if len(events) <= limit:
        return list(events)
    problems = [item for item in events if item.get('problem')][-limit:]
    remaining = limit - len(problems)
    context = [item for item in events if not item.get('problem')][-remaining:] if remaining else []
    return sorted(problems + context, key=lambda item: item['epoch'])


def correlate(incident, events):
    start, end = incident['epoch'] - WINDOW_BEFORE, incident['epoch'] + WINDOW_AFTER
    relevant = []
    for item in events:
        if (isinstance(item, dict) and type(item.get('epoch')) in (int, float)
                and start <= item['epoch'] <= end and item.get('device') in ('ps5', 'portal')
                and isinstance(item.get('domains'), list) and isinstance(item.get('kind'), str)):
            relevant.append(item)
    candidates = {}
    for item in relevant:
        for domain in item.get('domains', [])[:8]:
            if not isinstance(domain, str) or len(domain) > 253:
                continue
            key = (item.get('device', ''), domain)
            candidate = candidates.setdefault(key, {'device': key[0], 'domain': domain,
                                                    'evidence': [], 'errors': 0, 'last_seen': item.get('time')})
            kind = item.get('kind', '')
            if kind not in candidate['evidence']:
                candidate['evidence'].append(kind)
            if item.get('problem'):
                count = item.get('count', 1)
                candidate['errors'] += count if type(count) is int and 0 < count <= 1000000 else 1
            candidate['last_seen'] = item.get('time')
    ordered = sorted(candidates.values(), key=lambda item: (-item['errors'], item['domain']))[:64]
    return {'candidates': ordered, 'events': event_context(relevant),
            'truncated': len(relevant) > 80,
            'event_count': len(relevant), 'evidence_complete': time.time() >= end,
            'limit': OBSERVATION_LIMIT}
