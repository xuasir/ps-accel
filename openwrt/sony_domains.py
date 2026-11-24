"""Sony categories and dynamic routing patterns shared with PS-Portal-Relay."""
import ipaddress
import re

AUTH_HOSTS = (
    'auth.api.sonyentertainmentnetwork.com', 'account.sonyentertainmentnetwork.com',
    'accounts.sonyentertainmentnetwork.com', 'signin.api.sonyentertainmentnetwork.com',
    'auth.api.playstation.com', 'ca.account.sony.com', 'np.ac.playstation.net',
)
SIGNALING_HOSTS = ('remoteplay.dl.playstation.net', 'remoteplay.prod.dl.playstation.net')
CONNECTIVITY_HOSTS = ('google.com', 'www.google.com')
FIRMWARE_HOST = 'dwc.dl.playstation.net'
CATEGORY_NAMES = {'auth': '认证', 'signaling': '信令', 'api': 'Sony API', 'misc': '其他'}
DYNAMIC_AUTH_RULES = ('*.auth.np.ac.playstation.net',)
DYNAMIC_SIGNALING_RULES = (
    '*.np.communication.playstation.net', 'gsconnect.*',
    '*.gsconnect.playstation.net', '*signaling*', '*.remoteplay.playstation.net',
)
DYNAMIC_PROXY_RULES = DYNAMIC_AUTH_RULES + DYNAMIC_SIGNALING_RULES


def domain_rules(text):
    if not isinstance(text, str) or len(text) > 8192:
        raise ValueError('域名列表限 8192 字符')
    result = []
    for line in text.splitlines():
        name = line.strip().lower()
        if not name or name.startswith('#'):
            continue
        full = name.startswith('full:')
        if full:
            name = name[5:]
        host = name[2:] if name.startswith('*.') and not full else name
        if (len(name) > 253 or '.' not in host or
                any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part)
                    for part in host.split('.'))):
            raise ValueError('每行填写完整主机名或 *.example.com；支持 full: 完整主机名前缀')
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError('目标列表使用主机名或子域名匹配规则')
        if name not in result:
            result.append(name)
    if len(result) > 32:
        raise ValueError('每份列表最多 32 条域名规则')
    return result


def matches_domain(host, rules):
    host = host.lower().rstrip('.')
    return bool(host) and any(re.fullmatch(re.escape(rule).replace(r'\*', '.*'), host)
                              for rule in rules)


def proxy_rules(config):
    return list(dict.fromkeys(domain_rules(config.get('domains', '')) + list(DYNAMIC_PROXY_RULES)))


def rule_excluded(rule, exclusions):
    """Report complete exclusion; a wildcard may also have individual exceptions."""
    return any(rule == exclusion or (exclusion.startswith('*.') and rule.endswith(exclusion[1:]))
               or ('*' not in rule and matches_domain(rule, [exclusion])) for exclusion in exclusions)


def domain_matcher(rules):
    """Sing-box combines its domain fields with OR, inside the scoped AND rule."""
    result = {}
    for rule in rules:
        if rule.startswith('*.'):
            key, value = 'domain_suffix', rule[1:]
        elif rule == 'gsconnect.*':
            key, value = 'domain_regex', r'^gsconnect\.'
        elif rule == '*signaling*':
            key, value = 'domain_keyword', 'signaling'
        else:
            key, value = 'domain', rule
        values = result.setdefault(key, [])
        if value not in values:
            values.append(value)
    return result


def dynamic_rule_info():
    return [dict(domain=rule, builtin=True, category=category, category_label=CATEGORY_NAMES[category])
            for category, rules in (('auth', DYNAMIC_AUTH_RULES), ('signaling', DYNAMIC_SIGNALING_RULES))
            for rule in rules]


def classify_sony_domain(host):
    h = host.lower().rstrip('.')
    if h in CONNECTIVITY_HOSTS:
        return 'api'
    if h in AUTH_HOSTS or matches_domain(h, DYNAMIC_AUTH_RULES):
        return 'auth'
    if h in SIGNALING_HOSTS or matches_domain(h, DYNAMIC_SIGNALING_RULES):
        return 'signaling'
    if h.endswith(('.playstation.net', '.playstation.com', '.sonyentertainmentnetwork.com',
                   '.sony.com', '.sonyinteractive.com')):
        return 'api'
    return 'misc'


def domain_info(host):
    host = host.lower().rstrip('.')
    category = classify_sony_domain(host)
    purpose = 'connectivity' if host in CONNECTIVITY_HOSTS else 'firmware' if host == FIRMWARE_HOST else category
    return {'category': category, 'category_label': {'connectivity': '连通探测', 'firmware': '固件下载'}.get(
                purpose, CATEGORY_NAMES[category]), 'purpose': purpose,
            'suggestion': 'proxy' if purpose in ('auth', 'signaling', 'connectivity') else
                          'direct' if purpose == 'firmware' else 'review'}


def candidates(rows, config):
    included = proxy_rules(config)
    excluded = domain_rules(config.get('exclusions', ''))
    result, seen = [], set()
    for row in rows:
        host = row.get('domain', '')
        info = domain_info(host)
        if host and host not in seen and info['suggestion'] == 'proxy':
            seen.add(host)
            result.append(dict(domain=host, device=row.get('device', ''), **info,
                               included=matches_domain(host, included), excluded=matches_domain(host, excluded)))
    for host in CONNECTIVITY_HOSTS:
        if host not in seen:
            result.append(dict(domain=host, device='', **domain_info(host),
                               included=matches_domain(host, included), excluded=matches_domain(host, excluded)))
    return result[:64]
