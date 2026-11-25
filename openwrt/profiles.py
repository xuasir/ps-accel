"""Fixed, same-length LaunchSpec requests shared by the CLI and LuCI."""

APP_VERSION = '0.1.8'

PROFILE_INFO = {
    '35': {'request': b'35000', 'label': '35 Mbps', 'description': '轻量 · 优先留出无线余量'},
    '45': {'request': b'45000', 'label': '45 Mbps', 'description': '均衡 · 逐步提升画质'},
    '65': {'request': b'65000', 'label': '65 Mbps', 'description': '推荐 · 已有方案的起点'},
    '100': {'request': b'1e+05', 'label': '100 Mbps', 'description': '高清 · 适合余量充足的链路'},
    '200': {'request': b'2e+05', 'label': '200 Mbps', 'description': '实验 · 建议逐档验证'},
}

# Trim only trailing zero deltas; keep every changed byte at the original offset.
PROFILES = {key: bytes(a ^ b for a, b in zip(b'25000', info['request'])).rstrip(b'\0')
            for key, info in PROFILE_INFO.items()}


def public_profiles():
    return [{'value': key, 'label': info['label'], 'description': info['description'],
             'target_mbps': int(key), 'experimental': key == '200'}
            for key, info in PROFILE_INFO.items()]
