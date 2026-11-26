"""Bounded UCI snapshots and isolated edits of PassWall-owned configuration."""
import hashlib
from pathlib import Path
import re
import shlex
import stat
import subprocess
import tempfile

import portal_openwrt as port

CONFIG = Path('/etc/config/passwall')
BINARY = 'uci'
SAVEDIR = None
MAX_CONFIG = 4 * 1024 * 1024
IDENTIFIER = re.compile(r'[a-zA-Z0-9_][a-zA-Z0-9_-]{0,63}')


def command(*args, directory=None, savedir=None, input=None):
    argv = [BINARY, '-q', '-c', str(directory if directory is not None else CONFIG.parent)]
    if directory is not None:
        argv += ['-t', str(savedir)]
    elif SAVEDIR is not None:
        argv += ['-t', str(SAVEDIR)]
    argv += list(args)
    result = subprocess.run(argv, input=input, text=True, capture_output=True, timeout=8, check=False)
    if result.returncode:
        raise RuntimeError('PassWall UCI 配置读取或校验失败，请检查本机配置')
    if len(result.stdout.encode('utf-8')) > MAX_CONFIG * 3:
        raise ValueError('PassWall UCI 配置超过容量限制')
    return result.stdout


def parse(text):
    """uci show quotes multiline strings and emits list members as extra words."""
    lexer = shlex.shlex(text, posix=True)
    lexer.whitespace_split = True
    lexer.commenters = ''
    sections, previous = {}, None
    for token in lexer:
        key, separator, value = token.partition('=')
        if separator and key.startswith('passwall.'):
            parts = key.split('.', 2)
            section = sections.setdefault(parts[1], {})
            field = parts[2] if len(parts) == 3 else '.type'
            section[field] = value
            previous = (section, field) if len(parts) == 3 else None
        elif previous:
            section, field = previous
            values = section[field]
            section[field] = values + [token] if isinstance(values, list) else [values, token]
    return sections


def snapshot():
    path = CONFIG.resolve()
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CONFIG:
        raise ValueError('PassWall 配置文件容量或类型需要检查')
    data = path.read_bytes()
    if len(data) > MAX_CONFIG:
        raise ValueError('PassWall 配置超过 4 MiB')
    sections = parse(command('-X', 'show', 'passwall'))
    pending = command('changes', 'passwall')
    if path.read_bytes() != data:
        raise RuntimeError('PassWall 配置正在更新，请重新读取')
    return {'path': path, 'data': data, 'mode': stat.S_IMODE(info.st_mode), 'sections': sections,
            'pending': bool(pending), 'digest': hashlib.sha256(data + b'\0' + pending.encode()).hexdigest()}


def global_section(sections):
    item = next(((name, row) for name, row in sections.items() if row.get('.type') == 'global'), None)
    if item is None:
        raise RuntimeError('PassWall 全局配置待就绪，请在 PassWall 保存配置后重新读取')
    return item


def scalar(value, default=''):
    return value if isinstance(value, str) else default


def canonical(row):
    return {key: value[0] if isinstance(value, list) and len(value) == 1 else value for key, value in row.items()}


def stage(before, replacements, global_changes=None, first_acl=None):
    """Use libuci in a private copy, then return its validated configuration bytes."""
    if before['pending']:
        raise RuntimeError('PassWall 有待保存配置，请先在 PassWall 保存或撤销后应用设备规则')
    commands = []
    for name in replacements:
        if not IDENTIFIER.fullmatch(name):
            raise ValueError('设备访问控制标识无效')
        if name in before['sections']:
            commands.append('delete passwall.' + name)
    for name, row in replacements.items():
        if row is None:
            continue
        commands.append('set passwall.' + name + '=' + shlex.quote(row['.type']))
        for field, value in row.items():
            if field == '.type':
                continue
            if not IDENTIFIER.fullmatch(field):
                raise ValueError('设备分流字段无效')
            if isinstance(value, list):
                for member in value:
                    commands.append('add_list passwall.' + name + '.' + field + '=' + shlex.quote(member))
            else:
                commands.append('set passwall.' + name + '.' + field + '=' + shlex.quote(value))
    if global_changes:
        name, _row = global_section(before['sections'])
        if not IDENTIFIER.fullmatch(name):
            raise ValueError('PassWall 全局配置标识无效')
        for field, value in global_changes.items():
            if field != 'acl_enable':
                raise ValueError('设备接管只调整访问控制总开关')
            if value is None:
                commands.append('delete passwall.' + name + '.' + field)
            else:
                commands.append('set passwall.' + name + '.' + field + '=' + shlex.quote(value))
    if first_acl:
        # Keep all existing ACLs in relative order; put this group's ACL first.
        remaining = [(name, row) for name, row in before['sections'].items() if name not in replacements]
        index = next((i for i, (_name, row) in enumerate(remaining) if row.get('.type') == 'acl_rule'), None)
        if index is not None:
            commands.append('reorder passwall.' + first_acl + '=' + str(index))
    port.RUNTIME.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix='passwall-uci-', dir=port.RUNTIME) as temporary:
        root = Path(temporary)
        directory, savedir = root / 'config', root / 'delta'
        directory.mkdir(mode=0o700)
        savedir.mkdir(mode=0o700)
        path = directory / 'passwall'
        path.write_bytes(before['data'])
        path.chmod(0o600)
        command('batch', directory=directory, savedir=savedir, input='\n'.join(commands) + '\n')
        command('commit', 'passwall', directory=directory, savedir=savedir)
        after = parse(command('-X', 'show', 'passwall', directory=directory, savedir=savedir))
        for name, wanted in replacements.items():
            actual = after.get(name)
            if (wanted is None and actual is not None) or (wanted is not None and canonical(wanted) != actual):
                raise RuntimeError('设备访问控制或分流规则校验失败')
        for name, row in before['sections'].items():
            if name not in replacements and row.get('.type') in ('nodes', 'shunt_rules') and after.get(name) != row:
                raise RuntimeError('本机节点或分流规则使用了会变化的标识，请在 PassWall 整理具名配置后应用')
        data = path.read_bytes()
        if len(data) > MAX_CONFIG:
            raise ValueError('设备规则写入后 PassWall 配置超过 4 MiB')
        return data
