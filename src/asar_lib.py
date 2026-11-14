"""标准 ASAR 读写与完整性校验；数据基址为 8 + headerSize。"""
import hashlib
import json
import os
import struct

BLOCK_SIZE = 4 * 1024 * 1024


def parse(path):
    """返回 (header, data_offset, file_size)，拒绝异常或截断的头部。"""
    size = os.path.getsize(path)
    with open(path, 'rb') as f:
        head = f.read(16)
        if len(head) != 16:
            raise ValueError('ASAR 头部不足 16 字节')
        a, b, c, d = struct.unpack('<IIII', head)
        aligned = (d + 3) & ~3
        if a != 4 or b != 8 + aligned or c != 4 + aligned:
            raise ValueError('ASAR 头部长度字段不一致')
        if not d or d > 512 * 1024 * 1024 or 8 + b > size:
            raise ValueError('ASAR 头部长度异常或内容截断')
        raw = f.read(d)
        if len(raw) != d:
            raise ValueError('ASAR JSON 头部截断')
        header = json.loads(raw.decode('utf-8'))
        if not isinstance(header, dict) or not isinstance(header.get('files'), dict):
            raise ValueError('ASAR 文件树无效')
    return header, 8 + b, size


def header_is_wellformed(path):
    try:
        parse(path)
        return []
    except Exception as exc:
        return [str(exc)]


def _parts(path):
    if not isinstance(path, str) or not path.startswith('/'):
        raise ValueError('ASAR 路径必须从根目录开始: %r' % path)
    parts = path[1:].split('/')
    if any(not p or p in ('.', '..') or any(c in p for c in '\\:\x00') for p in parts):
        raise ValueError('不安全的 ASAR 路径: %r' % path)
    return parts


def walk_files(node, prefix=''):
    """枚举文件，同时验证目录树和路径组件，拒绝路径穿越。"""
    if not isinstance(node, dict) or not isinstance(node.get('files'), dict):
        raise ValueError('ASAR 目录节点无效: %s' % prefix)
    for name, child in node['files'].items():
        if not isinstance(name, str) or '/' in name:
            raise ValueError('ASAR 文件名无效: %r' % name)
        path = prefix + '/' + name
        _parts(path)
        if not isinstance(child, dict):
            raise ValueError('ASAR 文件节点无效: %s' % path)
        if 'files' in child:
            yield from walk_files(child, path)
        else:
            yield path, child


def _bounds(node, base, size):
    off, length = node.get('offset'), node.get('size')
    if isinstance(off, bool) or not (isinstance(off, int) or isinstance(off, str) and off.isdigit()):
        raise ValueError('文件 offset 无效')
    if isinstance(length, bool) or not isinstance(length, int):
        raise ValueError('文件 size 无效')
    off = int(off)
    if off < 0 or length < 0 or off > size - base or length > size - base - off:
        raise ValueError('文件偏移为负或超出 ASAR 边界')
    return base + off, length


def _local_path(root, path):
    root = os.path.realpath(root)
    target = os.path.realpath(os.path.join(root, *_parts(path)))
    if os.path.commonpath([root, target]) != root or target == root:
        raise ValueError('文件路径越界: %s' % path)
    return target


def extract(asar_path, dest_dir, unpacked_dir=None):
    header, base, size = parse(asar_path)
    unpacked_dir = unpacked_dir or asar_path + '.unpacked'
    entries = list(walk_files(header))
    # 先验证所有路径与边界，避免处理到恶意条目前已经写出部分内容。
    for path, node in entries:
        _local_path(dest_dir, path)
        if node.get('unpacked'):
            _local_path(unpacked_dir, path)
        elif 'link' not in node:
            _bounds(node, base, size)
    count = 0
    with open(asar_path, 'rb') as archive:
        for path, node in entries:
            if 'link' in node:
                continue
            out = _local_path(dest_dir, path)
            if node.get('unpacked'):
                src = _local_path(unpacked_dir, path)
                if not os.path.isfile(src):
                    continue
                with open(src, 'rb') as f:
                    data = f.read()
            else:
                off, length = _bounds(node, base, size)
                archive.seek(off)
                data = archive.read(length)
                if len(data) != length:
                    raise ValueError('文件内容截断: %s' % path)
                count += 1
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, 'wb') as f:
                f.write(data)
    return header, count


def _sha256_blocks(data, block_size=BLOCK_SIZE):
    if isinstance(block_size, bool) or not isinstance(block_size, int) or block_size <= 0:
        raise ValueError('integrity blockSize 必须为正整数')
    return [hashlib.sha256(data[i:i + block_size]).hexdigest()
            for i in range(0, max(len(data), 1), block_size)]


def build(orig_asar, out_asar, edits, new_files, unpacked_src=None):
    """保持原始数据与未修改节点，仅追加改动文件，并重算完整 SHA256。"""
    header, base, size = parse(orig_asar)
    entries = dict(walk_files(header))
    for node in entries.values():
        if not node.get('unpacked') and 'link' not in node:
            _bounds(node, base, size)
    if os.path.abspath(orig_asar) == os.path.abspath(out_asar):
        raise ValueError('输出路径不能覆盖输入 ASAR')
    if set(edits) & set(new_files):
        raise ValueError('同一路径不能同时属于 edits 与 new_files')
    with open(orig_asar, 'rb') as f:
        f.seek(base)
        payload = f.read()
    pending = []
    offset = len(payload)
    for path, data in list(edits.items()) + list(new_files.items()):
        parts = _parts(path)
        if not isinstance(data, bytes):
            raise ValueError('文件内容必须为 bytes: %s' % path)
        if path in edits and path not in entries:
            raise ValueError('修改目标不存在: %s' % path)
        parent = header
        for part in parts[:-1]:
            child = parent['files'].setdefault(part, {'files': {}})
            if 'files' not in child:
                raise ValueError('父路径不是目录: %s' % path)
            parent = child
        node = parent['files'].get(parts[-1])
        if node is not None and ('files' in node or node.get('unpacked') or 'link' in node):
            raise ValueError('不能覆盖目录、unpacked 或 link: %s' % path)
        parent['files'][parts[-1]] = {
            'size': len(data), 'offset': str(offset),
            'integrity': {
                'algorithm': 'SHA256', 'hash': hashlib.sha256(data).hexdigest(),
                'blockSize': BLOCK_SIZE, 'blocks': _sha256_blocks(data),
            },
        }
        pending.append(data)
        offset += len(data)
    raw = json.dumps(header, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    aligned = (len(raw) + 3) & ~3
    tmp = out_asar + '.tmp'
    if os.path.exists(out_asar) or os.path.exists(tmp):
        raise ValueError('输出或临时文件已存在，拒绝覆盖: %s' % out_asar)
    try:
        with open(tmp, 'xb') as f:
            f.write(struct.pack('<IIII', 4, 8 + aligned, 4 + aligned, len(raw)))
            f.write(raw)
            f.write(b'\x00' * (aligned - len(raw)))
            f.write(payload)
            for data in pending:
                f.write(data)
        os.replace(tmp, out_asar)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    return header


def validate(asar_path, unpacked_dir=None, expect_main=None):
    """验证全部 packed 文件边界、整体及分块哈希，以及入口和 unpacked 文件。"""
    try:
        header, base, size = parse(asar_path)
        files = dict(walk_files(header))
    except Exception as exc:
        return ['ASAR 头部或目录树不可读: %s' % exc]
    problems = []
    unpacked_dir = unpacked_dir or asar_path + '.unpacked'
    contents = {}
    with open(asar_path, 'rb') as archive:
        for path, node in files.items():
            try:
                if node.get('unpacked'):
                    if not os.path.isfile(_local_path(unpacked_dir, path)):
                        problems.append('unpacked 文件缺失: %s' % path)
                    continue
                if 'link' in node:
                    _parts('/' + str(node['link']).lstrip('/'))
                    continue
                off, length = _bounds(node, base, size)
                archive.seek(off)
                data = archive.read(length)
                if len(data) != length:
                    raise ValueError('文件内容截断')
                integrity = node.get('integrity')
                if not isinstance(integrity, dict) or integrity.get('algorithm') != 'SHA256':
                    raise ValueError('缺少 SHA256 完整性元数据')
                if integrity.get('hash') != hashlib.sha256(data).hexdigest():
                    raise ValueError('整体 SHA256 不一致')
                blocks = _sha256_blocks(data, integrity.get('blockSize'))
                if integrity.get('blocks') != blocks:
                    raise ValueError('分块 SHA256 不一致')
                if path == '/package.json':
                    contents[path] = data
            except Exception as exc:
                problems.append('%s: %s' % (path, exc))
    try:
        meta = json.loads(contents['/package.json'].decode('utf-8'))
        main = meta.get('main')
        if not isinstance(main, str) or not main:
            raise ValueError('缺少 main 入口')
        main_path = '/' + main.replace('\\', '/').lstrip('/')
        _parts(main_path)
        if expect_main and main != expect_main:
            problems.append('package.json main=%r，预期 %r' % (main, expect_main))
        if main_path not in files or files[main_path].get('unpacked') or 'link' in files[main_path]:
            problems.append('main 入口不存在或不是 packed 文件: %s' % main_path)
    except Exception as exc:
        problems.append('package.json 无法读取或入口无效: %s' % exc)
    return problems
