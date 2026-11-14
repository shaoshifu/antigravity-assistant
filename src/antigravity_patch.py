"""Antigravity 捕获补丁：严格识别已验证调用结构，验证后原子替换 ASAR。"""
import hashlib
import json
import os
import posixpath
import re
import shutil
import subprocess
import sys
import time
import uuid

import asar_lib

TOOL_VERSION = '1.3.1'
INTERCEPTOR_REL = '/dist/urlInterceptor.js'
MAIN_INJECT = (
    b'"use strict";\n'
    b'process.env.ANTIGRAVITY_VSCODE_HOST = "1";\n'
    b'require("./urlInterceptor");\n'
)
LEGACY_SITES = (
    ('/dist/utils.js', b'void electron_1.shell.openExternal(details.url);',
     b'void require("./urlInterceptor").handleCapturedUrl(details.url, "utils");'),
    ('/dist/ipcHandlers.js', b'await electron_1.shell.openExternal(url);',
     b'await require("./urlInterceptor").handleCapturedUrl(url, "ipc");'),
    ('/dist/languageServer.js', b'void electron_1.shell.openExternal(openUrl);',
     b'void require("./urlInterceptor").handleCapturedUrl(openUrl, "languageServer");'),
)
SAFE_SITES = (
    ('/dist/externalUrl.js', b'await electron_1.shell.openExternal(parsed.href);',
     b'await require("./urlInterceptor").handleCapturedUrl(parsed.href, "externalUrl");'),
    LEGACY_SITES[-1],
)
SAFE_CALLS = (
    ('/dist/utils.js', b'const externalUrl_1 = require("./externalUrl");'),
    ('/dist/utils.js', b"void (0, externalUrl_1.openExternalSafely)(event.url, 'unconfirmed');"),
    ('/dist/utils.js', b"void (0, externalUrl_1.openExternalSafely)(details.url, 'unconfirmed');"),
    ('/dist/ipcHandlers.js', b'const externalUrl_1 = require("./externalUrl");'),
    ('/dist/ipcHandlers.js', b"await (0, externalUrl_1.openExternalSafely)(url, 'confirmed');"),
)
SAFE_GATE = (
    b'async function openExternalSafely(url, policy) {\n'
    b'    const parsed = parseUrl(url);\n'
    b"    const scheme = parsed ? parsed.protocol.slice(0, -1) : '<invalid>';\n"
    b"    if (!parsed || classifyParsedExternalUrl(parsed, policy) !== 'allow') {\n"
    b'        console.warn(`[externalUrl] Blocked external URL with scheme "${scheme}"`);\n'
    b'        return;\n'
    b'    }\n'
    b'    try {\n'
    b'        '
)


class PatchError(Exception):
    pass


def resource_path(name):
    base = getattr(sys, '_MEIPASS', None) or os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, name)


def paths():
    local = os.environ.get('LOCALAPPDATA') or os.path.join(os.path.expanduser('~'), 'AppData', 'Local')
    roaming = os.environ.get('APPDATA') or os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming')
    res = os.path.join(local, 'Programs', 'antigravity', 'resources')
    return {
        'resources': res, 'asar': os.path.join(res, 'app.asar'),
        'backup': os.path.join(res, 'app.asar.backup'),
        'unpacked': os.path.join(res, 'app.asar.unpacked'),
        'exe': os.path.join(local, 'Programs', 'antigravity', 'Antigravity.exe'),
        'userdata': os.path.join(roaming, 'Antigravity'),
    }


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def read_json(path, default=None):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return default


def write_json(path, data):
    tmp = path + '.tmp.' + uuid.uuid4().hex
    created = False
    try:
        with open(tmp, 'x', encoding='utf-8') as f:
            created = True
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)
    finally:
        if created and os.path.exists(tmp):
            os.remove(tmp)


def running_processes():
    try:
        result = subprocess.run(
            ['tasklist', '/FI', 'IMAGENAME eq Antigravity.exe', '/NH'],
            capture_output=True, text=True, errors='replace',
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
        )
    except Exception as exc:
        raise PatchError('无法确认客户端进程状态，已禁止修改：%s' % exc) from exc
    if result.returncode != 0:
        raise PatchError('tasklist 进程检测失败（退出码 %s），已禁止修改。' % result.returncode)
    return [line for line in (result.stdout or '').splitlines() if 'antigravity.exe' in line.lower()]


def _archive(asar_path):
    header, base, size = asar_lib.parse(asar_path)
    files = dict(asar_lib.walk_files(header))
    with open(asar_path, 'rb') as f:
        blob = f.read()

    def read(path):
        node = files.get(path)
        if node is None or node.get('unpacked') or 'link' in node:
            raise PatchError('缺少 packed 文件：%s' % path)
        off, length = asar_lib._bounds(node, base, size)
        return blob[off:off + length]

    try:
        pkg = json.loads(read('/package.json').decode('utf-8'))
        main_rel = pkg.get('main')
        if not isinstance(main_rel, str) or not main_rel:
            raise ValueError('缺少 main')
        main_path = '/' + main_rel.replace('\\', '/').lstrip('/')
        asar_lib._parts(main_path)
        read(main_path)
    except Exception as exc:
        raise PatchError('package.json 或 main 入口无效：%s' % exc) from exc
    return files, read, pkg, main_path


def _require_once(src, token, label):
    count = src.count(token)
    if count != 1:
        raise PatchError('%s 预期命中 1 处，实际 %d 处；未知版本漂移，已中止。' % (label, count))


def _structure(read, files, patched=False):
    """仅接受完整的 legacy 三调用或新版安全出口结构。"""
    safe = '/dist/externalUrl.js' in files
    sites = SAFE_SITES if safe else LEGACY_SITES
    if safe:
        for path, token in SAFE_CALLS:
            _require_once(read(path), token, '%s 安全出口引用' % path)
        for path, old, new in LEGACY_SITES[:2]:
            if old in read(path) or new in read(path):
                raise PatchError('%s 混入旧调用结构，拒绝修改。' % path)
        src = read('/dist/externalUrl.js')
        call = SAFE_SITES[0][2 if patched else 1]
        _require_once(src, SAFE_GATE + call, 'externalUrl 校验门及出口顺序')
        _require_once(src, b"if (scheme.length === 1 || exports.DENIED_EXTERNAL_SCHEMES.has(scheme)) {", 'externalUrl 协议拒绝门')
        _require_once(src, b"if (policy === 'unconfirmed' && !UNCONFIRMED_ALLOWED_SCHEMES.has(scheme)) {", 'externalUrl 未确认策略门')
    for path, old, new in sites:
        src = read(path)
        wanted, forbidden = (new, old) if patched else (old, new)
        _require_once(src, wanted, path + ' 实际调用')
        if forbidden in src:
            raise PatchError('%s 同时存在原始和补丁调用。' % path)
        if src.count(b'.handleCapturedUrl(') != (1 if patched else 0):
            raise PatchError('%s 存在额外拦截调用，拒绝未知漂移。' % path)
    # 系统设置等固定字符串出口不受补丁影响；任何额外动态出口均须显式适配。
    allowed_dynamic = {} if patched else {path: old for path, old, _ in sites}
    for path in {site[0] for site in LEGACY_SITES} | ({'/dist/externalUrl.js'} if safe else set()):
        src = read(path)
        dynamic = re.findall(rb'electron_1\.shell\.openExternal\s*\(\s*([^\r\n;]*)\);', src)
        dynamic = [arg for arg in dynamic if not re.fullmatch(rb'''(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*''', arg)]
        expected = []
        if path in allowed_dynamic:
            expected = re.findall(rb'openExternal\(([^)]*)\)', allowed_dynamic[path])
        if dynamic != expected:
            raise PatchError('%s 存在未知动态 openExternal 出口，已中止。' % path)
    return 'safe-external' if safe else 'legacy-3-call', sites


def _interceptor_bytes():
    with open(resource_path('interceptor.js'), 'rb') as f:
        data = f.read()
    if b'handleCapturedUrl' not in data or not data:
        raise PatchError('随工具附带的 interceptor.js 无效。')
    return data


def _main_inject(main_path):
    rel = posixpath.relpath(INTERCEPTOR_REL, posixpath.dirname(main_path))
    if not rel.startswith('.'):
        rel = './' + rel
    return MAIN_INJECT.replace(b'./urlInterceptor', rel[:-3].encode('utf-8'))


def _has_markers(files, read, main_path):
    if INTERCEPTOR_REL in files:
        return True
    if b'urlInterceptor' in read(main_path):
        return True
    return any(b'handleCapturedUrl' in read(path) for path, _, _ in LEGACY_SITES if path in files) or (
        '/dist/externalUrl.js' in files and b'handleCapturedUrl' in read('/dist/externalUrl.js'))


def is_patched(header=None, asar_path=None):
    # 仅有头部不能证明文件内容、调用与完整性均有效。
    if header is not None and asar_path is None:
        return False
    try:
        return all(ok for _, ok in verify_patched_app(asar_path))
    except Exception:
        return False


def status():
    p = paths()
    process_error = None
    try:
        running = bool(running_processes())
    except PatchError as exc:
        running = None
        process_error = str(exc)
    manifest = read_json(os.path.join(p['userdata'], 'patch-manifest.json'))
    backup = manifest.get('backup') if isinstance(manifest, dict) else None
    backup = backup if isinstance(backup, str) and backup else p['backup']
    info = {
        'tool_version': TOOL_VERSION, 'installed': os.path.exists(p['exe']),
        'asar_exists': os.path.exists(p['asar']), 'backup_exists': os.path.isfile(backup),
        'asar_path': p['asar'], 'backup_path': backup, 'patched': False,
        'product_version': None, 'asar_sha256': None, 'asar_wellformed': None,
        'interception_enabled': None, 'running': running, 'manifest': manifest,
    }
    if process_error:
        info['process_error'] = process_error
    if info['asar_exists']:
        try:
            info['asar_sha256'] = sha256_file(p['asar'])
            info['asar_wellformed'] = not asar_lib.header_is_wellformed(p['asar'])
            files, read, pkg, main_path = _archive(p['asar'])
            info['product_version'] = pkg.get('version')
            checks = verify_patched_app(p['asar'], unpacked_dir=p['unpacked'])
            info['verification'] = checks
            info['patched'] = bool(checks) and all(ok for _, ok in checks)
            if info['patched']:
                info['structure'] = _structure(read, files, patched=True)[0]
        except Exception as exc:
            info['asar_error'] = str(exc)
    cfg = read_json(os.path.join(p['userdata'], 'interceptor_config.json'))
    if isinstance(cfg, dict):
        info['interception_enabled'] = cfg.get('enabled', True)
        info['capture_all'] = cfg.get('capture_all', False)
    info['antigravity_installed'] = info['installed']
    info['interception_active'] = info['interception_enabled'] if info['interception_enabled'] is not None else True
    return info


def _make_edits(official_asar):
    files, read, pkg, main_path = _archive(official_asar)
    if _has_markers(files, read, main_path):
        raise PatchError('输入包含旧补丁或残留注入，不能作为官方原始包。')
    structure, sites = _structure(read, files)
    edits = {main_path: _main_inject(main_path) + read(main_path)}
    for path, old, new in sites:
        edits[path] = read(path).replace(old, new)
    return edits, {INTERCEPTOR_REL: _interceptor_bytes()}, ['已验证结构：' + structure], pkg.get('version')


def _validate(path, unpacked_dir):
    problems = asar_lib.validate(path, unpacked_dir=unpacked_dir)
    if problems:
        raise PatchError('ASAR 完整校验失败：\n' + '\n'.join(problems[:8]))


def _backup_current(p):
    """仅备份已验证的原始包，已有备份绝不覆盖。"""
    files, read, pkg, main_path = _archive(p['asar'])
    if _has_markers(files, read, main_path):
        raise PatchError('拒绝将含补丁的包保存为官方备份。')
    _structure(read, files)
    cur_sha = sha256_file(p['asar'])
    backup = p['backup']
    if os.path.exists(backup):
        if sha256_file(backup) == cur_sha:
            return backup, cur_sha, False
        version = re.sub(r'[^0-9A-Za-z._-]', '_', str(pkg.get('version', 'unknown')))
        backup += '.' + version + '.' + cur_sha[:12] + '.' + time.strftime('%Y%m%d-%H%M%S') + '.' + uuid.uuid4().hex
    # 独占创建，避免并发或同秒操作覆盖既有备份。
    with open(p['asar'], 'rb') as src, open(backup, 'xb') as dst:
        shutil.copyfileobj(src, dst)
    if sha256_file(backup) != cur_sha:
        raise PatchError('官方备份复制后哈希不一致。')
    return backup, cur_sha, True


def _verified_backup(p):
    manifest = read_json(os.path.join(p['userdata'], 'patch-manifest.json'))
    if not isinstance(manifest, dict):
        raise PatchError('缺少有效补丁清单，无法确定同版本官方备份。')
    backup, expected, version = (manifest.get(k) for k in ('backup', 'original_sha256', 'product_version'))
    if not isinstance(backup, str) or not os.path.isabs(backup) or not os.path.isfile(backup):
        raise PatchError('补丁清单所指官方备份不存在。')
    if not isinstance(expected, str) or not re.fullmatch('[0-9a-fA-F]{64}', expected):
        raise PatchError('补丁清单缺少有效的原始 SHA256。')
    if not isinstance(version, str) or not version:
        raise PatchError('补丁清单缺少客户端版本，禁止跨版本恢复。')
    current_version = _archive(p['asar'])[2].get('version')
    if current_version != version:
        raise PatchError('当前版本 %r 与备份清单版本 %r 不同，禁止跨版本恢复。' % (current_version, version))
    patched_sha = manifest.get('patched_sha256')
    if not isinstance(patched_sha, str) or not re.fullmatch('[0-9a-fA-F]{64}', patched_sha):
        raise PatchError('补丁清单缺少有效的 patched_sha256，拒绝恢复或重建。')
    current_sha = sha256_file(p['asar'])
    if current_sha not in (expected.lower(), patched_sha.lower()):
        raise PatchError('当前 app.asar 与清单记录的原版和补丁版均不一致，可能已自动更新，拒绝覆盖。')
    if sha256_file(backup) != expected.lower():
        raise PatchError('官方备份 SHA256 与补丁清单不符。')
    _validate(backup, p['unpacked'])
    files, read, pkg, main_path = _archive(backup)
    if pkg.get('version') != version or _has_markers(files, read, main_path):
        raise PatchError('备份版本不符或含有补丁，拒绝恢复。')
    _structure(read, files)
    return backup, expected.lower(), version


def apply_patch(dry_run=False, force=False):
    p = paths()
    if not os.path.isfile(p['asar']):
        raise PatchError('找不到 app.asar：%s' % p['asar'])
    if running_processes() and not dry_run:
        raise PatchError('Antigravity 正在运行，请先完全退出客户端。')
    _validate(p['asar'], p['unpacked'])
    files, read, pkg, main_path = _archive(p['asar'])
    source = p['asar']
    reuse_backup = _has_markers(files, read, main_path)
    if reuse_backup:
        if not force:
            raise PatchError('当前包含补丁或残留注入；请恢复官方版，或用 force 从验证过的官方备份重建。')
        source, orig_sha, _ = _verified_backup(p)
        backup_path = source
    edits, new_files, notes, product_version = _make_edits(source)
    source_files, source_read, _, _ = _archive(source)
    structure, _ = _structure(source_read, source_files)
    result = {
        'tool_version': TOOL_VERSION, 'notes': notes, 'product_version': product_version,
        'compatible': True, 'structure': structure,
        'files': sorted(set(edits) | set(new_files)),
        'original_sha256': sha256_file(source),
        'plan': {'edit': sorted(edits), 'add': sorted(new_files), 'source': source},
    }
    # dry-run 在任何备份、临时输出、用户目录创建之前返回。
    if dry_run:
        result.update({'dry_run': True, 'backup_created': False, 'output': None})
        if reuse_backup:
            result['backup'] = backup_path
        return result
    if reuse_backup:
        created = False
    else:
        backup_path, orig_sha, created = _backup_current(p)
    result.update({'backup': backup_path, 'backup_created': created})
    tmp_out = p['asar'] + '.new.' + uuid.uuid4().hex
    try:
        asar_lib.build(source, tmp_out, edits, new_files)
        _validate(tmp_out, p['unpacked'])
        checks = verify_patched_app(tmp_out, unpacked_dir=p['unpacked'])
        if not all(ok for _, ok in checks):
            raise PatchError('新包补丁核验失败：%s' % [name for name, ok in checks if not ok])
        orig_map = dict(asar_lib.walk_files(asar_lib.parse(source)[0]))
        out_map = dict(asar_lib.walk_files(asar_lib.parse(tmp_out)[0]))
        if set(out_map) != set(orig_map) | set(new_files):
            raise PatchError('新包文件树与预定改动不一致。')
        for path, node in orig_map.items():
            if path not in edits and path not in new_files and out_map[path] != node:
                raise PatchError('未修改条目发生变化：%s' % path)
        result['patched_sha256'] = sha256_file(tmp_out)
        result['patched_size'] = os.path.getsize(tmp_out)
        os.replace(tmp_out, p['asar'])
    finally:
        if os.path.exists(tmp_out):
            os.remove(tmp_out)
    _validate(p['asar'], p['unpacked'])
    if sha256_file(p['asar']) != result['patched_sha256'] or not all(
            ok for _, ok in verify_patched_app(p['asar'], unpacked_dir=p['unpacked'])):
        raise PatchError('替换后核验失败，请从已验证备份恢复。')
    os.makedirs(p['userdata'], exist_ok=True)
    manifest_path = os.path.join(p['userdata'], 'patch-manifest.json')
    write_json(manifest_path, {
        'tool_version': TOOL_VERSION, 'product_version': product_version,
        'structure': result['structure'], 'patched_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'original_sha256': orig_sha, 'patched_sha256': result['patched_sha256'],
        'backup': backup_path, 'files': result['files'],
    })
    result['manifest'] = manifest_path
    return result


def restore(dry_run=False):
    p = paths()
    if running_processes() and not dry_run:
        raise PatchError('Antigravity 正在运行，请先完全退出客户端。')
    backup, bak_sha, version = _verified_backup(p)
    result = {'backup_sha256': bak_sha, 'backup': backup, 'product_version': version,
              'patched_before': sha256_file(p['asar'])}
    if dry_run:
        result['dry_run'] = True
        return result
    tmp = p['asar'] + '.restore.' + uuid.uuid4().hex
    try:
        with open(backup, 'rb') as src, open(tmp, 'xb') as dst:
            shutil.copyfileobj(src, dst)
        if sha256_file(tmp) != bak_sha:
            raise PatchError('恢复临时文件哈希不一致。')
        _validate(tmp, p['unpacked'])
        os.replace(tmp, p['asar'])
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)
    _validate(p['asar'], p['unpacked'])
    if sha256_file(p['asar']) != bak_sha:
        raise PatchError('恢复后哈希不一致，请重新安装官方客户端。')
    result['restored_sha256'] = bak_sha
    return result


def set_switch(enabled=None, capture_all=None):
    p = paths()
    os.makedirs(p['userdata'], exist_ok=True)
    path = os.path.join(p['userdata'], 'interceptor_config.json')
    cfg = read_json(path, {}) or {}
    if not isinstance(cfg, dict):
        cfg = {}
    if enabled is not None:
        cfg['enabled'] = bool(enabled)
    if capture_all is not None:
        cfg['capture_all'] = bool(capture_all)
    cfg.setdefault('enabled', True)
    cfg.setdefault('capture_all', False)
    write_json(path, cfg)
    return cfg


def verify_patched_app(asar_path=None, unpacked_dir=None):
    p = paths()
    selected = asar_path or p['asar']
    if unpacked_dir is None:
        unpacked_dir = p['unpacked'] if selected == p['asar'] else selected + '.unpacked'
    problems = asar_lib.validate(selected, unpacked_dir=unpacked_dir)
    checks = [('ASAR 全量结构与完整性' + (': ' + '; '.join(problems[:3]) if problems else ''), not problems)]
    try:
        files, read, pkg, main_path = _archive(selected)
        checks.append(('interceptor 内容与当前工具一致', read(INTERCEPTOR_REL) == _interceptor_bytes()))
        main = read(main_path)
        inject = _main_inject(main_path)
        checks.append(('动态 main 引导与环境标记', main.startswith(inject) and main.count(inject) == 1))
        structure, sites = _structure(read, files, patched=True)
        checks.append(('已验证调用结构：' + structure, True))
        for path, old, new in sites:
            checks.append((path + ' 拦截调用', read(path).count(new) == 1 and old not in read(path)))
    except Exception as exc:
        checks.append(('补丁内容核验：%s' % exc, False))
    return checks


def _notify_failure(msg):
    try:
        errfile = os.path.join(paths()['userdata'], 'patch_error.log')
        os.makedirs(os.path.dirname(errfile), exist_ok=True)
        with open(errfile, 'a', encoding='utf-8') as f:
            f.write('[%s] %s\n' % (time.strftime('%Y-%m-%d %H:%M:%S'), msg.replace('\n', ' | ')))
    except Exception:
        pass
    if os.environ.get('ANTIGRAVITY_PATCH_NO_UI'):
        return
    try:
        if sys.stdout is not None and sys.stdout.isatty():
            return
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, msg, 'Antigravity 补丁工具 —— 操作失败', 0x10)
    except Exception:
        pass


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else 'status'
    dry = '--dry-run' in argv
    force = '--force' in argv
    if not argv and sys.stdout is not None and sys.stdout.isatty():
        print('Antigravity 捕获补丁工具 v%s' % TOOL_VERSION)
        print('用法：patch_tool.exe [status|patch|restore|verify|enable|disable]')
        return 0
    try:
        if cmd == 'status':
            print(json.dumps(status(), indent=2, ensure_ascii=False))
        elif cmd == 'patch':
            print(json.dumps(apply_patch(dry_run=dry, force=force), indent=2, ensure_ascii=False))
        elif cmd == 'restore':
            print(json.dumps(restore(dry_run=dry), indent=2, ensure_ascii=False))
        elif cmd == 'verify':
            checks = verify_patched_app()
            for name, ok in checks:
                print(('OK   ' if ok else 'FAIL ') + name)
            return 0 if all(ok for _, ok in checks) else 1
        elif cmd == 'enable':
            print(json.dumps(set_switch(enabled=True), ensure_ascii=False))
        elif cmd == 'disable':
            print(json.dumps(set_switch(enabled=False), ensure_ascii=False))
        else:
            print('usage: status|patch|restore|verify|enable|disable [--dry-run] [--force]', file=sys.stderr)
            return 2
        return 0
    except Exception as exc:
        print('ERROR: %s: %s' % (type(exc).__name__, exc), file=sys.stderr)
        # dry-run 即使失败也不写用户数据或日志。
        if not dry:
            _notify_failure(str(exc))
        return 1


if __name__ == '__main__':
    sys.exit(main())
