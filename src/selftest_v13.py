"""v1.3 隔离回归：python -B selftest_v13.py [只读官方 app.asar 路径]。

所有写入均位于批目录下独立的验证目录，不调用真实安装 paths；保留测试产物供检查。
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from urllib.parse import urlencode

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import antigravity_patch as ap
import asar_lib
import login_core

OFFICIAL = Path(sys.argv.pop(1)) if len(sys.argv) > 1 and sys.argv[1].lower().endswith('.asar') else Path(ap.paths()['asar'])
NODE = shutil.which('node')


def integrity(data):
    return {'algorithm': 'SHA256', 'hash': hashlib.sha256(data).hexdigest(),
            'blockSize': asar_lib.BLOCK_SIZE,
            'blocks': [hashlib.sha256(data[i:i + asar_lib.BLOCK_SIZE]).hexdigest()
                       for i in range(0, max(1, len(data)), asar_lib.BLOCK_SIZE)]}


def write_archive(path, header, payload):
    raw = json.dumps(header, separators=(',', ':')).encode('utf-8')
    aligned = (len(raw) + 3) & ~3
    Path(path).write_bytes(struct.pack('<IIII', 4, 8 + aligned, 4 + aligned, len(raw))
                           + raw + b'\0' * (aligned - len(raw)) + payload)


def fixture(path, version='2.30.0', extra=None):
    contents = {
        '/package.json': json.dumps({'main': 'dist/main.js', 'version': version}).encode(),
        '/dist/main.js': b'"use strict";\nconsole.log("fixture");\n',
        '/dist/utils.js': b'"use strict"; void electron_1.shell.openExternal(details.url);\n',
        '/dist/ipcHandlers.js': b'"use strict"; async function fixture() { await electron_1.shell.openExternal(url); }\n',
        '/dist/languageServer.js': b'"use strict"; void electron_1.shell.openExternal(openUrl);\n',
        '/unchanged.txt': b'untouched fixture payload',
    }
    contents.update(extra or {})
    header = {'files': {}}
    payload = bytearray()
    for name, data in contents.items():
        parent = header
        parts = name.strip('/').split('/')
        for part in parts[:-1]:
            parent = parent['files'].setdefault(part, {'files': {}})
        parent['files'][parts[-1]] = {'size': len(data), 'offset': str(len(payload)),
                                     'integrity': integrity(data)}
        payload.extend(data)
    header['files']['native.node'] = {'size': 6, 'unpacked': True}
    header['files']['alias.txt'] = {'link': 'unchanged.txt'}
    write_archive(path, header, payload)
    unpacked = Path(str(path) + '.unpacked')
    unpacked.mkdir(exist_ok=True)
    (unpacked / 'native.node').write_bytes(b'native')
    return contents


def read_entries(path):
    header, base, _ = asar_lib.parse(str(path))
    return dict(asar_lib.walk_files(header)), base, Path(path).read_bytes()


def entry_bytes(path, name):
    entries, base, raw = read_entries(path)
    node = entries[name]
    start = base + int(node['offset'])
    return raw[start:start + int(node['size'])]


def snapshot(root):
    return {str(p.relative_to(root)): (p.is_dir(), p.stat().st_size, p.stat().st_mtime_ns,
                                      None if p.is_dir() else hashlib.sha256(p.read_bytes()).hexdigest())
            for p in Path(root).rglob('*')}


def assert_integrity(test, path):
    entries, base, raw = read_entries(path)
    checked = 0
    for name, node in entries.items():
        if node.get('unpacked') or 'link' in node or 'integrity' not in node:
            continue
        start = base + int(node['offset'])
        data = raw[start:start + int(node['size'])]
        actual = integrity(data)
        for key in ('algorithm', 'hash', 'blockSize', 'blocks'):
            test.assertEqual(node['integrity'][key], actual[key], '%s: %s' % (name, key))
        checked += 1
    test.assertGreater(checked, 0)
    return checked


class IsolatedTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='验证-v13-', dir=str(HERE.parent)))
        self.archive = self.root / 'app.asar'
        fixture(self.archive)
        self.paths = {'resources': str(self.root), 'asar': str(self.archive),
                      'backup': str(self.root / 'app.asar.backup'),
                      'unpacked': str(self.root / 'app.asar.unpacked'),
                      'exe': str(self.root / 'Antigravity.exe'),
                      'userdata': str(self.root / 'userdata')}
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(ap, 'paths', return_value=self.paths).start()
        mock.patch.object(ap, 'running_processes', return_value=[]).start()
        mock.patch.dict(os.environ, {'APPDATA': str(self.root / 'Roaming'),
                                     'LOCALAPPDATA': str(self.root / 'Local'),
                                     'ANTIGRAVITY_PATCH_NO_UI': '1'}).start()

    def corrupt_header(self, name, change):
        header, base, _ = asar_lib.parse(str(self.archive))
        change(header)
        output = self.root / name
        write_archive(output, header, self.archive.read_bytes()[base:])
        return output


class ArchiveTests(IsolatedTest):
    def test_legacy_build_verify_integrity(self):
        edits, additions, _, version = ap._make_edits(str(self.archive))
        self.assertEqual(version, '2.30.0')
        self.assertEqual(set(edits), {'/dist/main.js', '/dist/utils.js', '/dist/ipcHandlers.js', '/dist/languageServer.js'})
        self.assertEqual(set(additions), {ap.INTERCEPTOR_REL})
        output = self.root / 'patched.asar'
        asar_lib.build(str(self.archive), str(output), edits, additions)
        self.assertEqual(asar_lib.validate(str(output), unpacked_dir=self.paths['unpacked'], expect_main='dist/main.js'), [])
        checks = ap.verify_patched_app(str(output), unpacked_dir=self.paths['unpacked'])
        self.assertTrue(all(ok for _, ok in checks), checks)
        assert_integrity(self, output)

    def test_build_preserves_unchanged_nodes_and_payload(self):
        before, base, raw = read_entries(self.archive)
        edits, additions, _, _ = ap._make_edits(str(self.archive))
        output = self.root / 'patched.asar'
        asar_lib.build(str(self.archive), str(output), edits, additions)
        after, newbase, newraw = read_entries(output)
        self.assertEqual(newraw[newbase:newbase + len(raw) - base], raw[base:])
        self.assertEqual(set(after), set(before) | set(additions))
        for name in set(before) - set(edits) - set(additions):
            self.assertEqual(before[name], after[name], name)
        self.assertTrue(after['/native.node']['unpacked'])
        self.assertEqual(after['/alias.txt']['link'], 'unchanged.txt')

    def test_whole_file_hash_larger_than_four_mib(self):
        large = b'A' * asar_lib.BLOCK_SIZE + b'whole-file-tail'
        output = self.root / 'large.asar'
        asar_lib.build(str(self.archive), str(output), {'/unchanged.txt': large}, {})
        entries, _, _ = read_entries(output)
        node = entries['/unchanged.txt']['integrity']
        self.assertEqual(node['hash'], hashlib.sha256(large).hexdigest())
        self.assertNotEqual(node['hash'], node['blocks'][0])
        self.assertEqual(len(node['blocks']), 2)
        assert_integrity(self, output)

    def test_short_headers_report_problems(self):
        for size in (0, 1, 4, 8, 15):
            with self.subTest(size=size):
                path = self.root / ('short-%d.asar' % size)
                path.write_bytes(b'\0' * size)
                self.assertTrue(asar_lib.header_is_wellformed(str(path)))
                self.assertTrue(asar_lib.validate(str(path)))
                with self.assertRaises(ValueError):
                    asar_lib.parse(str(path))

    def test_bad_size_fields_rejected(self):
        raw = bytearray(self.archive.read_bytes())
        b = struct.unpack_from('<I', raw, 4)[0]
        struct.pack_into('<I', raw, 4, b - 4)
        path = self.root / 'shifted.asar'
        path.write_bytes(raw)
        self.assertTrue(asar_lib.header_is_wellformed(str(path)))
        self.assertTrue(asar_lib.validate(str(path), unpacked_dir=self.paths['unpacked']))

    def test_truncated_payload_rejected(self):
        path = self.root / 'truncated.asar'
        path.write_bytes(self.archive.read_bytes()[:-8])
        self.assertTrue(asar_lib.validate(str(path), unpacked_dir=self.paths['unpacked']))

    def test_negative_offset_rejected(self):
        path = self.corrupt_header('negative.asar', lambda h: h['files']['unchanged.txt'].update(offset='-1'))
        self.assertTrue(asar_lib.validate(str(path), unpacked_dir=self.paths['unpacked']))

    def test_negative_size_rejected(self):
        path = self.corrupt_header('negative-size.asar', lambda h: h['files']['unchanged.txt'].update(size=-1))
        self.assertTrue(asar_lib.validate(str(path), unpacked_dir=self.paths['unpacked']))

    def test_hash_corruption_rejected(self):
        path = self.corrupt_header('hash.asar', lambda h: h['files']['unchanged.txt']['integrity'].update(hash='0' * 64))
        self.assertTrue(asar_lib.validate(str(path), unpacked_dir=self.paths['unpacked']))

    def test_block_corruption_rejected(self):
        path = self.corrupt_header('blocks.asar', lambda h: h['files']['unchanged.txt']['integrity'].update(blocks=['0' * 64]))
        self.assertTrue(asar_lib.validate(str(path), unpacked_dir=self.paths['unpacked']))

    def test_payload_corruption_rejected(self):
        path = self.root / 'payload.asar'
        raw = bytearray(self.archive.read_bytes())
        raw[-1] ^= 1
        path.write_bytes(raw)
        self.assertTrue(asar_lib.validate(str(path), unpacked_dir=self.paths['unpacked']))

    def test_missing_unpacked_rejected(self):
        self.assertTrue(asar_lib.validate(str(self.archive), unpacked_dir=str(self.root / 'missing-unpacked')))

    def test_missing_integrity_rejected(self):
        path = self.corrupt_header('no-integrity.asar', lambda h: h['files']['unchanged.txt'].pop('integrity'))
        self.assertTrue(asar_lib.validate(str(path), unpacked_dir=self.paths['unpacked']))

    def test_header_size_mismatch_parse_refused(self):
        raw = bytearray(self.archive.read_bytes())
        c = struct.unpack_from('<I', raw, 8)[0]
        struct.pack_into('<I', raw, 8, c + 4)
        path = self.root / 'mismatched.asar'
        path.write_bytes(raw)
        with self.assertRaises(ValueError):
            asar_lib.parse(str(path))

    def test_legacy_callsite_drift_rejected(self):
        for call in (b'console.log("removed");', b'void electron_1.shell.openExternal(details.url);' * 2):
            with self.subTest(call=call):
                fixture(self.archive, extra={'/dist/utils.js': call})
                with self.assertRaises(ap.PatchError):
                    ap._make_edits(str(self.archive))


class TransactionTests(IsolatedTest):
    def test_patch_dry_run_is_zero_write(self):
        before = snapshot(self.root)
        result = ap.apply_patch(dry_run=True)
        self.assertTrue(result['dry_run'])
        self.assertEqual(snapshot(self.root), before)

    def test_restore_dry_run_is_zero_write(self):
        ap.apply_patch()
        before = snapshot(self.root)
        self.assertTrue(ap.restore(dry_run=True)['dry_run'])
        self.assertEqual(snapshot(self.root), before)

    def test_backup_manifest_and_roundtrip(self):
        original = self.archive.read_bytes()
        result = ap.apply_patch()
        self.assertEqual(Path(result['backup']).read_bytes(), original)
        self.assertNotEqual(self.archive.read_bytes(), original)
        self.assertTrue(ap.is_patched(asar_path=str(self.archive)))
        manifest = json.loads((Path(self.paths['userdata']) / 'patch-manifest.json').read_text(encoding='utf-8'))
        self.assertEqual(manifest['backup'], result['backup'])
        self.assertEqual(manifest['tool_version'], ap.TOOL_VERSION)
        self.assertEqual(manifest['original_sha256'], hashlib.sha256(original).hexdigest())
        ap.restore()
        self.assertEqual(self.archive.read_bytes(), original)

    def test_manifest_selects_versioned_backup(self):
        original = self.archive.read_bytes()
        stale = Path(self.paths['backup'])
        fixture(stale, version='1.0.0')
        stale_bytes = stale.read_bytes()
        result = ap.apply_patch()
        self.assertNotEqual(Path(result['backup']), stale)
        self.assertIn('2.30.0', Path(result['backup']).name)
        self.assertEqual(stale.read_bytes(), stale_bytes)
        ap.restore()
        self.assertEqual(self.archive.read_bytes(), original)
        self.assertEqual(stale.read_bytes(), stale_bytes)

    def test_cross_version_restore_is_refused_without_writes(self):
        ap.apply_patch()
        fixture(self.archive, version='9.99.0')
        before = snapshot(self.root)
        with self.assertRaises(ap.PatchError):
            ap.restore()
        self.assertEqual(snapshot(self.root), before)

    def test_tampered_manifest_backup_is_refused(self):
        result = ap.apply_patch()
        with Path(result['backup']).open('ab') as f:
            f.write(b'tampered')
        before = snapshot(self.root)
        with self.assertRaises(ap.PatchError):
            ap.restore()
        self.assertEqual(snapshot(self.root), before)

    def test_force_rebuild_reuses_official_backup(self):
        first = ap.apply_patch()
        backup = Path(first['backup'])
        original = backup.read_bytes()
        second = ap.apply_patch(force=True)
        self.assertEqual(second['backup'], first['backup'])
        self.assertFalse(second['backup_created'])
        self.assertEqual(backup.read_bytes(), original)
        checks = ap.verify_patched_app(str(self.archive), unpacked_dir=self.paths['unpacked'])
        self.assertTrue(all(ok for _, ok in checks), checks)

    def test_repeat_patch_rejected_without_writes(self):
        ap.apply_patch()
        before = snapshot(self.root)
        with self.assertRaises(ap.PatchError):
            ap.apply_patch()
        self.assertEqual(snapshot(self.root), before)

    def test_missing_manifest_restore_refused_without_writes(self):
        shutil.copyfile(str(self.archive), self.paths['backup'])
        before = snapshot(self.root)
        with self.assertRaises(ap.PatchError):
            ap.restore()
        self.assertEqual(snapshot(self.root), before)

    def test_running_process_blocks_modification(self):
        before = snapshot(self.root)
        with mock.patch.object(ap, 'running_processes', return_value=['Antigravity.exe']):
            with self.assertRaises(ap.PatchError):
                ap.apply_patch()
        self.assertEqual(snapshot(self.root), before)


class LoginValidationTests(unittest.TestCase):
    def setUp(self):
        self.params = {'client_id': 'fixture.apps.googleusercontent.com', 'response_type': 'code',
                       'state': 'fixture-state-123', 'code_challenge': 'A' * 43,
                       'code_challenge_method': 'S256', 'scope': 'openid email',
                       'redirect_uri': 'http://localhost:43891/auth/callback'}
        self.url = 'https://accounts.google.com/o/oauth2/v2/auth?' + urlencode(self.params)
        self.captured = {'url': self.url, 'age_s': 0, 'time': int(time.time() * 1000)}
        self.callback = 'http://localhost:43891/auth/callback?code=fixture-code&state=fixture-state-123'

    def test_valid_callback_and_expiration(self):
        self.assertTrue(login_core.validate(self.captured, self.callback, set())['ok'])
        self.captured['age_s'] = 901
        self.assertFalse(login_core.validate(self.captured, self.callback, set())['ok'])

    def test_capture_expiration_uses_original_timestamp(self):
        self.captured['time_ms'] = int((time.time() - 901) * 1000)
        self.captured['age_s'] = 0
        self.assertFalse(login_core.validate(self.captured, self.callback, set())['ok'])

    def test_invalid_age_rejected(self):
        for age in (float('nan'), float('inf'), 900):
            with self.subTest(age=age):
                self.captured['age_s'] = age
                self.assertFalse(login_core.validate(self.captured, self.callback, set())['ok'])

    def test_duplicate_auth_parameters_rejected(self):
        for key in ('state', 'redirect_uri', 'response_type', 'code_challenge', 'client_id'):
            with self.subTest(key=key):
                auth = login_core.parse_auth_url(self.url + '&' + urlencode({key: self.params[key]}))
                self.assertFalse(auth['valid'])

    def test_malformed_auth_is_rejected_without_exception(self):
        for url in ('https://[bad', self.url.replace('43891', 'bad'), self.url.replace('43891', '99999'),
                    self.url + '&extra=%ZZ', self.url.replace('https://', 'https://user@')):
            with self.subTest(url=url):
                self.assertFalse(login_core.parse_auth_url(url)['valid'])

    def test_malformed_callback_is_rejected_without_exception(self):
        for callback in ('http://[bad', self.callback.replace('43891', 'bad'),
                         self.callback.replace('43891', '99999'), self.callback + '&scope=%ZZ',
                         self.callback + '&state=fixture-state-123', self.callback + '#fragment'):
            with self.subTest(callback=callback):
                self.assertFalse(login_core.validate(self.captured, callback, set())['ok'])


class RealPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not OFFICIAL.is_file():
            raise unittest.SkipTest('未找到只读官方包，可传入 app.asar 路径')
        cls.root = Path(tempfile.mkdtemp(prefix='验证-v13-真实-', dir=str(HERE.parent)))
        cls.before_hash = ap.sha256_file(str(OFFICIAL))
        cls.original_entries, _, _ = read_entries(OFFICIAL)
        cls.edits, cls.additions, cls.notes, cls.version = ap._make_edits(str(OFFICIAL))
        cls.output = cls.root / 'app.asar'
        asar_lib.build(str(OFFICIAL), str(cls.output), cls.edits, cls.additions)

    @classmethod
    def tearDownClass(cls):
        if ap.sha256_file(str(OFFICIAL)) != cls.before_hash:
            raise AssertionError('只读官方包发生变化')

    def test_real_2312_safe_external_edits(self):
        self.assertEqual(self.version, '2.31.2')
        self.assertEqual(set(self.edits), {'/dist/main.js', '/dist/externalUrl.js', '/dist/languageServer.js'})
        external = self.edits['/dist/externalUrl.js']
        self.assertIn(b'await require("./urlInterceptor").handleCapturedUrl(parsed.href, "externalUrl")', external)
        self.assertIn(b'classifyParsedExternalUrl(parsed, policy)', external)
        original_external = entry_bytes(OFFICIAL, '/dist/externalUrl.js')
        self.assertEqual(external, original_external.replace(
            b'await electron_1.shell.openExternal(parsed.href);',
            b'await require("./urlInterceptor").handleCapturedUrl(parsed.href, "externalUrl");'))
        self.assertEqual(set(self.additions), {ap.INTERCEPTOR_REL})

    def test_real_build_verify_and_complete_integrity(self):
        problems = asar_lib.validate(str(self.output), unpacked_dir=str(OFFICIAL) + '.unpacked', expect_main='dist/main.js')
        self.assertEqual(problems, [])
        checks = ap.verify_patched_app(str(self.output), unpacked_dir=str(OFFICIAL) + '.unpacked')
        self.assertTrue(all(ok for _, ok in checks), checks)
        assert_integrity(self, OFFICIAL)
        assert_integrity(self, self.output)

    def test_real_preserves_all_unchanged_offsets_unpacked_links(self):
        after, _, _ = read_entries(self.output)
        self.assertEqual(set(after), set(self.original_entries) | set(self.additions))
        for name, before in self.original_entries.items():
            if name not in self.edits and name not in self.additions:
                self.assertEqual(before, after[name], name)

    def test_real_changed_javascript_syntax(self):
        if not NODE:
            self.skipTest('node 不可用')
        for name, data in dict(self.edits, **self.additions).items():
            with self.subTest(path=name):
                output = self.root / Path(name).name
                output.write_bytes(data)
                result = subprocess.run([NODE, '--check', str(output)], capture_output=True, text=True, encoding='utf-8', errors='replace')
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_real_external_structure_drift_rejected(self):
        external = entry_bytes(OFFICIAL, '/dist/externalUrl.js')
        drift = self.root / 'drift.asar'
        old = b'await electron_1.shell.openExternal(parsed.href);'
        self.assertEqual(external.count(old), 1)
        asar_lib.build(str(OFFICIAL), str(drift), {'/dist/externalUrl.js': external.replace(old, b'return;')}, {})
        with self.assertRaises(ap.PatchError):
            ap._make_edits(str(drift))


class JavaScriptHarnessTests(unittest.TestCase):
    def test_interceptor_vm_harness(self):
        if not NODE:
            self.skipTest('node 不可用')
        result = subprocess.run([NODE, str(HERE / 'selftest_interceptor.js')], capture_output=True, text=True, encoding='utf-8', errors='replace')
        print(result.stdout, end='')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    print('只读官方包：%s' % OFFICIAL)
    print('测试写入范围：%s/验证-v13-*（保留产物，不执行批量删除）' % HERE.parent)
    unittest.main(verbosity=2)
