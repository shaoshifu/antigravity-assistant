"""登录联动逻辑的自检：用假值 + 本机回环服务器，不碰真实账号、不碰真实客户端。

用法：python selftest_login.py
"""
import http.server
import json
import os
import socket
import sys
import tempfile
import threading
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

TMP = tempfile.mkdtemp(prefix='logintest-')
os.environ['APPDATA'] = os.path.join(TMP, 'Roaming')
os.environ['LOCALAPPDATA'] = os.path.join(TMP, 'Local')
os.makedirs(os.path.join(os.environ['APPDATA'], 'Antigravity', 'logs'), exist_ok=True)

import login_core as core  # noqa: E402  必须在设置环境变量之后导入

PASS, FAIL = [], []
CALLBACK_PATH = '/auth/callback'


def check(name, cond, detail=''):
    (PASS if cond else FAIL).append(name)
    print(('  OK   ' if cond else '  FAIL ') + name + (('  -> ' + str(detail)) if detail and not cond else ''))


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def write_capture(port, state, age_s=0, extra=''):
    payload = {
        'url': ('https://accounts.google.com/o/oauth2/auth?access_type=offline&client_id=test.apps.googleusercontent.com'
                '&code_challenge=FAKE_CHALLENGE_1234567890&code_challenge_method=S256&prompt=consent'
                '&redirect_uri=' + urllib.parse.quote('http://localhost:%d%s' % (port, CALLBACK_PATH), safe='')
                + '&response_type=code&scope=openid+email' + extra + '&state=' + state),
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'time': int((time.time() - age_s) * 1000),
    }
    with open(core.captured_path(), 'w', encoding='utf-8') as f:
        json.dump(payload, f)


class Handler(http.server.BaseHTTPRequestHandler):
    received = []

    def do_GET(self):
        Handler.received.append({'path': self.path, 'host': self.headers.get('Host')})
        body = b'<html><body>Authorization successful. You can close this window.</body></html>'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def main():
    port = free_port()
    state = 'FAKE_STATE_ABCDEF123456'
    write_capture(port, state)

    print('\n[1] 捕获链接解析')
    cap = core.read_captured()
    check('能读到捕获文件', cap is not None)
    auth = core.parse_auth_url(cap['url'])
    check('识别为合法 Google 授权请求', auth['valid'])
    check('取到回调端口 %d' % port, auth['redirect_port'] == port, auth['redirect_port'])
    check('state 长度正确', len(auth['state']) == len(state))

    print('\n[2] 回调校验：应放行')
    good = 'http://localhost:%d%s?code=FAKE_CODE_1&state=%s&iss=%s&scope=email+profile&authuser=0' % (
        port, CALLBACK_PATH, state, urllib.parse.quote(core.GOOGLE_ISSUER, safe=''))
    r = core.validate(cap, good, set())
    check('正常回调通过', r['ok'], r.get('reason'))
    check('端口解析正确', r.get('port') == port, r.get('port'))
    check('code 只留指纹不留原文', 'FAKE_CODE_1' not in json.dumps(r), r)

    r2 = core.validate(cap, good.replace('localhost', '127.0.0.1'), set())
    check('127.0.0.1 也接受', r2['ok'], r2.get('reason'))

    r3 = core.validate(cap, '?code=FAKE_CODE_2&state=' + state, set())
    check('只贴 ?code=… 也能识别', r3['ok'], r3.get('reason'))
    check('缺 iss 仅告警不放错', r3['ok'] and r3['warnings'], r3)

    print('\n[3] 回调校验：应拒绝')
    cases = [
        ('端口不对', good.replace(':%d' % port, ':%d' % (port + 1))),
        ('state 不对', good.replace(state, 'OTHER_STATE')),
        ('主机是外网', good.replace('localhost', 'evil.example.com')),
        ('路径不对', good.replace(CALLBACK_PATH, '/oauth2callback')),
        ('https 协议', good.replace('http://', 'https://')),
        ('iss 不对', good.replace(urllib.parse.quote(core.GOOGLE_ISSUER, safe=''), 'https://evil.example.com')),
        ('重复 code', 'http://localhost:%d%s?code=A&code=B&state=%s' % (port, CALLBACK_PATH, state)),
        ('未知参数', 'http://localhost:%d%s?code=A&state=%s&foo=bar' % (port, CALLBACK_PATH, state)),
        ('没有 code', 'http://localhost:%d%s?state=%s' % (port, CALLBACK_PATH, state)),
        ('没有 state', 'http://localhost:%d%s?code=A' % (port, CALLBACK_PATH)),
        ('Google 报错', 'http://localhost:%d%s?error=access_denied&error_description=nope&state=%s' % (port, CALLBACK_PATH, state)),
    ]
    for name, url in cases:
        rr = core.validate(cap, url, set())
        check('拒绝：' + name, not rr['ok'], rr.get('reason', 'UNEXPECTED PASS'))

    print('\n[4] 防重放与过期')
    rr = core.validate(cap, good, {'%s' % r['code_sha8']})
    check('拒绝：同一 code 重复提交', not rr['ok'], rr.get('reason'))
    write_capture(port, state, age_s=16 * 60)
    cap_old = core.read_captured()
    rr = core.validate(cap_old, good, set())
    check('拒绝：超过 15 分钟', not rr['ok'], rr.get('reason'))

    print('\n[5] 真实投递到本机回环')
    write_capture(port, state)
    cap = core.read_captured()
    srv = http.server.ThreadingHTTPServer(('127.0.0.1', port), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    check('端口探测为活', core.port_alive(port))
    res = core.validate(cap, good, set())
    out = core.deliver(res['port'], good)
    time.sleep(0.2)
    srv.shutdown()
    check('服务端收到 1 个请求', len(Handler.received) == 1, Handler.received)
    got = Handler.received[0] if Handler.received else {}
    check('Host 头沿用 localhost:%d' % port, got.get('host') == 'localhost:%d' % port, got.get('host'))
    check('路径与查询串完整', got.get('path', '').startswith(CALLBACK_PATH + '?code=FAKE_CODE_1'), got.get('path'))
    check('客户端返回 200', out['status'] == 200, out['status'])

    print('\n[6] 成功判定读日志')
    lp = os.path.join(os.environ['APPDATA'], 'Antigravity', 'logs', 'language_server.log')
    with open(lp, 'w', encoding='utf-8') as f:
        f.write('old line\n')
    off = os.path.getsize(lp)
    with open(lp, 'a', encoding='utf-8') as f:
        f.write('I1102 20:51:44.295869 1429 server.go:3399] Auth succeeded, refreshing features and managers\n')
    ok, waited = core.wait_auth_success(lp, off, timeout=3)
    check('识别出 Auth succeeded', ok, waited)

    with open(lp, 'a', encoding='utf-8') as f:
        f.write('some other line\n')
    off2 = os.path.getsize(lp)
    ok2, _ = core.wait_auth_success(lp, off2, timeout=2)
    check('没有成功日志时不误判', not ok2)

    print('\n通过 %d 项，失败 %d 项' % (len(PASS), len(FAIL)))
    if FAIL:
        for n in FAIL:
            print('  - ' + n)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
