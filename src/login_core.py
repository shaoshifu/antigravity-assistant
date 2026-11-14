"""登录联动的核心逻辑：读捕获链接 → 校验回调 → 送回本机客户端 → 核实真的登录成功。

只用 127.0.0.1，不走系统代理，不跟随重定向，不落盘保存 code/state。
"""
import hashlib
import http.client
import json
import math
import os
import re
import socket
import time
from urllib.parse import parse_qsl, unquote, urlparse

import antigravity_patch as ap

GOOGLE_ISSUER = 'https://accounts.google.com'
AUTH_PATH_RE = re.compile(r'^/o/oauth2/(v2/)?auth$')
CALLBACK_PATH = '/auth/callback'
WINDOW_SECONDS = 15 * 60
ALLOWED_PARAMS = {'code', 'state', 'scope', 'authuser', 'prompt', 'iss', 'hd', 'session_state'}
ERROR_PARAMS = {'error', 'error_description', 'error_uri'}


def captured_path():
    return os.path.join(ap.paths()['userdata'], 'captured_url.json')


def read_captured():
    """返回 dict(url, time_ms, age_s) 或 None。"""
    p = captured_path()
    try:
        with open(p, 'r', encoding='utf-8') as f:
            d = json.load(f)
        url = (d.get('url') or '').strip()
        if not url:
            return None
        ts = d.get('time')
        if isinstance(ts, bool) or not isinstance(ts, (int, float)) or not math.isfinite(ts) or ts <= 0:
            return None
        if ts / 1000.0 > time.time() + 30:
            return None
        age = max(0.0, time.time() - ts / 1000.0)
        return {'url': url, 'time_ms': int(ts), 'age_s': age, 'redirect': _get(url, 'redirect_uri')}
    except Exception:
        return None


def _get(url, key):
    for k, v in parse_qsl(urlparse(url).query, keep_blank_values=True):
        if k == key:
            return v
    return ''


def parse_auth_url(url):
    """解析授权请求；畸形 URL 一律返回 invalid，不将原文写进错误。"""
    invalid = {'valid': False, 'state': '', 'redirect_port': None, 'params': [], 'dupes': []}
    if (not isinstance(url, str) or len(url) > 8192 or any(ord(c) < 32 for c in url)
            or re.search(r'%(?![0-9A-Fa-f]{2})', url)):
        return invalid
    try:
        u = urlparse(url)
        pairs = parse_qsl(u.query, keep_blank_values=True, max_num_fields=100)
        names = [k for k, _ in pairs]
        q = dict(pairs)
        dupes = sorted({k for k in names if names.count(k) > 1})
        redirect = q.get('redirect_uri', '')
        ru = urlparse(redirect)
        port = ru.port
        valid = bool(
            AUTH_PATH_RE.fullmatch(u.path or '') and u.hostname == 'accounts.google.com'
            and u.scheme == 'https' and u.port in (None, 443) and not u.username and not u.password
            and not u.fragment and not dupes and q.get('response_type') == 'code'
            and q.get('code_challenge') and q.get('state')
            and re.fullmatch(r'http://(?:localhost|127\.0\.0\.1):[0-9]{1,5}/auth/callback', redirect, re.I)
            and ru.path == CALLBACK_PATH and port and 1 <= port <= 65535)
        return {
            'host': u.hostname, 'path': u.path, 'scheme': u.scheme, 'state': q.get('state', ''),
            'redirect': redirect, 'redirect_host': ru.hostname, 'redirect_port': port,
            'redirect_path': ru.path, 'response_type': q.get('response_type', ''),
            'has_pkce': bool(q.get('code_challenge')), 'params': sorted(q), 'dupes': dupes, 'valid': valid,
        }
    except (ValueError, TypeError):
        return invalid


def normalize_callback(text):
    """把用户粘进来的东西统一成可解析的 URL（允许只贴 ?code=... 部分）。"""
    text = (text or '').strip().strip('"').strip("'")
    if not text:
        return ''
    if text.startswith('?'):
        return 'http://localhost' + CALLBACK_PATH + text
    if not text.lower().startswith('http'):
        return 'http://localhost' + (text if text.startswith('/') else '/' + text)
    return text


def validate(captured, callback_text, already_used=None):
    """校验回调是否属于这次会话。返回 dict(ok, reason, port, query, code_sha8, warnings)。"""
    res = {'ok': False, 'reason': '', 'warnings': []}
    if not captured:
        res['reason'] = '还没捕获到授权链接。先在客户端点 “Continue with Google”。'
        return res
    auth = parse_auth_url(captured['url'])
    if not auth['valid']:
        res['reason'] = '捕获到的链接不是预期的 Google 授权请求，已拒绝。'
        return res
    age = captured.get('age_s', float('inf'))
    if 'time_ms' in captured:
        age = max(0.0, time.time() - captured['time_ms'] / 1000.0)
    if not isinstance(age, (int, float)) or not math.isfinite(age) or age >= WINDOW_SECONDS:
        res['reason'] = '这条授权链接已过期或时间无效，请回客户端重新点一次 Continue with Google。'
        return res

    text = normalize_callback(callback_text)
    if not text:
        res['reason'] = '还没有粘贴回调地址。'
        return res
    try:
        if (len(text) > 16384 or any(ord(c) < 32 for c in text)
                or re.search(r'%(?![0-9A-Fa-f]{2})', text)):
            raise ValueError('invalid callback')
        u = urlparse(text)
        callback_port = u.port
        host = (u.hostname or '').lower()
        if u.username or u.password or u.fragment:
            raise ValueError('invalid callback')
    except ValueError:
        res['reason'] = '回调地址格式无效，已拒绝。请复制完整地址，不要改动参数。'
        return res

    if u.scheme not in ('http',):
        res['reason'] = '回调必须是 http://（不是 https 或别的协议）。'
        return res
    if host not in ('localhost', '127.0.0.1'):
        res['reason'] = '回调主机是 %s，必须是 localhost 或 127.0.0.1。' % host
        return res
    if u.path != CALLBACK_PATH:
        res['reason'] = '回调路径是 %s，必须是 %s。' % (u.path, CALLBACK_PATH)
        return res
    # 只贴 ?code=… 时没有端口，按本次会话的端口补齐；贴了别的端口就拒
    port = callback_port if callback_port is not None else auth['redirect_port']
    if port != auth['redirect_port']:
        res['reason'] = '端口对不上：这次会话的回调端口是 %s，你贴的是 %s。可能贴了上一次的链接。' % (auth['redirect_port'], u.port)
        return res

    pairs = parse_qsl(u.query, keep_blank_values=True)
    names = [k for k, _ in pairs]
    dupes = sorted({k for k in names if names.count(k) > 1})
    if dupes:
        res['reason'] = '回调里出现重复参数：%s，已拒绝。' % ', '.join(dupes)
        return res

    q = dict(pairs)
    err = q.get('error')
    if err:
        res['reason'] = 'Google 拒绝了本次授权，请在浏览器查看原因并重新登录。'
        return res

    unknown = [k for k in names if k not in ALLOWED_PARAMS and k not in ERROR_PARAMS]
    if unknown:
        res['reason'] = '回调里有不认识的参数：%s，为安全已拒绝。' % ', '.join(unknown)
        return res

    code = q.get('code', '')
    if not code:
        res['reason'] = '回调里没有 code 参数。'
        return res
    if len(code) > 4096:
        res['reason'] = 'code 长度异常，已拒绝。'
        return res

    iss = q.get('iss')
    if iss is not None and iss != GOOGLE_ISSUER:
        res['reason'] = 'iss 不是 %s（实际 %s），已拒绝。' % (GOOGLE_ISSUER, iss[:80])
        return res
    if iss is None:
        res['warnings'].append('回调里没有 iss 字段（新版本 Google 通常会带），按兼容处理放行。')

    state = q.get('state', '')
    if not state:
        res['reason'] = '回调里没有 state 参数，无法确认是哪一次登录，已拒绝。'
        return res
    if state != auth['state']:
        res['reason'] = 'state 与这次会话不匹配（可能是上次的链接），已拒绝。请重新点一次 Continue with Google。'
        return res

    code_sha8 = hashlib.sha256(code.encode('utf-8')).hexdigest()[:8]
    if already_used and code_sha8 in already_used:
        res['reason'] = '这个 code 已经提交过了（授权码只能用一次）。请重新登录。'
        return res

    res.update({
        'ok': True,
        'port': auth['redirect_port'],
        'code_sha8': code_sha8,
        'state_sha8': hashlib.sha256(state.encode()).hexdigest()[:8],
    })
    return res


def port_alive(port, host='127.0.0.1', timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def deliver(port, callback_text, timeout=10):
    """把回调原文送到本机 127.0.0.1:port，Host 头沿用 localhost:port。"""
    raw_query = urlparse(normalize_callback(callback_text)).query
    path = CALLBACK_PATH + ('?' + raw_query if raw_query else '')
    conn = http.client.HTTPConnection('127.0.0.1', port, timeout=timeout)
    try:
        conn.putrequest('GET', path, skip_host=True, skip_accept_encoding=True)
        conn.putheader('Host', 'localhost:%d' % port)
        conn.putheader('User-Agent', 'antigravity-login-assistant')
        conn.putheader('Connection', 'close')
        conn.endheaders()
        resp = conn.getresponse()
        body = resp.read(4096)
        return {'status': resp.status, 'body': body.decode('utf-8', 'replace')}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def log_offset():
    p = os.path.join(ap.paths()['userdata'], 'logs', 'language_server.log')
    try:
        return p, os.path.getsize(p)
    except Exception:
        return os.path.join(ap.paths()['userdata'], 'logs', 'language_server.log'), 0


def wait_auth_success(path, offset, timeout=40):
    """从 offset 之后找 “Auth succeeded”，返回 (bool, 耗时秒)。"""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with open(path, 'rb') as f:
                if os.path.getsize(path) >= offset:
                    f.seek(offset)
                chunk = f.read().decode('utf-8', 'replace')
            if 'Auth succeeded' in chunk:
                return True, time.time() - start
            if 'invalid_grant' in chunk or 'invalid request' in chunk.lower():
                return False, time.time() - start
        except Exception:
            pass
        time.sleep(0.8)
    return False, time.time() - start
