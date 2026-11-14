"""命令行版：给自检和排障用。不打印 code。

python login_cli.py captured          # 打印当前捕获到的授权链接解析结果
python login_cli.py submit "<回调URL>" # 校验并提交
"""
import json
import sys

import login_core as core


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'captured'
    if cmd == 'captured':
        cap = core.read_captured()
        if not cap:
            print(json.dumps({'ok': False, 'reason': 'no capture'}, ensure_ascii=False))
            return 1
        auth = core.parse_auth_url(cap['url'])
        out = {k: auth.get(k) for k in ('valid', 'redirect_port', 'redirect_path', 'response_type', 'has_pkce', 'dupes')}
        out['age_s'] = round(cap['age_s'], 1)
        out['state_len'] = len(auth['state'])
        print(json.dumps(out, ensure_ascii=False, indent=1))
        return 0 if auth['valid'] else 1

    if cmd == 'submit':
        text = sys.argv[2] if len(sys.argv) > 2 else sys.stdin.read()
        cap = core.read_captured()
        res = core.validate(cap, text)
        safe = dict(res)
        if not res['ok']:
            print(json.dumps(safe, ensure_ascii=False, indent=1))
            return 1
        safe['port_alive'] = core.port_alive(res['port'])
        if safe['port_alive']:
            log_path, off = core.log_offset()
            r = core.deliver(res['port'], text)
            safe['http_status'] = r['status']
            # 客户端正文可能回显授权参数，不写入输出。
            ok, waited = core.wait_auth_success(log_path, off, timeout=25)
            safe['auth_succeeded'] = ok
            safe['waited_s'] = round(waited, 1)
        print(json.dumps(safe, ensure_ascii=False, indent=1))
        return 0 if safe.get('auth_succeeded') else 1

    print('usage: login_cli.py [captured|submit <url>]', file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())
