"""Antigravity 助手：登录 + 补丁，一个窗口两个标签页。"""
import os
import json
import sys
import queue
import subprocess
import threading
import time
import tkinter as tk
import webbrowser
from tkinter import messagebox, ttk

import antigravity_patch as ap
import login_core as core
import client_process

APP_TITLE = 'Antigravity 助手 v1.3.1'
AUTHOR = '伽马AI'
AUTHOR_URL = 'https://www.16688.com.cn/shop/S444368'
FONT = ('Microsoft YaHei UI', 9)
NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


def client_running():
    try:
        out = subprocess.run(['tasklist', '/FI', 'IMAGENAME eq Antigravity.exe', '/NH'],
                             capture_output=True, text=True, encoding='mbcs', errors='replace',
                             creationflags=NO_WINDOW).stdout or ''
        return 'Antigravity.exe' in out
    except Exception:
        return False


class LogBox(ttk.Frame):
    def __init__(self, parent, height=10, title='结果'):
        super().__init__(parent)
        box = ttk.LabelFrame(self, text=' %s ' % title, padding=8)
        box.pack(fill='both', expand=True)
        self.text = tk.Text(box, height=height, wrap='word', relief='solid', borderwidth=1, state='disabled')
        sb = ttk.Scrollbar(box, command=self.text.yview)
        self.text.configure(yscrollcommand=sb.set)
        self.text.pack(side='left', fill='both', expand=True)
        sb.pack(side='right', fill='y')

    def write(self, msg):
        self.text.configure(state='normal')
        self.text.insert('end', time.strftime('[%H:%M:%S] ') + msg + '\n')
        self.text.see('end')
        self.text.configure(state='disabled')


# --------------------------------------------------------------------------- 登录
class LoginTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent, padding=12)
        self.q = queue.Queue()
        self.used_codes = set()
        self.last_mtime = 0
        self.captured = None
        self.busy = False
        self.patch_label = '待检查（到补丁页刷新）'

        top = ttk.Frame(self)
        top.pack(fill='x')
        self.client_var = tk.StringVar(value='正在检查客户端…')
        ttk.Label(top, textvariable=self.client_var).pack(side='left')
        self.btn_start = ttk.Button(top, text='启动客户端', width=12, command=self.start_client)
        self.btn_start.pack(side='right')

        box1 = ttk.LabelFrame(self, text=' ① 授权链接（客户端点 “Continue with Google” 后出现） ', padding=10)
        box1.pack(fill='x', pady=(10, 6))
        self.link_var = tk.StringVar(value='等待捕获…')
        ttk.Label(box1, textvariable=self.link_var, wraplength=700, justify='left').pack(anchor='w', fill='x')
        row = ttk.Frame(box1)
        row.pack(fill='x', pady=(6, 0))
        self.btn_copy = ttk.Button(row, text='复制链接到剪贴板', command=self.copy_link, state='disabled')
        self.btn_copy.pack(side='left')
        self.expire_var = tk.StringVar(value='')
        ttk.Label(row, textvariable=self.expire_var).pack(side='left', padx=10)

        box2 = ttk.LabelFrame(self, text=' ② 把你浏览器最后停住的那一整行地址粘到这里 ', padding=10)
        box2.pack(fill='x', pady=6)
        self.txt = tk.Text(box2, height=3, wrap='char', relief='solid', borderwidth=1)
        self.txt.pack(fill='x')
        row2 = ttk.Frame(box2)
        row2.pack(fill='x', pady=(6, 0))
        self.btn_submit = ttk.Button(row2, text='提交给客户端', command=self.submit)
        self.btn_submit.pack(side='left')
        ttk.Button(row2, text='清空', command=self.clear_input).pack(side='left', padx=8)
        ttk.Label(row2, text='（授权码只在本机回环里传递，不落盘、不外发）').pack(side='left', padx=6)

        self.log = LogBox(self, height=9)
        self.log.pack(fill='both', expand=True, pady=(6, 0))

        self.log.write('客户端点 “Continue with Google”，链接会出现在①；拿到你自己电脑打开，'
                       '授权完把最后那一行地址粘到②。')
        self.after(100, self.drain)
        self.after(300, self.tick)

    def drain(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == 'log':
                    self.log.write(payload)
                elif kind == 'error':
                    self.log.write('✗ ' + payload)
                    messagebox.showerror('出错了', payload)
                elif kind == 'busy':
                    self.set_busy(payload)
                elif kind == 'submit-done':
                    self.used_codes.add(payload)
                elif kind == 'clear-input':
                    self.clear_input()
        except queue.Empty:
            pass
        self.after(150, self.drain)

    def set_busy(self, busy):
        self.busy = busy
        self.btn_submit.configure(state='disabled' if busy else 'normal')
        self.btn_start.configure(state='disabled' if busy else 'normal')
        self.btn_copy.configure(state='disabled' if busy or not self.captured else 'normal')

    def start_client(self):
        exe = ap.paths()['exe']
        if not os.path.exists(exe):
            messagebox.showerror('找不到客户端', '没有找到 %s' % exe)
            return
        env = {k: v for k, v in os.environ.items() if k not in ('ELECTRON_RUN_AS_NODE', 'NODE_OPTIONS')}
        try:
            subprocess.Popen([exe], cwd=os.path.dirname(exe), env=env)
            self.log.write('已启动客户端，等它出现登录页后点 “Continue with Google”。')
        except Exception as exc:
            messagebox.showerror('启动失败', str(exc))
        # tick 已有唯一的周期链，不在启动时另建定时器。

    def tick(self):
        running = client_running()
        self.client_var.set('客户端：%s      补丁：%s' % ('运行中' if running else '未运行', self.patch_label))
        self.btn_start.configure(state='disabled' if running or self.busy else 'normal')

        p = core.captured_path()
        try:
            mtime = os.path.getmtime(p)
        except Exception:
            mtime = 0
        if mtime and mtime != self.last_mtime:
            self.last_mtime = mtime
            cap = core.read_captured()
            if cap:
                self.captured = cap
                auth = core.parse_auth_url(cap['url'])
                if auth['valid'] and cap['age_s'] <= core.WINDOW_SECONDS:
                    self.link_var.set(cap['url'])
                    mins = int(cap['age_s'] // 60)
                    if mins >= 2:
                        self.log.write('授权链接（端口 %s）已 %d 分钟，可能已经用过；如果是，回客户端重新点一次。' % (auth['redirect_port'], mins))
                    else:
                        self.log.write('捕获到授权链接（端口 %s）。复制它，到你自己的电脑浏览器打开。' % auth['redirect_port'])
                else:
                    self.link_var.set('（上次的链接已失效，请在客户端重新点 Continue with Google）')
        if self.captured:
            age = max(0.0, time.time() - self.captured['time_ms'] / 1000.0)
            self.captured['age_s'] = age
            left = core.WINDOW_SECONDS - age
            valid = core.parse_auth_url(self.captured['url'])['valid']
            self.expire_var.set('剩余 %02d:%02d' % (max(0, int(left)) // 60, max(0, int(left)) % 60) if left > 0 and valid else '已失效')
            self.btn_copy.configure(state='normal' if left > 0 and valid and not self.busy else 'disabled')
        self.after(1000, self.tick)

    def copy_link(self):
        cap = core.read_captured()
        if not cap or not core.parse_auth_url(cap['url'])['valid'] or cap['age_s'] >= core.WINDOW_SECONDS:
            messagebox.showerror('链接已失效', '请在客户端重新点 Continue with Google。')
            return
        self.captured = cap
        try:
            self.clipboard_clear()
            self.clipboard_append(self.captured['url'])
            self.log.write('已复制授权链接。去你自己电脑的浏览器里 Ctrl+V 打开。')
            self.update_idletasks()
        except Exception as exc:
            messagebox.showerror('复制失败', str(exc))

    def clear_input(self):
        self.txt.delete('1.0', 'end')

    def submit(self):
        if self.busy:
            return
        text = self.txt.get('1.0', 'end').strip()
        if not text:
            messagebox.showinfo('还没粘', '把浏览器地址栏最后那一整行粘进②。')
            return
        self.set_busy(True)
        threading.Thread(target=self._worker, args=(text,), daemon=True).start()

    def _worker(self, text):
        try:
            cap = core.read_captured()
            res = core.validate(cap, text, self.used_codes)
            for w in res.get('warnings', []):
                self.q.put(('log', '注：' + w))
            if not res['ok']:
                self.q.put(('error', res['reason']))
                return
            port = res['port']
            self.q.put(('log', '校验通过：端口 %d，state 匹配，code 指纹 %s。' % (port, res['code_sha8'])))
            if not core.port_alive(port):
                self.q.put(('error', '本机 127.0.0.1:%d 没有在监听。客户端可能重启过或这次登录已超时，'
                                    '请回客户端重新点一次 Continue with Google。' % port))
                return
            log_path, offset = core.log_offset()
            r = core.deliver(port, text)
            self.q.put(('log', '回调已送达客户端：HTTP %s。' % r['status']))
            # 不显示客户端响应正文：其中可能回显授权码或其他会话参数。
            if r['status'] != 200:
                self.q.put(('log', '客户端返回非 200，不能据此认定登录成功。'))
            self.q.put(('submit-done', res['code_sha8']))
            ok, waited = core.wait_auth_success(log_path, offset, timeout=40)
            if ok:
                self.q.put(('log', '✅ 客户端已完成换票（日志出现 Auth succeeded，%.0f 秒）。看下客户端进主界面没有。' % waited))
                self.q.put(('clear-input', None))
            else:
                self.q.put(('log', '⚠ 回调送进去了，但 %.0f 秒内没看到成功日志。可能授权码过期/已用过，建议重新登录。' % waited))
        except Exception as exc:
            self.q.put(('error', '%s: %s' % (type(exc).__name__, exc)))
        finally:
            self.q.put(('busy', False))


# --------------------------------------------------------------------------- 补丁
class PatchTab(ttk.Frame):
    def __init__(self, parent, login_tab=None):
        super().__init__(parent, padding=12)
        self.q = queue.Queue()
        self.busy = False
        self.login_tab = login_tab

        self.status_var = tk.StringVar(value='正在读取状态…')
        ttk.Label(self, textvariable=self.status_var, justify='left').pack(anchor='w')

        bar = ttk.Frame(self)
        bar.pack(fill='x', pady=(10, 6))
        self.buttons = [
            ttk.Button(bar, text='打补丁', command=lambda: self.run('patch')),
            ttk.Button(bar, text='恢复官方版', command=lambda: self.run('restore')),
            ttk.Button(bar, text='暂停拦截', command=lambda: self.run('toggle')),
            ttk.Button(bar, text='刷新状态', command=self.refresh),
            ttk.Button(bar, text='一键结束客户端', command=lambda: self.run('end-client')),
        ]
        for b in self.buttons:
            b.pack(side='left', padx=(0, 8))

        ttk.Label(self, text='打补丁 / 恢复前请先完全退出 Antigravity（包括右下角托盘图标）。',
                  foreground='#666').pack(anchor='w')

        self.log = LogBox(self, height=10)
        self.log.pack(fill='both', expand=True, pady=(8, 0))
        self.log.write('这一页只管“链接捕获”能力：客户端自动更新后点一次「打补丁」即可。')
        self.log.write('日常使用不需要打开这一页。')

        self.after(100, self.drain)
        self.refresh()

    def drain(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == 'log':
                    self.log.write(payload)
                elif kind == 'error':
                    self.log.write('✗ ' + payload)
                    messagebox.showerror('操作失败', payload)
                elif kind == 'status':
                    self.show_status(payload)
                elif kind == 'end-preview':
                    self.confirm_end(payload)
                elif kind == 'end-done':
                    if self.login_tab is not None:
                        self.login_tab.captured = None
                        self.login_tab.link_var.set('客户端已结束；重启后请重新获取授权链接。')
                        self.login_tab.expire_var.set('请重新登录')
                        self.login_tab.clear_input()
                        self.login_tab.set_busy(False)
                    self.set_busy(False)
                elif kind == 'done':
                    self.set_busy(False)
        except queue.Empty:
            pass
        self.after(120, self.drain)

    def set_busy(self, busy):
        self.busy = busy
        for b in self.buttons:
            b.configure(state='disabled' if busy else 'normal')

    def refresh(self):
        if self.busy:
            return
        self.set_busy(True)
        def read_status():
            try:
                self.q.put(('status', ap.status()))
            except Exception as exc:
                self.q.put(('error', '读取状态失败：%s' % type(exc).__name__))
            finally:
                self.q.put(('done', None))
        threading.Thread(target=read_status, daemon=True).start()

    def show_status(self, info):
        state = '已核验当前补丁' if info['patched'] else '未核验为当前补丁'
        if self.login_tab is not None:
            self.login_tab.patch_label = state
        if info.get('asar_wellformed') is False:
            state = '⚠ app.asar 结构损坏（很可能是旧版补丁工具写坏的）'
        running = '，客户端正在运行' if info['running'] else ''
        self.status_var.set(
            '客户端版本：%s      补丁状态：%s%s\n拦截开关：%s      官方备份：%s'
            % (info.get('product_version') or '未知', state, running,
               '开启' if info.get('interception_enabled', True) else '已暂停',
               '有' if info['backup_exists'] else '无'))
        self.buttons[2].configure(text='暂停拦截' if info.get('interception_enabled', True) else '开启拦截')

    def confirm_end(self, payload):
        exe, processes = payload
        if not processes:
            self.log.write('当前安装路径没有残留客户端进程，无需结束。')
            self.set_busy(False)
            self.refresh()
            return
        detail = '\n'.join('PID %s — %s' % (item['pid'], item['path']) for item in processes)
        if self.login_tab is not None and self.login_tab.busy:
            self.log.write('登录提交正在进行，请等它完成后再结束客户端。')
            self.set_busy(False)
            return
        if not messagebox.askyesno('结束客户端确认',
            '将强制结束以下客户端进程，未保存内容可能丢失，当前登录会话将失效。\n\n'
            + detail + '\n\n不会结束其他安装目录的同名程序，也不会自动打补丁。\n确认结束？', default='no'):
            self.set_busy(False)
            return
        if self.login_tab is not None:
            self.login_tab.set_busy(True)
        threading.Thread(target=self._end_worker, args=(exe, processes), daemon=True).start()

    def _end_worker(self, exe, processes):
        try:
            result = client_process.end_client_processes(exe, processes)
            self.q.put(('log', '已结束 PID：%s' % (', '.join(map(str, result['ended'])) or '无（已自行退出）')))
            if result['remaining']:
                self.q.put(('log', '仍有客户端进程（可能自动重启）：%s。请再次确认后结束。'
                            % ', '.join(str(p['pid']) for p in result['remaining'])))
            else:
                self.q.put(('log', '客户端已全部退出。现在可手动点击「打补丁」。'))
        except Exception as exc:
            self.q.put(('error', str(exc)))
        finally:
            try:
                self.q.put(('status', ap.status()))
            except Exception:
                pass
            self.q.put(('end-done', None))

    def run(self, action):
        if self.busy:
            return
        if self.login_tab is not None and self.login_tab.busy:
            messagebox.showinfo('请稍候', '登录提交正在进行，请等它完成。')
            return
        if action == 'end-client':
            self.set_busy(True)
            def preview():
                try:
                    exe = ap.paths()['exe']
                    self.q.put(('end-preview', (exe, client_process.list_client_processes(exe))))
                except Exception as exc:
                    self.q.put(('error', str(exc)))
                    self.q.put(('done', None))
            threading.Thread(target=preview, daemon=True).start()
            return
        if action in ('patch', 'restore'):
            p = ap.paths()
            if not messagebox.askyesno('确认修改客户端',
                '此操作会替换客户端文件，存在启动失败风险。\n\n'
                '目标：%s\n备份：%s（或该路径的版本化副本）\n记录：%s\n\n'
                '工具将先备份、校验；账号授权、state 和 PKCE 不作绕过。\n继续？'
                % (p['asar'], p['backup'], os.path.join(p['userdata'], 'patch-manifest.json'))):
                return
        self.set_busy(True)
        threading.Thread(target=self._worker, args=(action,), daemon=True).start()

    def _worker(self, action):
        try:
            if action == 'patch':
                self.q.put(('log', '开始打补丁…'))
                res = ap.apply_patch()
                self.q.put(('log', '✓ 补丁完成'))
                self.q.put(('log', '  客户端版本：%s' % res.get('product_version')))
                self.q.put(('log', '  原包 SHA256：%s' % res['original_sha256']))
                self.q.put(('log', '  新包 SHA256：%s' % res['patched_sha256']))
                self.q.put(('log', '  备份：%s%s' % (res['backup'], '（新建）' if res['backup_created'] else '（沿用）')))
                for n in res.get('notes', []):
                    self.q.put(('log', '  注：%s' % n))
                checks = ap.verify_patched_app()
                for name, ok in checks:
                    self.q.put(('log', '  %s %s' % ('✓' if ok else '✗', name)))
                if not all(ok for _, ok in checks):
                    raise ap.PatchError('补丁写入后回读校验未全部通过，建议点「恢复官方版」。')
                self.q.put(('log', '现在可以打开 Antigravity 了，去「登录」页点 Continue with Google。'))
            elif action == 'restore':
                self.q.put(('log', '开始恢复官方版…'))
                res = ap.restore()
                self.q.put(('log', '✓ 已恢复为官方包'))
                self.q.put(('log', '  官方包 SHA256：%s' % res['restored_sha256']))
            else:
                info = ap.status()
                cur = info.get('interception_enabled', True)
                cfg = ap.set_switch(enabled=not cur)
                self.q.put(('log', '拦截开关 → %s（对下次启动生效）' % ('开启' if cfg['enabled'] else '暂停')))
        except ap.PatchError as exc:
            self.q.put(('error', str(exc)))
        except Exception as exc:
            self.q.put(('error', '%s: %s' % (type(exc).__name__, exc)))
        finally:
            try:
                self.q.put(('status', ap.status()))
            except Exception:
                pass
            self.q.put(('done', None))


class Main:
    def __init__(self, root):
        self.root = root
        root.title('%s — %s' % (APP_TITLE, AUTHOR))
        root.geometry('800x660')
        root.minsize(740, 600)
        root.option_add('*Font', FONT)
        try:
            ttk.Style().theme_use('vista')
        except Exception:
            pass

        nb = ttk.Notebook(root)
        nb.pack(fill='both', expand=True, padx=8, pady=(8, 4))
        login_tab = LoginTab(nb)
        nb.add(login_tab, text='  登  录  ')
        nb.add(PatchTab(nb, login_tab), text='  补  丁  ')

        foot = ttk.Frame(root, padding=(14, 0, 14, 8))
        foot.pack(side='bottom', fill='x')
        ttk.Separator(foot, orient='horizontal').pack(fill='x', pady=(0, 6))
        row = ttk.Frame(foot)
        row.pack(fill='x')
        ttk.Label(row, text='作者：', foreground='#6b7280').pack(side='left')
        ttk.Label(row, text=AUTHOR, font=('Microsoft YaHei UI', 9, 'bold')).pack(side='left')
        link = tk.Label(row, text=AUTHOR_URL, fg='#2563eb', cursor='hand2',
                        font=('Microsoft YaHei UI', 9, 'underline'))
        link.pack(side='left', padx=(10, 0))
        link.bind('<Button-1>', lambda _e: webbrowser.open(AUTHOR_URL))
        ttk.Label(row, text='点击打开店铺', foreground='#9ca3af').pack(side='left', padx=(8, 0))
        self.status_tip = ttk.Label(row, text='', foreground='#6b7280')
        self.status_tip.pack(side='right')


def main():
    if len(sys.argv) == 3 and sys.argv[1] == '--self-test':
        # Hidden, offline packaging smoke test. Never applies a patch or submits OAuth.
        report = {'version': ap.TOOL_VERSION, 'ok': False}
        root = None
        try:
            root = tk.Tk()
            root.withdraw()
            Main(root)
            root.update_idletasks()
            notebooks = [w for w in root.winfo_children() if isinstance(w, ttk.Notebook)]
            report['tabs'] = len(notebooks[0].tabs())
            patch_tab = notebooks[0].nametowidget(notebooks[0].tabs()[1])
            report['end_button'] = any(b.cget('text') == '一键结束客户端' for b in patch_tab.buttons)
            report['preflight'] = ap.apply_patch(dry_run=True)
            report['ok'] = report['tabs'] == 2 and report['end_button']
        except Exception as exc:
            report['error_type'] = type(exc).__name__
        finally:
            if root is not None:
                root.destroy()
            with open(sys.argv[2], 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
        return 0 if report['ok'] else 1
    root = tk.Tk()
    Main(root)
    root.mainloop()
    return 0


if __name__ == '__main__':
    sys.exit(main())
