"""Windows 客户端精确结束：匹配安装路径、PID 与创建时间，持有句柄避免 PID 复用。"""
import csv
import ctypes
from ctypes import wintypes
import io
import os
import subprocess


class ProcessError(RuntimeError):
    pass


def _norm(path):
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))


def _candidate_pids():
    try:
        result = subprocess.run(
            ['tasklist', '/FI', 'IMAGENAME eq Antigravity.exe', '/FO', 'CSV', '/NH'],
            capture_output=True, text=True, errors='replace', timeout=10,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except Exception as exc:
        raise ProcessError('无法读取进程列表，未结束任何进程。') from exc
    if result.returncode:
        raise ProcessError('进程列表读取失败，未结束任何进程。')
    pids = []
    for row in csv.reader(io.StringIO(result.stdout or '')):
        if row and row[0].lower() == 'antigravity.exe':
            if len(row) < 2 or not row[1].isdigit() or int(row[1]) <= 0:
                raise ProcessError('进程列表格式异常，拒绝结束。')
            pids.append(int(row[1]))
    return sorted(set(pids))


class _WinAPI:
    QUERY = 0x1000
    TERMINATE = 0x0001
    SYNCHRONIZE = 0x00100000

    def __init__(self):
        if os.name != 'nt':
            raise ProcessError('此功能只支持 Windows。')
        self.k = ctypes.WinDLL('kernel32', use_last_error=True)
        self.k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.k.OpenProcess.restype = wintypes.HANDLE
        self.k.CloseHandle.argtypes = [wintypes.HANDLE]
        self.k.CloseHandle.restype = wintypes.BOOL
        self.k.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        self.k.QueryFullProcessImageNameW.restype = wintypes.BOOL
        self.k.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        self.k.GetProcessTimes.restype = wintypes.BOOL
        self.k.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        self.k.TerminateProcess.restype = wintypes.BOOL
        self.k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.k.WaitForSingleObject.restype = wintypes.DWORD

    def open(self, pid, terminate=False):
        rights = self.QUERY | self.SYNCHRONIZE | (self.TERMINATE if terminate else 0)
        handle = self.k.OpenProcess(rights, False, pid)
        if not handle:
            error = ctypes.get_last_error()
            if error == 87:  # process disappeared
                return None
            raise ProcessError('无法核实 PID %d（错误 %d），没有结束该进程。' % (pid, error))
        return handle

    def close(self, handle):
        self.k.CloseHandle(handle)

    def exited(self, handle):
        value = self.k.WaitForSingleObject(handle, 0)
        if value == 0xffffffff:
            raise ProcessError('无法读取进程状态。')
        return value == 0

    def identity(self, handle, pid):
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        if not self.k.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            raise ProcessError('无法读取 PID %d 的程序路径，拒绝结束。' % pid)
        creation, exit_time, kernel, user = (wintypes.FILETIME() for _ in range(4))
        if not self.k.GetProcessTimes(handle, ctypes.byref(creation), ctypes.byref(exit_time), ctypes.byref(kernel), ctypes.byref(user)):
            raise ProcessError('无法读取 PID %d 的创建时间，拒绝结束。' % pid)
        stamp = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
        return {'pid': pid, 'path': buffer.value, 'created': stamp}

    def terminate(self, handle):
        if not self.k.TerminateProcess(handle, 1) and not self.exited(handle):
            raise ProcessError('Windows 拒绝结束进程（可能需要相同用户权限）。')

    def wait(self, handle):
        return self.k.WaitForSingleObject(handle, 3000) == 0


def list_client_processes(exe_path):
    """只读列出当前安装路径的客户端，不包含其他目录的同名程序。"""
    api = _WinAPI()
    matches = []
    target = _norm(exe_path)
    for pid in _candidate_pids():
        handle = api.open(pid)
        if handle is None:
            continue
        try:
            if api.exited(handle):
                continue
            item = api.identity(handle, pid)
            if _norm(item['path']) == target:
                matches.append(item)
        finally:
            api.close(handle)
    return matches


def end_client_processes(exe_path, confirmed):
    """仅结束用户已确认的身份。新出现/复用 PID 不补杀，不修改任何文件。"""
    if not confirmed:
        return {'ended': [], 'already_exited': [], 'remaining': list_client_processes(exe_path)}
    target = _norm(exe_path)
    if any(_norm(item['path']) != target for item in confirmed):
        raise ProcessError('确认列表包含其他安装路径，拒绝结束。')
    if len({item['pid'] for item in confirmed}) != len(confirmed):
        raise ProcessError('确认列表存在重复 PID，拒绝结束。')
    api = _WinAPI()
    opened = []
    ended, gone = [], []
    try:
        # 所有身份/权限验证完成才开始结束，验证失败不执行部分结束。
        for item in confirmed:
            handle = api.open(item['pid'], terminate=True)
            if handle is None:
                gone.append(item['pid'])
                continue
            opened.append((handle, item))
            if api.exited(handle):
                continue
            current = api.identity(handle, item['pid'])
            if _norm(current['path']) != target or current['created'] != item['created']:
                raise ProcessError('PID %d 的身份已变化，已取消结束，请刷新后重试。' % item['pid'])
        for handle, item in opened:
            if api.exited(handle):
                gone.append(item['pid'])
                continue
            api.terminate(handle)
            if not api.wait(handle):
                raise ProcessError('PID %d 尚未退出，未自动重试；请刷新状态。已结束 PID：%s' % (item['pid'], ended))
            ended.append(item['pid'])
    finally:
        for handle, _ in opened:
            api.close(handle)
    return {'ended': ended, 'already_exited': gone, 'remaining': list_client_processes(exe_path)}
