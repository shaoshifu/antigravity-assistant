"""只用模拟进程测试结束功能；绝不终止真实客户端。"""
import subprocess
import unittest
from unittest.mock import patch
import client_process as cp

EXE = 'C:/mock/Antigravity.exe'
OTHER = 'C:/other/Antigravity.exe'


class FakeAPI:
    def __init__(self, items=None):
        self.items = items or {}
        self.killed = []
        self.closed = []
        self.denied = set()
        self.timeout = set()

    def open(self, pid, terminate=False):
        if pid in self.denied:
            raise cp.ProcessError('denied')
        return pid if pid in self.items else None

    def close(self, handle):
        self.closed.append(handle)

    def exited(self, handle):
        return self.items[handle].get('exited', False)

    def identity(self, handle, pid):
        return dict(self.items[handle], pid=pid)

    def terminate(self, handle):
        self.killed.append(handle)
        self.items[handle]['exited'] = True

    def wait(self, handle):
        return handle not in self.timeout


def item(pid, path=EXE, created=100):
    return {'pid': pid, 'path': path, 'created': created}


class ProcessTests(unittest.TestCase):
    def test_csv_exact_name_only(self):
        result = subprocess.CompletedProcess([], 0, '"Antigravity.exe","123","Console","1","1 K"\n"Antigravity助手.exe","456"\n')
        with patch.object(cp.subprocess, 'run', return_value=result):
            self.assertEqual(cp._candidate_pids(), [123])

    def test_csv_no_matches(self):
        with patch.object(cp.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'INFO: no tasks')):
            self.assertEqual(cp._candidate_pids(), [])

    def test_tasklist_failure_closed(self):
        with patch.object(cp.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '')):
            with self.assertRaises(cp.ProcessError): cp._candidate_pids()

    def test_tasklist_timeout_closed(self):
        with patch.object(cp.subprocess, 'run', side_effect=subprocess.TimeoutExpired('tasklist', 10)):
            with self.assertRaises(cp.ProcessError): cp._candidate_pids()

    def test_list_excludes_other_install(self):
        api = FakeAPI({1: item(1), 2: item(2, OTHER)})
        with patch.object(cp, '_WinAPI', return_value=api), patch.object(cp, '_candidate_pids', return_value=[1, 2]):
            self.assertEqual([r['pid'] for r in cp.list_client_processes(EXE)], [1])
        self.assertEqual(api.closed, [1, 2])
        self.assertEqual(api.killed, [])

    def test_ends_confirmed_and_rechecks(self):
        api = FakeAPI({1: item(1), 2: item(2)})
        with patch.object(cp, '_WinAPI', return_value=api), patch.object(cp, '_candidate_pids', return_value=[1, 2]):
            result = cp.end_client_processes(EXE, [item(1), item(2)])
        self.assertEqual(result['ended'], [1, 2])
        self.assertEqual(result['remaining'], [])

    def test_unconfirmed_no_termination(self):
        api = FakeAPI({1: item(1)})
        with patch.object(cp, '_WinAPI', return_value=api), patch.object(cp, '_candidate_pids', return_value=[1]):
            self.assertEqual(len(cp.end_client_processes(EXE, [])['remaining']), 1)
        self.assertEqual(api.killed, [])

    def test_other_path_rejected(self):
        with self.assertRaises(cp.ProcessError): cp.end_client_processes(EXE, [item(1, OTHER)])

    def test_reused_pid_rejects_all(self):
        api = FakeAPI({1: item(1), 2: item(2, created=101)})
        with patch.object(cp, '_WinAPI', return_value=api):
            with self.assertRaises(cp.ProcessError): cp.end_client_processes(EXE, [item(1), item(2)])
        self.assertEqual(api.killed, [])
        self.assertEqual(api.closed, [1, 2])

    def test_access_denied_rejects_all(self):
        api = FakeAPI({1: item(1), 2: item(2)})
        api.denied.add(2)
        with patch.object(cp, '_WinAPI', return_value=api):
            with self.assertRaises(cp.ProcessError): cp.end_client_processes(EXE, [item(1), item(2)])
        self.assertEqual(api.killed, [])
        self.assertEqual(api.closed, [1])

    def test_vanished_pid_safe(self):
        api = FakeAPI()
        with patch.object(cp, '_WinAPI', return_value=api), patch.object(cp, '_candidate_pids', return_value=[]):
            result = cp.end_client_processes(EXE, [item(1)])
        self.assertEqual(result['already_exited'], [1])
        self.assertEqual(api.killed, [])

    def test_new_process_not_killed(self):
        api = FakeAPI({1: item(1), 2: item(2)})
        with patch.object(cp, '_WinAPI', return_value=api), patch.object(cp, '_candidate_pids', return_value=[1, 2]):
            result = cp.end_client_processes(EXE, [item(1)])
        self.assertEqual(api.killed, [1])
        self.assertEqual([p['pid'] for p in result['remaining']], [2])

    def test_wait_timeout_stops(self):
        api = FakeAPI({1: item(1), 2: item(2)})
        api.timeout.add(1)
        with patch.object(cp, '_WinAPI', return_value=api):
            with self.assertRaises(cp.ProcessError): cp.end_client_processes(EXE, [item(1), item(2)])
        self.assertEqual(api.killed, [1])
        self.assertEqual(api.closed, [1, 2])

    def test_duplicate_pid_refused(self):
        with self.assertRaises(cp.ProcessError): cp.end_client_processes(EXE, [item(1), item(1)])


if __name__ == '__main__':
    unittest.main(verbosity=2)
