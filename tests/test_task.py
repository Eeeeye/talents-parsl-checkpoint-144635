#!/usr/bin/env python3
from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import os
import pickle
import random
import secrets
import signal
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


WORKSPACE: Path
TEST_ROOT: Path
PYTHON = sys.executable


PR_SET_DUMPABLE = 4
PR_SET_NO_NEW_PRIVS = 38
SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_ERRNO = 0x00050000


def make_verifier_private() -> None:
    """Keep same-UID candidate code from inspecting trusted verifier memory/FDs."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def install_probe_seccomp() -> None:
    """Install a fail-closed syscall policy inherited by every probe descendant."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))

    seccomp = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    seccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int
    seccomp.seccomp_rule_add.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    seccomp.seccomp_rule_add.restype = ctypes.c_int
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_load.restype = ctypes.c_int
    seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_release.restype = None

    context = seccomp.seccomp_init(SCMP_ACT_ALLOW)
    if not context:
        raise RuntimeError("seccomp_init failed")
    denied = (
        # Do not let candidate code signal, inspect, or move the verifier.
        "kill", "tkill", "tgkill", "rt_sigqueueinfo", "rt_tgsigqueueinfo",
        "pidfd_open", "pidfd_getfd", "pidfd_send_signal", "ptrace", "kcmp",
        "process_vm_readv", "process_vm_writev", "setpgid", "setsid",
        # Do not let a probe escape its mount/namespace or install kernel code.
        "mount", "umount2", "pivot_root", "chroot", "setns", "unshare",
        "open_by_handle_at", "name_to_handle_at", "bpf",
        "perf_event_open", "userfaultfd", "io_uring_setup", "io_uring_enter",
        "io_uring_register", "init_module", "finit_module", "delete_module",
        "kexec_load", "kexec_file_load", "reboot", "swapon", "swapoff",
        # Probes need ordinary files, pipes, forks and threads, but no network.
        "socket", "socketpair", "connect", "bind", "listen", "accept",
        "accept4", "sendto", "sendmsg", "sendmmsg", "recvfrom", "recvmsg",
        "recvmmsg", "shutdown",
        # Protect trusted/log paths from destructive namespace manipulation.
        "link", "linkat", "symlink", "symlinkat", "rename", "renameat",
        "renameat2", "rmdir", "mknod", "mknodat",
        "chmod", "fchmod", "fchmodat", "fchmodat2", "chown", "fchown",
        "lchown", "fchownat",
    )
    action = SCMP_ACT_ERRNO | errno.EPERM
    try:
        for name in denied:
            number = seccomp.seccomp_syscall_resolve_name(name.encode("ascii"))
            if number < 0:
                continue
            result = seccomp.seccomp_rule_add(context, action, number, 0)
            if result != 0:
                raise OSError(-result, f"seccomp rule failed for {name}")
        result = seccomp.seccomp_load(context)
        if result != 0:
            raise OSError(-result, "seccomp_load failed")
    finally:
        seccomp.seccomp_release(context)


def terminate_probe_group(process: subprocess.Popen[str]) -> None:
    """Kill descendants which inherited the probe group and sandbox."""
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(f"probe group {process.pid} did not terminate") from exc


PROBE_HEADER = r'''
from __future__ import annotations
import hashlib
import json
import os
import pickle
import sys
import threading
import time
import subprocess
from concurrent.futures import ThreadPoolExecutor as GatePool
from pathlib import Path

_probe_fd = os.environ.pop("PARSL_PROBE_FD", "")
if _probe_fd:
    os.close(int(_probe_fd))

import parsl
from parsl.app.app import join_app, python_app
from parsl.config import Config
from parsl.dataflow.errors import BadCheckpoint
from parsl.executors.threads import ThreadPoolExecutor

ROOT = Path(sys.argv[1])
ROOT.mkdir(parents=True, exist_ok=True)
os.chdir(ROOT)

def config(run_root, *, mode="task_exit", files=None, threads=4, period=None,
           retries=0, garbage_collect=True):
    kwargs = dict(
        executors=[ThreadPoolExecutor(max_threads=threads, label="local")],
        checkpoint_mode=mode,
        run_dir=str(run_root),
        initialize_logging=False,
        usage_tracking=0,
        strategy="none",
        retries=retries,
        garbage_collect=garbage_collect,
    )
    if period is not None:
        kwargs["checkpoint_period"] = period
    if files is not None:
        kwargs["checkpoint_files"] = [str(p) for p in files]
    return Config(**kwargs)

def close_dfk():
    try:
        parsl.dfk().cleanup()
    finally:
        parsl.clear()

def decode(path):
    items = []
    with Path(path).open("rb") as stream:
        while True:
            try:
                item = pickle.load(stream)
            except EOFError:
                return items
            if not isinstance(item, dict) or set(item) != {"hash", "exception", "result"}:
                raise AssertionError("invalid checkpoint schema")
            if not isinstance(item["hash"], str) or item["exception"] is not None:
                raise AssertionError("invalid checkpoint values")
            items.append(item)

def emit(value):
    print(json.dumps(value, sort_keys=True))
'''


def run_probe(name: str, body: str, timeout: float = 35.0) -> dict:
    case_root = TEST_ROOT / secrets.token_hex(16)
    case_root.mkdir(parents=True, exist_ok=False)
    script = case_root / "probe.py"
    script.write_text(PROBE_HEADER + "\n" + textwrap.dedent(body), encoding="utf-8")
    script_fd = os.open(script, os.O_RDONLY)
    script.unlink()
    env = os.environ.copy()
    env.update(
        PYTHONPATH=str(WORKSPACE),
        PYTHONDONTWRITEBYTECODE="1",
        PYTHONUNBUFFERED="1",
        PARSL_PROBE_FD=str(script_fd),
    )
    try:
        process = subprocess.Popen(
            [PYTHON, "-B", f"/proc/self/fd/{script_fd}", str(case_root / "work")],
            cwd=case_root,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            preexec_fn=install_probe_seccomp,
            pass_fds=(script_fd,),
        )
    finally:
        os.close(script_fd)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        terminate_probe_group(process)
        stdout, stderr = process.communicate()
        raise AssertionError(
            f"probe {name} timed out after {timeout:.1f}s\n"
            f"stdout:\n{stdout}\nstderr:\n{stderr}"
        ) from exc
    finally:
        terminate_probe_group(process)
    if process.returncode != 0:
        raise AssertionError(
            f"probe {name} failed with {process.returncode}\n"
            f"stdout:\n{stdout}\nstderr:\n{stderr}"
        )
    lines = [line for line in stdout.splitlines() if line.strip()]
    if not lines:
        raise AssertionError(f"probe {name} produced no report")
    try:
        return __import__("json").loads(lines[-1])
    except Exception as exc:
        raise AssertionError(f"probe {name} produced invalid report: {lines[-1]!r}") from exc


class TaskTests(unittest.TestCase):
    def test_01_publication_boundary_nested_value(self) -> None:
        token = secrets.token_hex(13)
        value = {
            "token": token,
            "grid": [[random.randint(-5000, 5000) for _ in range(4)] for _ in range(3)],
            "meta": {"enabled": True, "label": secrets.token_hex(7)},
        }
        report = run_probe(
            "publication_nested",
            f'''
            VALUE = {value!r}
            TOKEN = {token!r}

            @python_app(cache=True)
            def work(token, value):
                import os
                fd = os.open("marker.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try:
                    os.write(fd, (token + "\\n").encode())
                    os.fsync(fd)
                finally:
                    os.close(fd)
                return value

            dfk = parsl.load(config(ROOT / "runinfo"))
            release = threading.Event()
            original = getattr(dfk, "handle_app_update", None)
            if original is not None:
                def delayed(record, future):
                    if not release.wait(10):
                        raise RuntimeError("callback gate timed out")
                    return original(record, future)
                dfk.handle_app_update = delayed

            first = work(TOKEN, VALUE)
            first_value = first.result(timeout=10)
            checkpoint = Path(dfk.run_dir) / "checkpoint" / "tasks.pkl"
            before = checkpoint.exists()
            records_before = decode(checkpoint) if before else []
            second = work(TOKEN, VALUE)
            second_value = second.result(timeout=10)
            second_from_memo = bool(second.task_record.get("from_memo"))
            executions = Path("marker.log").read_text().splitlines()
            release.set()
            close_dfk()
            emit({{
                "first": first_value,
                "second": second_value,
                "checkpoint_before": before,
                "records_before": len(records_before),
                "second_from_memo": second_from_memo,
                "executions": executions,
            }})
            ''',
        )
        self.assertEqual(report["first"], value)
        self.assertEqual(report["second"], value)
        self.assertTrue(report["checkpoint_before"])
        self.assertGreaterEqual(report["records_before"], 1)
        self.assertTrue(report["second_from_memo"])
        self.assertEqual(report["executions"], [token])

    def test_02_publication_boundary_none(self) -> None:
        token = secrets.token_hex(12)
        report = run_probe(
            "publication_none",
            f'''
            TOKEN = {token!r}
            @python_app(cache=True)
            def return_none(token):
                import os
                fd = os.open("marker.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try:
                    os.write(fd, (token + "\\n").encode())
                    os.fsync(fd)
                finally:
                    os.close(fd)
                return None

            dfk = parsl.load(config(ROOT / "runinfo"))
            release = threading.Event()
            original = getattr(dfk, "handle_app_update", None)
            if original is not None:
                def delayed(record, future):
                    if not release.wait(10): raise RuntimeError("callback gate timed out")
                    return original(record, future)
                dfk.handle_app_update = delayed
            first = return_none(TOKEN)
            first_result = first.result(timeout=10)
            checkpoint = Path(dfk.run_dir) / "checkpoint" / "tasks.pkl"
            checkpoint_exists = checkpoint.exists()
            records = decode(checkpoint) if checkpoint_exists else []
            second = return_none(TOKEN)
            second_result = second.result(timeout=10)
            from_memo = bool(second.task_record.get("from_memo"))
            executions = Path("marker.log").read_text().splitlines()
            release.set(); close_dfk()
            emit({{"first_is_none": first_result is None, "second_is_none": second_result is None,
                  "checkpoint_exists": checkpoint_exists,
                  "checkpoint_none": any(r["result"] is None for r in records),
                  "from_memo": from_memo, "executions": executions}})
            ''',
        )
        self.assertTrue(report["first_is_none"])
        self.assertTrue(report["second_is_none"])
        self.assertTrue(report["checkpoint_exists"])
        self.assertTrue(report["checkpoint_none"])
        self.assertTrue(report["from_memo"])
        self.assertEqual(report["executions"], [token])

    def test_03_automatic_cross_run_recovery(self) -> None:
        token = secrets.token_hex(14)
        value = [random.randint(-(2**31), 2**31 - 1) for _ in range(11)]
        report = run_probe(
            "automatic_restart",
            f'''
            TOKEN = {token!r}; VALUE = {value!r}
            worker = ROOT / "restart_worker.py"
            worker.write_text("import json, os, sys\\n"
                              "from pathlib import Path\\n"
                              "import parsl\\n"
                              "from parsl.app.app import python_app\\n"
                              "from parsl.config import Config\\n"
                              "from parsl.executors.threads import ThreadPoolExecutor\\n"
                              "root=Path(sys.argv[1]); token=sys.argv[2]; value=json.loads(sys.argv[3]); os.chdir(root)\\n"
                              "@python_app(cache=True)\\n"
                              "def durable(token, value):\\n"
                              " import os\\n"
                              " fd=os.open('marker.log', os.O_WRONLY|os.O_CREAT|os.O_APPEND, 0o600)\\n"
                              " try: os.write(fd, (token+'\\\\n').encode()); os.fsync(fd)\\n"
                              " finally: os.close(fd)\\n"
                              " return value\\n"
                              "parsl.load(Config(executors=[ThreadPoolExecutor(max_threads=2,label='local')], checkpoint_mode='task_exit', run_dir=str(root/'runinfo'), initialize_logging=False, usage_tracking=0, strategy='none'))\\n"
                              "future=durable(token,value); result=future.result(timeout=10)\\n"
                              "report={{'result':result,'from_memo':bool(future.task_record.get('from_memo')),'run_dir':parsl.dfk().run_dir}}\\n"
                              "parsl.dfk().cleanup(); parsl.clear(); print(json.dumps(report,sort_keys=True))\\n")
            def one():
                completed = subprocess.run([sys.executable, "-B", str(worker), str(ROOT), TOKEN,
                                            json.dumps(VALUE, sort_keys=True)], text=True,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
                if completed.returncode != 0:
                    raise RuntimeError(completed.stderr)
                return json.loads(completed.stdout.splitlines()[-1])
            a = one(); b = one()
            emit({{"first": a["result"], "second": b["result"],
                  "first_memo": a["from_memo"], "second_memo": b["from_memo"],
                  "first_run": Path(a["run_dir"]).name, "second_run": Path(b["run_dir"]).name,
                  "executions": Path("marker.log").read_text().splitlines()}})
            ''',
        )
        self.assertEqual(report["first"], value)
        self.assertEqual(report["second"], value)
        self.assertFalse(report["first_memo"])
        self.assertTrue(report["second_memo"])
        self.assertEqual(report["first_run"], "000")
        self.assertEqual(report["second_run"], "001")
        self.assertEqual(report["executions"], [token])

    def test_04_explicit_checkpoint_outside_run_root(self) -> None:
        token = secrets.token_hex(14)
        value = {"token": token, "value": random.random(), "items": [2, 3, 5, 7]}
        report = run_probe(
            "explicit_restart",
            f'''
            TOKEN = {token!r}; VALUE = {value!r}
            @python_app(cache=True)
            def durable(token, value):
                import os
                fd = os.open("marker.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try: os.write(fd, (token + "\\n").encode()); os.fsync(fd)
                finally: os.close(fd)
                return value
            parsl.load(config(ROOT / "source-runs"))
            first = durable(TOKEN, VALUE); first_value = first.result(timeout=10)
            checkpoint_dir = Path(parsl.dfk().run_dir) / "checkpoint"
            close_dfk()
            parsl.load(config(ROOT / "unrelated-runs", files=[checkpoint_dir]))
            second = durable(TOKEN, VALUE); second_value = second.result(timeout=10)
            second_memo = bool(second.task_record.get("from_memo"))
            close_dfk()
            emit({{"first": first_value, "second": second_value, "second_memo": second_memo,
                  "executions": Path("marker.log").read_text().splitlines()}})
            ''',
        )
        self.assertEqual(report["first"], value)
        self.assertEqual(report["second"], value)
        self.assertTrue(report["second_memo"])
        self.assertEqual(report["executions"], [token])

    def test_05_manual_mode_and_concurrent_completion(self) -> None:
        tokens = [secrets.token_hex(10) for _ in range(18)]
        report = run_probe(
            "manual_concurrent",
            f'''
            TOKENS = {tokens!r}
            @python_app(cache=True)
            def compute(index, token):
                import hashlib, os, time
                time.sleep((index % 5) * 0.002)
                fd = os.open("marker.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try: os.write(fd, (token + "\\n").encode()); os.fsync(fd)
                finally: os.close(fd)
                return {{"index": index, "digest": hashlib.sha256(token.encode()).hexdigest()}}
            dfk = parsl.load(config(ROOT / "runinfo", mode="manual", threads=8))
            futures = [compute(i, t) for i, t in enumerate(TOKENS)]
            stop = threading.Event(); errors = []
            def pump():
                while not stop.wait(0.001):
                    try: dfk.checkpoint()
                    except BaseException as exc: errors.append(repr(exc)); return
            thread = threading.Thread(target=pump, daemon=True); thread.start()
            values = [f.result(timeout=15) for f in futures]
            stop.set(); thread.join(10); dfk.checkpoint()
            checkpoint = Path(dfk.run_dir) / "checkpoint" / "tasks.pkl"
            records = decode(checkpoint); close_dfk()
            expected = [{{"index": i, "digest": hashlib.sha256(t.encode()).hexdigest()}} for i, t in enumerate(TOKENS)]
            checkpoint_results = [r["result"] for r in records]
            emit({{"values": values, "expected": expected, "records": checkpoint_results,
                  "errors": errors, "executions": sorted(Path("marker.log").read_text().splitlines())}})
            ''',
            timeout=45,
        )
        self.assertEqual(report["values"], report["expected"])
        self.assertEqual(report["errors"], [])
        self.assertEqual(len(report["records"]), len(tokens))
        self.assertCountEqual(report["records"], report["expected"])
        self.assertEqual(report["executions"], sorted(tokens))

    def test_06_dfk_exit_deferred_mode(self) -> None:
        tokens = [secrets.token_hex(11) for _ in range(7)]
        report = run_probe(
            "dfk_exit",
            f'''
            TOKENS = {tokens!r}
            @python_app(cache=True)
            def compute(token): return {{"token": token, "length": len(token)}}
            parsl.load(config(ROOT / "runinfo", mode="dfk_exit", threads=4))
            values = [compute(t).result(timeout=10) for t in TOKENS]
            run_dir = Path(parsl.dfk().run_dir)
            checkpoint = run_dir / "checkpoint" / "tasks.pkl"
            before = checkpoint.exists()
            close_dfk()
            records = decode(checkpoint)
            emit({{"before": before, "values": values, "records": [r["result"] for r in records]}})
            ''',
        )
        expected = [{"token": token, "length": len(token)} for token in tokens]
        self.assertFalse(report["before"])
        self.assertEqual(report["values"], expected)
        self.assertCountEqual(report["records"], expected)

    def test_07_failed_task_is_not_successfully_checkpointed(self) -> None:
        token = secrets.token_hex(15)
        report = run_probe(
            "failed_task",
            f'''
            TOKEN = {token!r}
            @python_app(cache=True)
            def fails(token):
                import os
                fd = os.open("marker.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try: os.write(fd, (token + "\\n").encode()); os.fsync(fd)
                finally: os.close(fd)
                raise RuntimeError("failure-" + token)
            parsl.load(config(ROOT / "runinfo"))
            messages = []; memo_flags = []
            for _ in range(2):
                future = fails(TOKEN)
                try: future.result(timeout=10)
                except RuntimeError as exc: messages.append(str(exc))
                else: messages.append("NO_EXCEPTION")
                memo_flags.append(bool(future.task_record.get("from_memo")))
            checkpoint = Path(parsl.dfk().run_dir) / "checkpoint" / "tasks.pkl"
            records = decode(checkpoint) if checkpoint.exists() else []
            close_dfk()
            emit({{"messages": messages, "memo": memo_flags, "record_count": len(records),
                  "executions": Path("marker.log").read_text().splitlines()}})
            ''',
        )
        self.assertEqual(report["messages"], [f"failure-{token}", f"failure-{token}"])
        self.assertEqual(report["record_count"], 0)
        self.assertIn(len(report["executions"]), (1, 2))
        self.assertTrue(all(item == token for item in report["executions"]))

    def test_08_periodic_mode_flushes_completed_outcomes(self) -> None:
        tokens = [secrets.token_hex(9) for _ in range(5)]
        report = run_probe(
            "periodic",
            f'''
            TOKENS = {tokens!r}
            @python_app(cache=True)
            def compute(token): return {{"token": token, "size": len(token)}}
            parsl.load(config(ROOT / "runinfo", mode="periodic", threads=3, period="00:00:01"))
            values = [compute(t).result(timeout=10) for t in TOKENS]
            checkpoint = Path(parsl.dfk().run_dir) / "checkpoint" / "tasks.pkl"
            deadline = time.monotonic() + 5
            records = []
            while time.monotonic() < deadline:
                if checkpoint.exists():
                    records = decode(checkpoint)
                    if len(records) == len(TOKENS): break
                time.sleep(0.05)
            close_dfk()
            emit({{"values": values, "records": [r["result"] for r in records]}})
            ''',
        )
        expected = [{"token": token, "size": len(token)} for token in tokens]
        self.assertEqual(report["values"], expected)
        self.assertCountEqual(report["records"], expected)

    def test_09_retry_then_success_preserves_checkpoint_semantics(self) -> None:
        token = secrets.token_hex(13)
        report = run_probe(
            "retry_success",
            f'''
            TOKEN = {token!r}
            @python_app(cache=True)
            def flaky(token):
                import os
                path = "attempts.log"
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try: os.write(fd, (token + "\\n").encode()); os.fsync(fd)
                finally: os.close(fd)
                attempts = Path(path).read_text().splitlines().count(token)
                if attempts == 1: raise RuntimeError("transient-" + token)
                return {{"token": token, "attempts": attempts}}
            parsl.load(config(ROOT / "runinfo", retries=1))
            first = flaky(TOKEN); first_value = first.result(timeout=10)
            second = flaky(TOKEN); second_value = second.result(timeout=10)
            second_memo = bool(second.task_record.get("from_memo"))
            checkpoint = Path(parsl.dfk().run_dir) / "checkpoint" / "tasks.pkl"
            records = decode(checkpoint); close_dfk()
            emit({{"first": first_value, "second": second_value, "second_memo": second_memo,
                  "records": [r["result"] for r in records],
                  "attempts": Path("attempts.log").read_text().splitlines()}})
            ''',
        )
        expected = {"token": token, "attempts": 2}
        self.assertEqual(report["first"], expected)
        self.assertEqual(report["second"], expected)
        self.assertTrue(report["second_memo"])
        self.assertIn(expected, report["records"])
        self.assertEqual(report["attempts"], [token, token])

    def test_10_join_app_preserves_inner_result_and_checkpoint(self) -> None:
        token = secrets.token_hex(13)
        report = run_probe(
            "join_behavior",
            f'''
            TOKEN = {token!r}

            @python_app(cache=True)
            def inner(token):
                import os
                fd = os.open("join-marker.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try: os.write(fd, (token + "\\n").encode()); os.fsync(fd)
                finally: os.close(fd)
                return {{"token": token, "length": len(token)}}

            @join_app
            def outer(token):
                return inner(token)

            parsl.load(config(ROOT / "runinfo"))
            first = outer(TOKEN); first_value = first.result(timeout=10)
            second = inner(TOKEN); second_value = second.result(timeout=10)
            checkpoint = Path(parsl.dfk().run_dir) / "checkpoint" / "tasks.pkl"
            records = decode(checkpoint); close_dfk()
            emit({{"first": first_value, "second": second_value,
                  "second_memo": bool(second.task_record.get("from_memo")),
                  "records": [r["result"] for r in records],
                  "executions": Path("join-marker.log").read_text().splitlines()}})
            ''',
        )
        expected = {"token": token, "length": len(token)}
        self.assertEqual(report["first"], expected)
        self.assertEqual(report["second"], expected)
        self.assertTrue(report["second_memo"])
        self.assertIn(expected, report["records"])
        self.assertEqual(report["executions"], [token])

    def test_11_invalid_checkpoints_fail_closed_and_remain_unchanged(self) -> None:
        report = run_probe(
            "invalid_checkpoints",
            r'''
            class RecordDict(dict):
                pass

            fixtures = {}
            missing = ROOT / "missing"
            fixtures["missing"] = missing

            empty = ROOT / "empty"; empty.mkdir()
            (empty / "tasks.pkl").write_bytes(b"")
            fixtures["empty"] = empty

            truncated = ROOT / "truncated"; truncated.mkdir()
            valid = pickle.dumps({"hash": "a" * 32, "exception": None, "result": {"x": 1}})
            (truncated / "tasks.pkl").write_bytes(valid + pickle.dumps({"hash": "b" * 32, "exception": None, "result": [1,2,3]})[:-5])
            fixtures["truncated"] = truncated

            eof_suffix = ROOT / "eof_suffix"; eof_suffix.mkdir()
            (eof_suffix / "tasks.pkl").write_bytes(valid + b"(")
            fixtures["eof_suffix"] = eof_suffix

            wrong_keys = ROOT / "wrong_keys"; wrong_keys.mkdir()
            (wrong_keys / "tasks.pkl").write_bytes(pickle.dumps({"hash": "c" * 32, "result": 7}))
            fixtures["wrong_keys"] = wrong_keys

            dict_subclass = ROOT / "dict_subclass"; dict_subclass.mkdir()
            (dict_subclass / "tasks.pkl").write_bytes(
                pickle.dumps(RecordDict(hash="d" * 32, exception=None, result=9))
            )
            fixtures["dict_subclass"] = dict_subclass

            exception_record = ROOT / "exception_record"; exception_record.mkdir()
            (exception_record / "tasks.pkl").write_bytes(
                pickle.dumps({"hash": "e" * 32, "exception": "not-none", "result": 11})
            )
            fixtures["exception_record"] = exception_record

            trailing = ROOT / "trailing"; trailing.mkdir()
            (trailing / "tasks.pkl").write_bytes(valid + b"not-a-pickle-record")
            fixtures["trailing"] = trailing

            reports = {}
            for name, directory in fixtures.items():
                file = directory / "tasks.pkl"
                before = hashlib.sha256(file.read_bytes()).hexdigest() if file.exists() else None
                try:
                    parsl.load(config(ROOT / ("runs-" + name), files=[directory]))
                except BadCheckpoint:
                    outcome = "BadCheckpoint"
                except BaseException as exc:
                    outcome = type(exc).__name__
                else:
                    outcome = "ACCEPTED"
                    close_dfk()
                after = hashlib.sha256(file.read_bytes()).hexdigest() if file.exists() else None
                reports[name] = {"outcome": outcome, "unchanged": before == after}
            emit(reports)
            ''',
        )
        for name in (
            "missing", "empty", "truncated", "eof_suffix", "wrong_keys",
            "dict_subclass", "exception_record", "trailing",
        ):
            self.assertEqual(report[name]["outcome"], "BadCheckpoint", name)
            self.assertTrue(report[name]["unchanged"], name)

    def test_12_terminal_futures_finalize_task_table_before_callbacks(self) -> None:
        token = secrets.token_hex(14)
        report = run_probe(
            "terminal_finalization",
            f'''
            TOKEN = {token!r}

            @python_app(cache=True)
            def succeed(token):
                return {{"token": token, "kind": "success"}}

            @python_app(cache=True)
            def fail(token):
                raise RuntimeError("failure-" + token)

            @python_app(cache=False)
            def consume(value):
                return value

            @join_app
            def invalid_join(token):
                return {{"token": token, "not": "a future"}}

            @join_app
            def failing_join(token):
                return fail(token + "-join-inner")

            dfk = parsl.load(config(ROOT / "runinfo", mode="manual", threads=8))
            callback_gates = {{}}
            original_callback = getattr(dfk, "handle_app_update", None)
            if original_callback is not None:
                def delayed_callback(record, future):
                    if any(
                        isinstance(arg, str) and arg.endswith("-join-inner")
                        for arg in record["args"]
                    ):
                        return original_callback(record, future)
                    gate = callback_gates.setdefault(record["id"], threading.Event())
                    if not gate.wait(10):
                        raise RuntimeError("callback gate timed out")
                    return original_callback(record, future)
                dfk.handle_app_update = delayed_callback

            observed = []
            def observe(future):
                observed.append({{
                    "tid": future.tid,
                    "present": future.tid in dfk.tasks,
                }})
                callback_gates.setdefault(future.tid, threading.Event()).set()

            first = succeed(TOKEN)
            first_value = first.result(timeout=10)
            observe(first)
            memo = succeed(TOKEN)
            memo_value = memo.result(timeout=10)
            observe(memo)

            terminal = fail(TOKEN + "-terminal")
            try:
                terminal.result(timeout=10)
            except BaseException as exc:
                terminal_error = type(exc).__name__
            else:
                terminal_error = "NO_ERROR"
            observe(terminal)

            dependency_source = fail(TOKEN + "-dependency")
            dependent = consume(dependency_source)
            try:
                dependency_source.result(timeout=10)
            except BaseException as exc:
                source_error = type(exc).__name__
            else:
                source_error = "NO_ERROR"
            observe(dependency_source)
            try:
                dependent.result(timeout=10)
            except BaseException as exc:
                dependency_error = type(exc).__name__
            else:
                dependency_error = "NO_ERROR"
            observe(dependent)

            invalid = invalid_join(TOKEN)
            try:
                invalid.result(timeout=10)
            except BaseException as exc:
                invalid_error = type(exc).__name__
            else:
                invalid_error = "NO_ERROR"
            observe(invalid)

            joined = failing_join(TOKEN)
            try:
                joined.result(timeout=10)
            except BaseException as exc:
                join_error = type(exc).__name__
            else:
                join_error = "NO_ERROR"
            observe(joined)

            expected_tids = [
                first.tid, memo.tid, terminal.tid, dependency_source.tid,
                dependent.tid, invalid.tid, joined.tid,
            ]
            close_dfk()

            retained_dfk = parsl.load(config(
                ROOT / "retained", mode=None, threads=2, garbage_collect=False
            ))
            retained = succeed(TOKEN + "-retained")
            retained_value = retained.result(timeout=10)
            retained_after = retained.tid in retained_dfk.tasks
            close_dfk()

            emit({{
                "first": first_value,
                "memo": memo_value,
                "memo_hit": bool(memo.task_record.get("from_memo")),
                "errors": [terminal_error, source_error, dependency_error,
                           invalid_error, join_error],
                "expected_tids": expected_tids,
                "observed": observed,
                "retained": retained_value,
                "retained_after": retained_after,
            }})
            ''',
            timeout=50,
        )
        expected_value = {"token": token, "kind": "success"}
        self.assertEqual(report["first"], expected_value)
        self.assertEqual(report["memo"], expected_value)
        self.assertTrue(report["memo_hit"])
        self.assertEqual(
            report["errors"],
            ["RuntimeError", "RuntimeError", "DependencyError", "TypeError", "JoinError"],
        )
        self.assertEqual(report["expected_tids"], [
            item["tid"] for item in report["observed"]
        ])
        self.assertTrue(all(not item["present"] for item in report["observed"]))
        self.assertEqual(
            report["retained"],
            {"token": token + "-retained", "kind": "success"},
        )
        self.assertTrue(report["retained_after"])

    def test_13_explicit_empty_checkpoint_list_disables_auto_recovery(self) -> None:
        token = secrets.token_hex(14)
        value = {"token": token, "nonce": random.randint(1, 2**31 - 1)}
        report = run_probe(
            "explicit_empty_checkpoint_list",
            f'''
            TOKEN = {token!r}; VALUE = {value!r}

            @python_app(cache=True)
            def durable(token, value):
                import os
                fd = os.open("marker.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try: os.write(fd, (token + "\\n").encode()); os.fsync(fd)
                finally: os.close(fd)
                return value

            run_root = ROOT / "runinfo"
            parsl.load(config(run_root))
            first = durable(TOKEN, VALUE)
            first_value = first.result(timeout=10)
            close_dfk()

            parsl.load(config(run_root, files=[]))
            second = durable(TOKEN, VALUE)
            second_value = second.result(timeout=10)
            second_memo = bool(second.task_record.get("from_memo"))
            second_run = Path(parsl.dfk().run_dir).name
            close_dfk()
            emit({{
                "first": first_value,
                "second": second_value,
                "second_memo": second_memo,
                "second_run": second_run,
                "executions": Path("marker.log").read_text().splitlines(),
            }})
            ''',
        )
        self.assertEqual(report["first"], value)
        self.assertEqual(report["second"], value)
        self.assertFalse(report["second_memo"])
        self.assertEqual(report["second_run"], "001")
        self.assertEqual(report["executions"], [token, token])

    def test_14_auto_recovery_uses_numeric_runs_and_ignores_other_dirs(self) -> None:
        token = secrets.token_hex(14)
        newest = {"token": token, "source": "run-1000", "value": random.random()}
        report = run_probe(
            "numeric_checkpoint_order",
            f'''
            TOKEN = {token!r}; NEWEST = {newest!r}

            @python_app(cache=True)
            def durable(token):
                import os
                fd = os.open("marker.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try: os.write(fd, (token + "\\n").encode()); os.fsync(fd)
                finally: os.close(fd)
                return {{"token": token, "source": "executed"}}

            run_root = ROOT / "runinfo"
            parsl.load(config(run_root))
            initial = durable(TOKEN)
            initial_value = initial.result(timeout=10)
            initial_checkpoint = Path(parsl.dfk().run_dir) / "checkpoint" / "tasks.pkl"
            close_dfk()
            template = decode(initial_checkpoint)[0]

            older_dir = run_root / "999" / "checkpoint"
            newer_dir = run_root / "1000" / "checkpoint"
            unrelated_dir = run_root / "scratch" / "checkpoint"
            older_dir.mkdir(parents=True)
            newer_dir.mkdir(parents=True)
            unrelated_dir.mkdir(parents=True)
            older = dict(template); older["result"] = {{"token": TOKEN, "source": "run-999"}}
            newer = dict(template); newer["result"] = NEWEST
            (older_dir / "tasks.pkl").write_bytes(pickle.dumps(older))
            (newer_dir / "tasks.pkl").write_bytes(pickle.dumps(newer))
            (unrelated_dir / "tasks.pkl").write_bytes(b"(")

            parsl.load(config(run_root))
            restored = durable(TOKEN)
            restored_value = restored.result(timeout=10)
            restored_memo = bool(restored.task_record.get("from_memo"))
            restored_run = Path(parsl.dfk().run_dir).name
            close_dfk()
            emit({{
                "initial": initial_value,
                "restored": restored_value,
                "restored_memo": restored_memo,
                "restored_run": restored_run,
                "executions": Path("marker.log").read_text().splitlines(),
            }})
            ''',
        )
        self.assertEqual(report["initial"], {"token": token, "source": "executed"})
        self.assertEqual(report["restored"], newest)
        self.assertTrue(report["restored_memo"])
        self.assertEqual(report["restored_run"], "1001")
        self.assertEqual(report["executions"], [token])

    def test_15_deferred_checkpoint_snapshots_mutable_results(self) -> None:
        token = secrets.token_hex(14)
        values = [random.randint(-(2**30), 2**30) for _ in range(9)]
        label = secrets.token_hex(10)
        mutation = random.randint(2**31, 2**32 - 1)
        expected = {
            "token": token,
            "payload": {"values": values, "labels": [label, token[:9]]},
            "meta": {"state": "published"},
        }
        report = run_probe(
            "deferred_snapshot",
            f'''
            TOKEN = {token!r}; VALUES = {values!r}; LABEL = {label!r}; MUTATION = {mutation!r}

            @python_app(cache=True)
            def mutable_result(token, values, label):
                return {{
                    "token": token,
                    "payload": {{"values": list(values), "labels": [label, token[:9]]}},
                    "meta": {{"state": "published"}},
                }}

            reports = {{}}
            for mode in ("manual", "dfk_exit"):
                dfk = parsl.load(config(ROOT / ("runs-" + mode), mode=mode, threads=2))
                future = mutable_result(TOKEN, VALUES, LABEL)
                result = future.result(timeout=10)
                visible = json.loads(json.dumps(result, sort_keys=True))

                result["payload"]["values"][0] = MUTATION
                result["payload"]["values"].append(MUTATION)
                result["payload"]["labels"][0] = "mutated-" + TOKEN
                result["meta"]["state"] = "mutated"
                result["added_after_publication"] = True

                checkpoint = Path(dfk.run_dir) / "checkpoint" / "tasks.pkl"
                if mode == "manual":
                    dfk.checkpoint()
                close_dfk()
                records = decode(checkpoint)
                reports[mode] = {{
                    "visible": visible,
                    "records": [record["result"] for record in records],
                }}
            emit(reports)
            ''',
        )
        for mode in ("manual", "dfk_exit"):
            self.assertEqual(report[mode]["visible"], expected, mode)
            self.assertEqual(report[mode]["records"], [expected], mode)

    def test_16_concurrent_run_allocation_ignores_numeric_lookalikes(self) -> None:
        token = secrets.token_hex(13)
        worker_count = 6
        report = run_probe(
            "concurrent_run_allocation",
            f'''
            TOKEN = {token!r}; WORKER_COUNT = {worker_count}
            run_root = ROOT / "shared-runinfo"
            lookalike_names = ("7x8", "\u0661\u0662\u0663")
            for name in lookalike_names:
                checkpoint = run_root / name / "checkpoint"
                checkpoint.mkdir(parents=True)
                (checkpoint / "tasks.pkl").write_bytes(b"(")

            ready = ROOT / "allocator-ready"
            ready.mkdir()
            gate = ROOT / "allocator-go"
            worker = ROOT / "allocator_worker.py"
            worker.write_text(
                "import json, os, sys, time\\n"
                "from pathlib import Path\\n"
                "import parsl\\n"
                "from parsl.config import Config\\n"
                "from parsl.executors.threads import ThreadPoolExecutor\\n"
                "root=Path(sys.argv[1]); run_root=Path(sys.argv[2]); gate=Path(sys.argv[3])\\n"
                "(root/'allocator-ready'/str(os.getpid())).write_text('ready')\\n"
                "deadline=time.monotonic()+15\\n"
                "while not gate.exists():\\n"
                "  if time.monotonic() >= deadline: raise RuntimeError('allocator gate timeout')\\n"
                "  time.sleep(0.005)\\n"
                "dfk=parsl.load(Config(executors=[ThreadPoolExecutor(max_threads=1,label='local')], run_dir=str(run_root), initialize_logging=False, usage_tracking=0, strategy='none'))\\n"
                "name=Path(dfk.run_dir).name\\n"
                "dfk.cleanup(); parsl.clear()\\n"
                "print(json.dumps({{'name':name}},sort_keys=True))\\n",
                encoding="utf-8",
            )

            processes = [
                subprocess.Popen(
                    [sys.executable, "-B", str(worker), str(ROOT), str(run_root), str(gate)],
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                for _ in range(WORKER_COUNT)
            ]
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if len(list(ready.iterdir())) == WORKER_COUNT:
                    break
                time.sleep(0.01)
            if len(list(ready.iterdir())) != WORKER_COUNT:
                raise RuntimeError("not all allocator workers became ready")
            gate.write_text("go", encoding="ascii")

            allocated = []
            for process in processes:
                stdout, stderr = process.communicate(timeout=25)
                if process.returncode != 0:
                    raise RuntimeError("allocator worker failed: " + stderr)
                allocated.append(json.loads(stdout.splitlines()[-1])["name"])

            @python_app(cache=True)
            def identity(token):
                return {{"token": token, "length": len(token)}}

            dfk = parsl.load(config(run_root, mode="task_exit", threads=2))
            value = identity(TOKEN).result(timeout=10)
            next_run = Path(dfk.run_dir).name
            close_dfk()
            lookalikes_unchanged = all(
                (run_root / name / "checkpoint" / "tasks.pkl").read_bytes() == b"("
                for name in lookalike_names
            )
            emit({{
                "allocated": allocated,
                "next_run": next_run,
                "value": value,
                "lookalikes_unchanged": lookalikes_unchanged,
            }})
            ''',
            timeout=60,
        )
        self.assertEqual(len(report["allocated"]), worker_count)
        self.assertEqual(len(set(report["allocated"])), worker_count)
        self.assertEqual(
            set(report["allocated"]),
            {f"{index:03d}" for index in range(worker_count)},
        )
        self.assertTrue(all(name.isascii() and name.isdecimal() for name in report["allocated"]))
        self.assertEqual(report["next_run"], f"{worker_count:03d}")
        self.assertEqual(report["value"], {"token": token, "length": len(token)})
        self.assertTrue(report["lookalikes_unchanged"])

    def test_17_ineligible_outcomes_do_not_poison_next_run(self) -> None:
        token = secrets.token_hex(14)
        value = {"token": token, "nonce": random.randint(1, 2**31 - 1)}
        report = run_probe(
            "ineligible_checkpoint_outcomes",
            f'''
            TOKEN = {token!r}; VALUE = {value!r}

            @python_app(cache=False)
            def uncached_success(token, value):
                return value

            @python_app(cache=True)
            def terminal_failure(token):
                raise RuntimeError("terminal-" + token)

            run_root = ROOT / "runinfo"
            first_dfk = parsl.load(config(run_root, mode="task_exit", threads=3))
            first_value = uncached_success(TOKEN, VALUE).result(timeout=10)
            failed = terminal_failure(TOKEN)
            try:
                failed.result(timeout=10)
            except RuntimeError as exc:
                failure_message = str(exc)
            else:
                failure_message = "NO_ERROR"
            first_run = Path(first_dfk.run_dir).name
            first_checkpoint = Path(first_dfk.run_dir) / "checkpoint" / "tasks.pkl"
            before_cleanup = first_checkpoint.exists()
            close_dfk()
            after_cleanup = first_checkpoint.exists()

            @python_app(cache=True)
            def durable(token, value):
                import os
                fd = os.open("marker.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try: os.write(fd, (token + "\\n").encode()); os.fsync(fd)
                finally: os.close(fd)
                return value

            second_dfk = parsl.load(config(run_root, mode="task_exit", threads=2))
            second = durable(TOKEN, VALUE)
            second_value = second.result(timeout=10)
            second_memo = bool(second.task_record.get("from_memo"))
            second_run = Path(second_dfk.run_dir).name
            close_dfk()
            emit({{
                "first_value": first_value,
                "failure_message": failure_message,
                "first_run": first_run,
                "before_cleanup": before_cleanup,
                "after_cleanup": after_cleanup,
                "second_value": second_value,
                "second_memo": second_memo,
                "second_run": second_run,
                "executions": Path("marker.log").read_text().splitlines(),
            }})
            ''',
        )
        self.assertEqual(report["first_value"], value)
        self.assertEqual(report["failure_message"], f"terminal-{token}")
        self.assertEqual(report["first_run"], "000")
        self.assertFalse(report["before_cleanup"])
        self.assertFalse(report["after_cleanup"])
        self.assertEqual(report["second_value"], value)
        self.assertFalse(report["second_memo"])
        self.assertEqual(report["second_run"], "001")
        self.assertEqual(report["executions"], [token])

    def test_18_memo_hits_are_independent_immutable_snapshots(self) -> None:
        token = secrets.token_hex(14)
        values = [random.randint(-(2**30), 2**30) for _ in range(8)]
        label = secrets.token_hex(9)
        mutation = random.randint(2**31, 2**32 - 1)
        expected = {
            "token": token,
            "payload": {"values": values, "labels": [label, token[:8]]},
            "meta": {"state": "published"},
        }
        report = run_probe(
            "memo_snapshot_isolation",
            f'''
            TOKEN = {token!r}; VALUES = {values!r}; LABEL = {label!r}; MUTATION = {mutation!r}

            class StickyBox:
                """Pickle-compatible mutable value whose deepcopy preserves identity."""
                def __init__(self, value):
                    self.value = value

                def __deepcopy__(self, memo):
                    return self

            @python_app(cache=True)
            def mutable_result(token, values, label):
                import os
                fd = os.open("marker.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try: os.write(fd, (token + "\\n").encode()); os.fsync(fd)
                finally: os.close(fd)
                return StickyBox({{
                    "token": token,
                    "payload": {{"values": list(values), "labels": [label, token[:8]]}},
                    "meta": {{"state": "published"}},
                }})

            dfk = parsl.load(config(ROOT / "runinfo", mode="manual", threads=2))
            first = mutable_result(TOKEN, VALUES, LABEL)
            first_value = first.result(timeout=10)
            first_visible = pickle.loads(pickle.dumps(first_value.value))
            first_value.value["payload"]["values"][0] = MUTATION
            first_value.value["payload"]["labels"][0] = "first-mutated-" + TOKEN
            first_value.value["meta"]["state"] = "first-mutated"

            second = mutable_result(TOKEN, VALUES, LABEL)
            second_value = second.result(timeout=10)
            second_visible = pickle.loads(pickle.dumps(second_value.value))
            second_value.value["payload"]["values"].append(MUTATION)
            second_value.value["payload"]["labels"][1] = "second-mutated-" + TOKEN
            second_value.value["meta"]["state"] = "second-mutated"

            third = mutable_result(TOKEN, VALUES, LABEL)
            third_value = third.result(timeout=10)
            third_visible = pickle.loads(pickle.dumps(third_value.value))

            dfk.checkpoint()
            checkpoint = Path(dfk.run_dir) / "checkpoint" / "tasks.pkl"
            records = decode(checkpoint)
            close_dfk()
            emit({{
                "first": first_visible,
                "second": second_visible,
                "third": third_visible,
                "first_memo": bool(first.task_record.get("from_memo")),
                "second_memo": bool(second.task_record.get("from_memo")),
                "third_memo": bool(third.task_record.get("from_memo")),
                "records": [record["result"].value for record in records],
                "executions": Path("marker.log").read_text().splitlines(),
            }})
            ''',
        )
        self.assertEqual(report["first"], expected)
        self.assertEqual(report["second"], expected)
        self.assertEqual(report["third"], expected)
        self.assertFalse(report["first_memo"])
        self.assertTrue(report["second_memo"])
        self.assertTrue(report["third_memo"])
        self.assertGreaterEqual(len(report["records"]), 1)
        self.assertTrue(all(record == expected for record in report["records"]))
        self.assertEqual(report["executions"], [token])

    def test_19_task_exit_persistence_failure_rolls_back_publication(self) -> None:
        token = secrets.token_hex(14)
        value = {
            "token": token,
            "values": [random.randint(-(2**30), 2**30) for _ in range(7)],
        }
        report = run_probe(
            "task_exit_transaction",
            f'''
            TOKEN = {token!r}; VALUE = {value!r}

            @python_app(cache=True)
            def durable(token, value):
                import os
                fd = os.open("marker.log", os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                try: os.write(fd, (token + "\\n").encode()); os.fsync(fd)
                finally: os.close(fd)
                return value

            dfk = parsl.load(config(ROOT / "runinfo", mode="task_exit", threads=2))
            blocker = Path(dfk.run_dir) / "checkpoint"
            blocker.write_bytes(("blocked-" + TOKEN).encode())

            first = durable(TOKEN, VALUE)
            try:
                first.result(timeout=5)
            except BaseException as exc:
                first_error = type(exc).__name__
            else:
                first_error = "NO_ERROR"
            first_done = first.done()
            first_present = first.tid in dfk.tasks
            blocker_unchanged = blocker.read_bytes() == ("blocked-" + TOKEN).encode()

            blocker.unlink()
            second = durable(TOKEN, VALUE)
            second_value = second.result(timeout=10)
            second_memo = bool(second.task_record.get("from_memo"))
            third = durable(TOKEN, VALUE)
            third_value = third.result(timeout=10)
            third_memo = bool(third.task_record.get("from_memo"))
            checkpoint = Path(dfk.run_dir) / "checkpoint" / "tasks.pkl"
            records = decode(checkpoint)
            close_dfk()
            emit({{
                "first_error": first_error,
                "first_done": first_done,
                "first_present": first_present,
                "blocker_unchanged": blocker_unchanged,
                "second": second_value,
                "second_memo": second_memo,
                "third": third_value,
                "third_memo": third_memo,
                "records": [record["result"] for record in records],
                "executions": Path("marker.log").read_text().splitlines(),
            }})
            ''',
        )
        self.assertNotIn(report["first_error"], ("NO_ERROR", "TimeoutError"))
        self.assertTrue(report["first_done"])
        self.assertFalse(report["first_present"])
        self.assertTrue(report["blocker_unchanged"])
        self.assertEqual(report["second"], value)
        self.assertFalse(report["second_memo"])
        self.assertEqual(report["third"], value)
        self.assertTrue(report["third_memo"])
        self.assertGreaterEqual(len(report["records"]), 1)
        self.assertTrue(all(record == value for record in report["records"]))
        self.assertEqual(report["executions"], [token, token])

    def test_20_deferred_flush_failure_retains_every_outcome(self) -> None:
        tokens = {
            mode: [secrets.token_hex(10) for _ in range(4)]
            for mode in ("manual", "periodic", "dfk_exit")
        }
        report = run_probe(
            "deferred_flush_retry",
            f'''
            TOKENS = {tokens!r}

            @python_app(cache=True)
            def compute(mode, index, token):
                return {{"mode": mode, "index": index, "token": token}}

            reports = {{}}
            for mode in ("manual", "periodic", "dfk_exit"):
                period = "01:00:00" if mode == "periodic" else None
                dfk = parsl.load(config(
                    ROOT / ("runs-" + mode), mode=mode, threads=4, period=period
                ))
                blocker = Path(dfk.run_dir) / "checkpoint"
                blocker_payload = ("blocked-" + mode).encode()
                blocker.write_bytes(blocker_payload)
                values = [
                    compute(mode, index, token).result(timeout=10)
                    for index, token in enumerate(TOKENS[mode])
                ]

                try:
                    dfk.checkpoint()
                except BaseException as exc:
                    failure = type(exc).__name__
                else:
                    failure = "NO_ERROR"
                blocker_unchanged = blocker.read_bytes() == blocker_payload
                blocker.unlink()

                dfk.checkpoint()
                checkpoint = Path(dfk.run_dir) / "checkpoint" / "tasks.pkl"
                after_retry = decode(checkpoint)
                dfk.checkpoint()
                after_second_flush = decode(checkpoint)
                close_dfk()
                after_cleanup = decode(checkpoint)
                reports[mode] = {{
                    "failure": failure,
                    "blocker_unchanged": blocker_unchanged,
                    "values": values,
                    "after_retry": [record["result"] for record in after_retry],
                    "after_second_flush": [record["result"] for record in after_second_flush],
                    "after_cleanup": [record["result"] for record in after_cleanup],
                }}
            emit(reports)
            ''',
            timeout=50,
        )
        for mode in ("manual", "periodic", "dfk_exit"):
            expected = [
                {"mode": mode, "index": index, "token": token}
                for index, token in enumerate(tokens[mode])
            ]
            self.assertNotEqual(report[mode]["failure"], "NO_ERROR", mode)
            self.assertTrue(report[mode]["blocker_unchanged"], mode)
            self.assertEqual(report[mode]["values"], expected, mode)
            self.assertCountEqual(report[mode]["after_retry"], expected, mode)
            self.assertCountEqual(report[mode]["after_second_flush"], expected, mode)
            self.assertCountEqual(report[mode]["after_cleanup"], expected, mode)
            self.assertEqual(len(report[mode]["after_retry"]), len(expected), mode)
            self.assertEqual(len(report[mode]["after_second_flush"]), len(expected), mode)
            self.assertEqual(len(report[mode]["after_cleanup"]), len(expected), mode)

def main() -> int:
    global WORKSPACE, TEST_ROOT
    inherited_fd = os.environ.pop("PARSL_VERIFIER_FD", "")
    if inherited_fd:
        os.close(int(inherited_fd))
    make_verifier_private()
    parser = argparse.ArgumentParser()
    parser.add_argument("--workspace", type=Path, required=True)
    args = parser.parse_args()
    WORKSPACE = args.workspace.resolve()
    TEST_ROOT = Path(tempfile.mkdtemp(prefix="parsl-verifier-", dir="/tmp"))
    try:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(TaskTests)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1
    finally:
        shutil.rmtree(TEST_ROOT, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
