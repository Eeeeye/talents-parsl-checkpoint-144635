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
from parsl.app.app import python_app
from parsl.config import Config
from parsl.dataflow.errors import BadCheckpoint
from parsl.executors.threads import ThreadPoolExecutor

ROOT = Path(sys.argv[1])
ROOT.mkdir(parents=True, exist_ok=True)
os.chdir(ROOT)

def config(run_root, *, mode="task_exit", files=None, threads=4, period=None, retries=0):
    kwargs = dict(
        executors=[ThreadPoolExecutor(max_threads=threads, label="local")],
        checkpoint_mode=mode,
        run_dir=str(run_root),
        initialize_logging=False,
        usage_tracking=0,
        strategy="none",
        retries=retries,
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
            entered = threading.Event()
            release = threading.Event()
            original = dfk.handle_app_update
            def delayed(record, future):
                entered.set()
                if not release.wait(10):
                    raise RuntimeError("callback gate timed out")
                return original(record, future)
            dfk.handle_app_update = delayed

            first = work(TOKEN, VALUE)
            first_value = first.result(timeout=10)
            assert entered.wait(10)
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
            entered = threading.Event(); release = threading.Event()
            original = dfk.handle_app_update
            def delayed(record, future):
                entered.set()
                if not release.wait(10): raise RuntimeError("callback gate timed out")
                return original(record, future)
            dfk.handle_app_update = delayed
            first = return_none(TOKEN)
            first_result = first.result(timeout=10)
            assert entered.wait(10)
            checkpoint = Path(dfk.run_dir) / "checkpoint" / "tasks.pkl"
            records = decode(checkpoint)
            second = return_none(TOKEN)
            second_result = second.result(timeout=10)
            from_memo = bool(second.task_record.get("from_memo"))
            executions = Path("marker.log").read_text().splitlines()
            release.set(); close_dfk()
            emit({{"first_is_none": first_result is None, "second_is_none": second_result is None,
                  "checkpoint_none": any(r["result"] is None for r in records),
                  "from_memo": from_memo, "executions": executions}})
            ''',
        )
        self.assertTrue(report["first_is_none"])
        self.assertTrue(report["second_is_none"])
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

    def test_10_invalid_checkpoints_fail_closed_and_remain_unchanged(self) -> None:
        report = run_probe(
            "invalid_checkpoints",
            r'''
            fixtures = {}
            missing = ROOT / "missing"
            fixtures["missing"] = missing

            truncated = ROOT / "truncated"; truncated.mkdir()
            valid = pickle.dumps({"hash": "a" * 32, "exception": None, "result": {"x": 1}})
            (truncated / "tasks.pkl").write_bytes(valid + pickle.dumps({"hash": "b" * 32, "exception": None, "result": [1,2,3]})[:-5])
            fixtures["truncated"] = truncated

            wrong_keys = ROOT / "wrong_keys"; wrong_keys.mkdir()
            (wrong_keys / "tasks.pkl").write_bytes(pickle.dumps({"hash": "c" * 32, "result": 7}))
            fixtures["wrong_keys"] = wrong_keys

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
        for name in ("missing", "truncated", "wrong_keys", "trailing"):
            self.assertEqual(report[name]["outcome"], "BadCheckpoint", name)
            self.assertTrue(report[name]["unchanged"], name)

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
