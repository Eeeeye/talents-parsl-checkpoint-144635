#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pickle
import threading
from pathlib import Path
from typing import Any

import parsl
from parsl.app.app import python_app
from parsl.config import Config
from parsl.executors.threads import ThreadPoolExecutor


@python_app(cache=True, ignore_for_cache=["marker_name"])
def recorded_value(key: str, value: Any, marker_name: str = "executions.log") -> Any:
    import os

    fd = os.open(marker_name, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (key + "\n").encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)
    return value


def read_checkpoint(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open("rb") as stream:
        while True:
            try:
                item = pickle.load(stream)
            except EOFError:
                return records
            if not isinstance(item, dict):
                raise ValueError("checkpoint record is not a dictionary")
            records.append(item)


def make_config(run_root: Path, threads: int = 4) -> Config:
    return Config(
        executors=[ThreadPoolExecutor(max_threads=threads, label="local")],
        checkpoint_mode="task_exit",
        run_dir=str(run_root),
        initialize_logging=False,
        usage_tracking=0,
        strategy="none",
    )


def cleanup() -> None:
    try:
        parsl.dfk().cleanup()
    finally:
        parsl.clear()


def visibility(root: Path) -> dict[str, Any]:
    key = "sample-visibility-key"
    value = {"temperatures": [273.15, 281.5], "valid": True}
    marker = root / "executions.log"
    dfk = parsl.load(make_config(root / "runinfo"))

    callback_entered = threading.Event()
    callback_release = threading.Event()
    original_callback = dfk.handle_app_update

    def delayed_callback(task_record: Any, future: Any) -> Any:
        callback_entered.set()
        if not callback_release.wait(10):
            raise RuntimeError("completion callback gate timed out")
        return original_callback(task_record, future)

    dfk.handle_app_update = delayed_callback
    first = recorded_value(key, value)
    first_result = first.result(timeout=10)
    if not callback_entered.wait(10):
        raise RuntimeError("completion callback did not enter")

    checkpoint = Path(dfk.run_dir) / "checkpoint" / "tasks.pkl"
    second = recorded_value(key, value)
    second_result = second.result(timeout=10)
    report = {
        "before_callback_release": {
            "checkpoint_visible": checkpoint.is_file(),
            "execution_count": len(marker.read_text(encoding="utf-8").splitlines()),
            "first_future_done": first.done(),
            "second_from_memo": bool(second.task_record.get("from_memo")),
        },
        "first_result": first_result,
        "second_result": second_result,
    }
    callback_release.set()
    cleanup()
    report["final_execution_count"] = len(marker.read_text(encoding="utf-8").splitlines())
    report["checkpoint_records"] = len(read_checkpoint(checkpoint))
    return report


def restart(root: Path) -> dict[str, Any]:
    key = "sample-restart-key"
    value = {"tiles": [3, 5, 8], "converged": False}
    marker = root / "executions.log"
    run_root = root / "runinfo"

    def one_run() -> tuple[Any, str, bool]:
        parsl.load(make_config(run_root, threads=2))
        future = recorded_value(key, value)
        result = future.result(timeout=10)
        run_dir = parsl.dfk().run_dir
        from_memo = bool(future.task_record.get("from_memo"))
        cleanup()
        return result, run_dir, from_memo

    first_result, first_run, first_from_memo = one_run()
    second_result, second_run, second_from_memo = one_run()
    return {
        "execution_count": len(marker.read_text(encoding="utf-8").splitlines()),
        "first_from_memo": first_from_memo,
        "first_result": first_result,
        "first_run": first_run,
        "second_from_memo": second_from_memo,
        "second_result": second_result,
        "second_run": second_run,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario", choices=("visibility", "restart"))
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    args.root.mkdir(parents=True, exist_ok=True)
    previous = Path.cwd()
    try:
        os.chdir(args.root)
        report = visibility(args.root) if args.scenario == "visibility" else restart(args.root)
    finally:
        os.chdir(previous)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
