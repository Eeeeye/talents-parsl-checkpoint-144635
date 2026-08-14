from __future__ import annotations

import pickle
from dataclasses import dataclass, field
from typing import Any

from parsl.dataflow.taskrecord import TaskRecord


@dataclass(frozen=True)
class TaskOutcome:
    """A completed task outcome passed to persistence before publication."""

    task_record: TaskRecord
    result: Any = None
    exception: BaseException | None = None
    checkpoint_payload: bytes | None = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.exception is not None and self.result is not None:
            raise ValueError("a task outcome cannot contain both result and exception")

        payload = None
        hashsum = self.task_record.get("hashsum")
        if self.exception is None and isinstance(hashsum, str):
            payload = pickle.dumps({
                "hash": hashsum,
                "exception": None,
                "result": self.result,
            })
        object.__setattr__(self, "checkpoint_payload", payload)

    @property
    def succeeded(self) -> bool:
        return self.exception is None
