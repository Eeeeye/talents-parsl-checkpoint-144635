from __future__ import annotations

import pickle
from dataclasses import dataclass, field

from parsl.dataflow.memoization import MemoEntry
from parsl.dataflow.taskrecord import TaskRecord


@dataclass(frozen=True)
class TaskOutcome:
    """A completed task outcome passed to persistence before publication."""

    task_record: TaskRecord
    memo_entry: MemoEntry
    checkpoint_payload: bytes | None = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        payload = None
        hashsum = self.task_record.get("hashsum")
        if self.memo_entry.exception is None and isinstance(hashsum, str):
            payload = pickle.dumps({
                "hash": hashsum,
                "exception": None,
                "result": self.memo_entry.materialize(),
            }, protocol=pickle.HIGHEST_PROTOCOL)
        object.__setattr__(self, "checkpoint_payload", payload)

    @property
    def succeeded(self) -> bool:
        return self.memo_entry.exception is None
