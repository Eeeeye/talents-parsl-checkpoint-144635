from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from parsl.dataflow.taskrecord import TaskRecord


@dataclass(frozen=True)
class TaskOutcome:
    """A completed task outcome passed to persistence before publication."""

    task_record: TaskRecord
    result: Any = None
    exception: BaseException | None = None

    def __post_init__(self) -> None:
        if self.exception is not None and self.result is not None:
            raise ValueError("a task outcome cannot contain both result and exception")

    @property
    def succeeded(self) -> bool:
        return self.exception is None
