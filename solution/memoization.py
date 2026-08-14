from __future__ import annotations

import hashlib
import logging
import os
import pickle
import types
from copy import deepcopy
from concurrent.futures import Future
from dataclasses import dataclass
from functools import lru_cache, singledispatch
from typing import Any, Dict, List, Optional, Sequence

import typeguard

from parsl.dataflow.errors import BadCheckpoint
from parsl.dataflow.taskrecord import TaskRecord

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class MemoEntry:
    """An isolated memo snapshot which materializes a fresh value per hit."""

    payload: bytes | None = None
    fallback: Any = None
    exception: BaseException | None = None

    @classmethod
    def from_result(cls, result: Any) -> MemoEntry:
        try:
            payload = pickle.dumps(result, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception:
            # App caching historically accepted some values which cannot be
            # pickled. Preserve that behavior where possible while giving
            # pickle-compatible values the stronger isolation guarantee.
            try:
                fallback = deepcopy(result)
            except Exception:
                fallback = result
            return cls(fallback=fallback)
        return cls(payload=payload)

    @classmethod
    def from_exception(cls, exception: BaseException) -> MemoEntry:
        return cls(exception=exception)

    def materialize(self) -> Any:
        if self.payload is not None:
            return pickle.loads(self.payload)
        try:
            return deepcopy(self.fallback)
        except Exception:
            return self.fallback

    def as_future(self) -> Future[Any]:
        future: Future[Any] = Future()
        if self.exception is not None:
            future.set_exception(self.exception)
        else:
            future.set_result(self.materialize())
        return future


@singledispatch
def id_for_memo(obj: object, output_ref: bool = False) -> bytes:
    """This should return a byte sequence which identifies the supplied
    value for memoization purposes: for any two calls of id_for_memo,
    the byte sequence should be the same when the "same" value is supplied,
    and different otherwise.

    "same" is in quotes about because sameness is not as straightforward as
    serialising out the content.

    For example, for two dicts x, y:

      x = {"a":3, "b":4}
      y = {"b":4, "a":3}

    then: x == y, but their serialization is not equal, and some other
    functions on x and y are not equal: list(x.keys()) != list(y.keys())


    id_for_memo is invoked with output_ref=True when the parameter is an
    output reference (a value in the outputs=[] parameter of an app
    invocation).

    Memo hashing might be different for such parameters: for example, a
    user might choose to hash input File content so that changing the
    content of an input file invalidates memoization. This does not make
    sense to do for output files: there is no meaningful content stored
    where an output filename points at memoization time.
    """
    logger.error("id_for_memo attempted on unknown type {}".format(type(obj)))
    raise ValueError("unknown type for memoization: {}".format(type(obj)))


@id_for_memo.register(str)
@id_for_memo.register(int)
@id_for_memo.register(float)
@id_for_memo.register(type(None))
def id_for_memo_pickle(obj: object, output_ref: bool = False) -> bytes:
    return pickle.dumps(obj)


@id_for_memo.register(list)
def id_for_memo_list(denormalized_list: list, output_ref: bool = False) -> bytes:
    if type(denormalized_list) is not list:
        raise ValueError("id_for_memo_list cannot work on subclasses of list")

    normalized_list = []

    for e in denormalized_list:
        normalized_list.append(id_for_memo(e, output_ref=output_ref))

    return pickle.dumps(normalized_list)


@id_for_memo.register(tuple)
def id_for_memo_tuple(denormalized_tuple: tuple, output_ref: bool = False) -> bytes:
    if type(denormalized_tuple) is not tuple:
        raise ValueError("id_for_memo_tuple cannot work on subclasses of tuple")

    normalized_list = []

    for e in denormalized_tuple:
        normalized_list.append(id_for_memo(e, output_ref=output_ref))

    return pickle.dumps(normalized_list)


@id_for_memo.register(dict)
def id_for_memo_dict(denormalized_dict: dict, output_ref: bool = False) -> bytes:
    """This normalises the keys and values of the supplied dictionary.

    When output_ref=True, the values are normalised as output refs, but
    the keys are not.
    """
    if type(denormalized_dict) is not dict:
        raise ValueError("id_for_memo_dict cannot work on subclasses of dict")

    keys = sorted(denormalized_dict)

    normalized_list = []
    for k in keys:
        normalized_list.append(id_for_memo(k))
        normalized_list.append(id_for_memo(denormalized_dict[k], output_ref=output_ref))
    return pickle.dumps(normalized_list)


# the LRU cache decorator must be applied closer to the id_for_memo_function call
# that the .register() call, so that the cache-decorated version is registered.
@id_for_memo.register(types.FunctionType)
@lru_cache()
def id_for_memo_function(f: types.FunctionType, output_ref: bool = False) -> bytes:
    """This will checkpoint a function based only on its name and module name.
    This means that changing source code (other than the function name) will
    not cause a checkpoint invalidation.
    """
    return pickle.dumps(["types.FunctionType", f.__name__, f.__module__])


class Memoizer:
    """Memoizer is responsible for ensuring that identical work is not repeated.

    When a task is repeated, i.e., the same function is called with the same exact arguments, the
    result from a previous execution is reused. `wiki <https://en.wikipedia.org/wiki/Memoization>`_

    The memoizer implementation here does not collapse duplicate calls
    at call time, but works **only** when the result of a previous
    call is available at the time the duplicate call is made.

    For instance::

       No advantage from                 Memoization helps
       memoization here:                 here:

        TaskA                            TaskB
          |   TaskA                        |
          |     |   TaskA                done  (TaskB)
          |     |     |                                (TaskB)
        done    |     |
              done    |
                    done

    The memoizer creates a lookup table by hashing the function name
    and its inputs, and storing the results of the function.

    When a task is ready for launch, i.e., all of its arguments
    have resolved, we add its hash to the task datastructure.

    """

    def __init__(self, *, memoize: bool = True, checkpoint_files: Sequence[str]):
        """Initialize the memoizer.

        KWargs:
            - memoize (Bool): enable memoization or not.
            - checkpoint (Dict): A checkpoint loaded as a dict.
        """
        self.memoize = memoize

        checkpoint = self.load_checkpoints(checkpoint_files)

        if self.memoize:
            logger.info("App caching initialized")
            self.memo_lookup_table = checkpoint
        else:
            logger.info("App caching disabled for all apps")
            self.memo_lookup_table = {}

    def make_hash(self, task: TaskRecord) -> str:
        """Create a hash of the task inputs.

        Args:
            - task (dict) : Task dictionary from dfk.tasks

        Returns:
            - hash (str) : A unique hash string
        """

        t: List[bytes] = []

        # if kwargs contains an outputs parameter, that parameter is removed
        # and normalised differently - with output_ref set to True.
        # kwargs listed in ignore_for_cache will also be removed

        filtered_kw = task['kwargs'].copy()

        ignore_list = task['ignore_for_cache']

        logger.debug("Ignoring these kwargs for checkpointing: %s", ignore_list)
        for k in ignore_list:
            logger.debug("Ignoring kwarg %s", k)
            del filtered_kw[k]

        if 'outputs' in task['kwargs']:
            outputs = task['kwargs']['outputs']
            del filtered_kw['outputs']
            t.append(id_for_memo(outputs, output_ref=True))

        t.extend(map(id_for_memo, (filtered_kw, task['func'], task['args'])))

        x = b''.join(t)
        return hashlib.md5(x).hexdigest()

    def check_memo(self, task: TaskRecord) -> Optional[Future[Any]]:
        """Create a hash of the task and its inputs and check the lookup table for this hash.

        If present, the results are returned.

        Args:
            - task(task) : task from the dfk.tasks table

        Returns:
            - Result of the function if present in table, wrapped in a Future

        This call will also set task['hashsum'] to the unique hashsum for the func+inputs.
        """

        task_id = task['id']

        if not self.memoize or not task['memoize']:
            task['hashsum'] = None
            logger.debug("Task {} will not be memoized".format(task_id))
            return None

        hashsum = self.make_hash(task)
        logger.debug("Task {} has memoization hash {}".format(task_id, hashsum))
        result: Optional[Future[Any]] = None
        if hashsum in self.memo_lookup_table:
            result = self.memo_lookup_table[hashsum].as_future()
            logger.info("Task %s using result from cache", task_id)
        else:
            logger.info("Task %s had no result in cache", task_id)

        task['hashsum'] = hashsum

        assert isinstance(result, Future) or result is None
        return result

    def _eligible_hash(self, task: TaskRecord) -> Optional[str]:
        if not self.memoize or not task['memoize']:
            return None
        hashsum = task.get('hashsum')
        if not isinstance(hashsum, str):
            logger.error("Attempting to update app cache entry but hashsum is not a string key")
            return None
        return hashsum

    def prepare_success(self, task: TaskRecord, result: Any) -> Optional[MemoEntry]:
        """Freeze a successful result without publishing it into the table."""
        if self._eligible_hash(task) is None:
            return None
        return MemoEntry.from_result(result)

    def prepare_failure(self, task: TaskRecord,
                        exception: BaseException) -> Optional[MemoEntry]:
        """Prepare the existing failure-caching behavior for publication."""
        if self._eligible_hash(task) is None:
            return None
        return MemoEntry.from_exception(exception)

    def update_memo(self, task: TaskRecord, entry: Optional[MemoEntry]) -> None:
        """Publish a previously prepared memo entry.

        Preparation is separate so required persistence can succeed before a
        successful value becomes reachable through memoization.

        Args:
             - task (TaskRecord) : A task record from dfk.tasks
        """
        task_id = task['id']

        if entry is None:
            return
        hashsum = self._eligible_hash(task)
        if hashsum is None:
            return

        if hashsum in self.memo_lookup_table:
            logger.info(f"Replacing app cache entry {hashsum} with result from task {task_id}")
        else:
            logger.debug(f"Storing app cache entry {hashsum} with result from task {task_id}")
        self.memo_lookup_table[hashsum] = entry

    def _load_checkpoints(self, checkpointDirs: Sequence[str]) -> Dict[str, MemoEntry]:
        """Load a checkpoint file into a lookup table.

        The data being loaded from the pickle file mostly contains input
        attributes of the task: func, args, kwargs, env...
        To simplify the check of whether the exact task has been completed
        in the checkpoint, we hash these input params and use it as the key
        for the memoized lookup table.

        Args:
            - checkpointDirs (list) : List of filepaths to checkpoints
              Eg. ['runinfo/001', 'runinfo/002']

        Returns:
            - memoized_lookup_table (dict)
        """
        memo_lookup_table = {}

        for checkpoint_dir in checkpointDirs:
            logger.info("Loading checkpoints from {}".format(checkpoint_dir))
            checkpoint_file = os.path.join(checkpoint_dir, 'tasks.pkl')
            try:
                with open(checkpoint_file, 'rb') as f:
                    file_size = os.fstat(f.fileno()).st_size
                    if file_size == 0:
                        raise ValueError("empty checkpoint stream")
                    while f.tell() < file_size:
                        data = pickle.load(f)
                        if type(data) is not dict or set(data) != {"hash", "exception", "result"}:
                            raise ValueError("invalid checkpoint record schema")
                        if not isinstance(data["hash"], str) or data["exception"] is not None:
                            raise ValueError("invalid checkpoint record values")
                        memo_lookup_table[data['hash']] = MemoEntry.from_result(data['result'])
            except FileNotFoundError:
                reason = "Checkpoint file was not found: {}".format(
                    checkpoint_file)
                logger.error(reason)
                raise BadCheckpoint(reason)
            except Exception:
                reason = "Failed to load checkpoint: {}".format(
                    checkpoint_file)
                logger.error(reason)
                raise BadCheckpoint(reason)

            logger.info("Completed loading checkpoint: {0} with {1} tasks".format(checkpoint_file,
                                                                                  len(memo_lookup_table.keys())))
        return memo_lookup_table

    @typeguard.typechecked
    def load_checkpoints(self, checkpointDirs: Optional[Sequence[str]]) -> Dict[str, MemoEntry]:
        """Load checkpoints from the checkpoint files into a dictionary.

        The results are used to pre-populate the memoizer's lookup_table

        Kwargs:
             - checkpointDirs (list) : List of run folder to use as checkpoints
               Eg. ['runinfo/001', 'runinfo/002']

        Returns:
             - dict containing, hashed -> future mappings
        """
        if checkpointDirs:
            return self._load_checkpoints(checkpointDirs)
        else:
            return {}
