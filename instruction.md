# Repair Parsl task-completion and checkpoint visibility

## Background

This repository is a pinned source snapshot of Parsl, a Python workflow system
used to run dependency graphs on HPC resources. The failure is in the submit-side
data-flow kernel and is reproducible with the local thread executor; no batch
scheduler or network service is required.

Scientific users enable app caching and checkpoints so that repeated task calls
reuse completed work and a later launcher process can resume without submitting
the same computation again. During incident reproduction, a returned `AppFuture`
could be visible to workflow code before its cache/checkpoint state was visible.
The completion callback still owned task-table cleanup, so terminal tasks could
also remain in the DFK after their Future was already observable. The next run
then failed to discover checkpoints written below the configured run root.

## Initial behavior

From `/workspace/parsl-checkpoint`, run:

```bash
./scripts/reproduce.sh
```

The publication-boundary report shows a completed first Future while the
`task_exit` checkpoint is still absent. An identical call executes again and its
`task_record["from_memo"]` is false. The restart report then executes the same
cached task once in each of two numbered run directories instead of recovering
the result written by the first process.

The saved, path-redacted output is in `incident/original-output.log`.

## Required final behavior

Repair the implementation under `parsl/`. The public Parsl interfaces described
below must retain their existing signatures and meanings.

1. **Completion is a publication boundary.** When a successful cached app Future
   becomes done, its result must already be available to memoization. An identical
   call made immediately after `future.result()` returns must reuse that result,
   must set `task_record["from_memo"]` to true, and must not execute the app body
   again. This must hold for ordinary Python values, nested containers, and a
   legitimate result of `None`.

2. **`task_exit` checkpoints are visible at completion.** With
   `checkpoint_mode="task_exit"`, before a successful cached app Future becomes
   observable as done, its run-specific
   `<dfk.run_dir>/checkpoint/tasks.pkl` file must contain the successful record.
   Code that calls `future.result()` and immediately opens that file must succeed.

3. **Terminal Futures expose fully finalized tasks.** With the default
   `Config.garbage_collect=True`, a task ID must no longer be present in
   `dfk.tasks` when its user-facing Future first becomes observable as done.
   The Future's done callback must not be responsible for that cleanup. This
   ordering applies to executed successes, memo hits, terminal execution errors,
   dependency failures, invalid join returns, and failures propagated through a
   join. Preserve the existing `garbage_collect=False` behavior, which retains
   task records for inspection.

4. **Deferred checkpoint modes retain completed outcomes.** In `manual`,
   `periodic`, and `dfk_exit` modes, successful cached task outcomes must be queued
   without depending on later reads from a user-facing Future. `dfk.checkpoint()`
   or normal DFK cleanup must write each queued success once. In `dfk_exit` mode,
   the file need not exist before cleanup, but it must contain all queued successes
   when cleanup returns. Concurrent task completion and a concurrent manual
   checkpoint call must not corrupt the pickle stream, duplicate a queued record,
   or lose completed records.

5. **Automatic recovery spans numbered runs.** If `checkpoint_files` is omitted
   and checkpointing is enabled, a new DFK must discover valid checkpoints under
   previous numbered run directories of `Config.run_dir`. Only all-decimal run
   directory names participate; unrelated directories below the run root must be
   ignored even if they contain a `checkpoint/tasks.pkl` path. Runs are ordered by
   numeric run ID, not lexicographically, so if later records repeat a hash the
   newest numbered run wins. The implementation must not search only the newly
   created per-run directory. The first invocation in a fresh run root executes
   normally; the same cached invocation in a second Parsl process must load the
   previous result, set `from_memo` to true, and not execute the app body.

6. **Explicit recovery remains supported.** Whenever
   `Config.checkpoint_files` is not `None`, that explicit list is authoritative.
   Each non-empty entry names a checkpoint directory containing `tasks.pkl` and
   must still be loaded even if it lies outside `Config.run_dir`. An explicit
   empty list disables automatic recovery; it must not silently fall back to
   scanning `Config.run_dir`.

7. **Failures are not successful cache entries.** A failed app must complete with
   its original exception behavior. It must not be emitted as a successful
   `{hash, exception, result}` checkpoint record and a later identical call must
   not return a fabricated successful value. Existing retry and join behavior must
   remain intact.

8. **Invalid checkpoints fail closed.** A requested checkpoint that is missing,
   empty, truncated, not a pickle stream of records, or has an invalid record
   schema must raise `parsl.dataflow.errors.BadCheckpoint` while loading. A clean
   end of file after a complete record is valid; an `EOFError` reached after any
   byte of a new record has begun is a truncated record, not a clean terminator.
   Do not silently discard a corrupt suffix, repair the file, or continue with a
   partial cache. The invalid file must remain byte-for-byte unchanged.

## Checkpoint compatibility contract

`tasks.pkl` is an append-only sequence of Python pickle objects. Every accepted
record is exactly a plain built-in dictionary (not a subclass) with the keys:

```text
hash       str
exception  None
result     any pickle-compatible Python value, including None
```

Writers must preserve that format. Do not introduce a replacement database,
sidecar index, alternate checkpoint filename, or a new public configuration API.
Checkpoint readers must accept valid files produced by the Starter and the
repaired implementation.

The ordering among independent task records is unspecified. For a given completed
task, however, the memoized result, any required `task_exit` record, final task
state, and default task-table cleanup must be published before its user-facing
Future is published.

## Allowed changes

You may modify Python source files under:

```text
/workspace/parsl-checkpoint/parsl/**
```

You may add focused source modules under that same directory. Do not modify the
incident probes, dependency installation, image definition, provenance/license
files, or paths outside `/workspace/parsl-checkpoint`. Do not replace Parsl with a
different package or intercept the probes.

## Environment and constraints

- Python 3.13 on Debian bookworm (`python:3.13-slim-bookworm`, digest pinned).
- Runtime dependencies are pinned and preinstalled from the offline wheel set.
- Candidate probes are network-isolated and the solution must not install packages
  or depend on a network service.
- Resource budget: 2 CPUs, 2 GiB RAM; individual verification scenarios use
  bounded thread pools and temporary directories.
- Preserve `Config(checkpoint_mode=..., checkpoint_files=..., run_dir=...)`,
  `DataFlowKernel.checkpoint()`, app decorators, `AppFuture.result()`,
  `task_record["from_memo"]`, `Config.garbage_collect`, and the on-disk schema
  above.

## Verification

The verifier hides its own assets before importing the candidate source in fresh,
network-isolated processes and uses randomized keys and values. It observes
app-body marker files, Future state, `from_memo`, independently decoded checkpoint
records, run-directory locations, exceptions, and artifact hashes. It covers
immediate duplicate submission, `None`, nested values, automatic and explicit
recovery (including an explicit empty list), numeric run ordering, deferred
modes, concurrent completion, terminal task cleanup across success/failure/join
paths, malformed checkpoints, and repeat execution.
