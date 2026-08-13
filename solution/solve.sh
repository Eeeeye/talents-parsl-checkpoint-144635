#!/bin/bash
set -Eeuo pipefail

workspace="${PARSL_WORKSPACE:-/workspace/parsl-checkpoint}"
solution_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for relative in \
    parsl/dataflow/dflow.py \
    parsl/dataflow/memoization.py \
    parsl/dataflow/completion.py
do
    source_path="${solution_root}/$(basename "${relative}")"
    destination="${workspace}/${relative}"
    if [[ ! -f "${source_path}" || ! -d "$(dirname "${destination}")" ]]; then
        echo "missing reference source or destination: ${relative}" >&2
        exit 1
    fi
    python3 -B - "${source_path}" "${destination}" <<'PY'
import os
import stat
import sys

source, destination = sys.argv[1:]
try:
    status = os.lstat(destination)
except FileNotFoundError:
    status = None
if status is not None and (not stat.S_ISREG(status.st_mode) or status.st_nlink != 1):
    raise SystemExit(f"unsafe reference destination: {destination}")

with open(source, "rb") as reader:
    payload = reader.read()

flags = os.O_WRONLY
if status is None:
    flags |= os.O_CREAT | os.O_EXCL
else:
    flags |= os.O_TRUNC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(destination, flags, 0o644)
try:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("short write while applying reference repair")
        view = view[written:]
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
done
