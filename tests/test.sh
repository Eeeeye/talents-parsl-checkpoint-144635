#!/bin/bash
set -Eeuo pipefail

workspace="${PARSL_WORKSPACE:-/workspace/parsl-checkpoint}"
verifier_root="/logs/verifier"
reward_path="${verifier_root}/reward.txt"
log_path="${verifier_root}/parsl-checkpoint-tests.log"

mkdir -p "${verifier_root}"
rm -f "${reward_path}" "${log_path}"

write_reward() {
    python3 -B - "${reward_path}" "$1" <<'PY'
import os
import stat
import sys

path, value = sys.argv[1:]
try:
    status = os.lstat(path)
except FileNotFoundError:
    status = None
if status is not None:
    if stat.S_ISDIR(status.st_mode):
        raise SystemExit("unsafe reward destination")
    os.unlink(path)

flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(path, flags, 0o644)
try:
    payload = (value + "\n").encode("ascii")
    if os.write(descriptor, payload) != len(payload):
        raise OSError("short reward write")
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
}

trap 'exit_code=$?; if (( exit_code != 0 )); then write_reward 0; fi' EXIT

exec 3< /tests/test_task.py
actual_verifier="$(sha256sum /proc/self/fd/3 | awk '{print $1}')"
expected_verifier="542bce78912bc2bfa293b60039944903d883fcdcbefe01cee40f16a13171c0fe"
declared_verifier="$(awk 'NF == 2 && $2 == "test_task.py" {print $1}' /tests/verifier.sha256)"
if [[ "${declared_verifier}" != "${expected_verifier}" || "${actual_verifier}" != "${expected_verifier}" ]]; then
    echo "trusted verifier digest mismatch" >&2
    exit 1
fi

: >"${log_path}"
chmod 0600 "${log_path}"
exec > >(tee "${log_path}") 2>&1

reject_agent_processes() {
    python3 -B - <<'PY'
from pathlib import Path

found = []
for entry in Path("/proc").iterdir():
    if not entry.name.isdigit():
        continue
    try:
        lines = (entry / "status").read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        continue
    uid_line = next((line for line in lines if line.startswith("Uid:")), "")
    if uid_line and 1000 in {int(value) for value in uid_line.split()[1:]}:
        found.append(entry.name)
if found:
    raise SystemExit("untrusted candidate process remains: " + ",".join(found))
PY
}

reject_agent_processes

if [[ ! -d "${workspace}/parsl" || -L "${workspace}" || -L "${workspace}/parsl" ]]; then
    echo "candidate workspace is missing or unsafe" >&2
    exit 1
fi

while IFS= read -r -d '' entry; do
    name="$(basename -- "${entry}")"
    case "${name}" in
        LICENSE|README.md|UPSTREAM.md|incident|parsl|scripts)
            ;;
        *)
            echo "path outside the allowed candidate surface: ${name}" >&2
            exit 1
            ;;
    esac
done < <(find "${workspace}" -mindepth 1 -maxdepth 1 -print0)

if find "${workspace}" -xdev \( -type l -o -type b -o -type c -o -type p -o -type s \) -print -quit | grep -q .; then
    echo "candidate workspace contains a symlink or special file" >&2
    exit 1
fi
if find "${workspace}" -xdev -type f -links +1 -print -quit | grep -q .; then
    echo "candidate workspace contains a multiply-linked file" >&2
    exit 1
fi

if [[ ! -d /tests || -L /tests || ( -e /solution && ( ! -d /solution || -L /solution ) ) ]]; then
    echo "verifier directory is missing or unsafe" >&2
    exit 1
fi

while read -r expected relative; do
    target="${workspace}/${relative}"
    [[ -f "${target}" && ! -L "${target}" ]] || {
        echo "candidate-visible support file is missing or unsafe: ${relative}" >&2
        exit 1
    }
    actual="$(sha256sum "${target}" | awk '{print $1}')"
    [[ "${actual}" == "${expected}" ]] || {
        echo "candidate-visible support file was modified: ${relative}" >&2
        exit 1
    }
done </tests/starter_assets.sha256

python3 -B - <<'PY'
from pathlib import Path
import shutil

for path in (Path("/tests"), Path("/solution")):
    if path.exists():
        shutil.rmtree(path)
        if path.exists():
            raise SystemExit(f"trusted upload directory remains visible: {path}")
PY

PARSL_VERIFIER_FD=3 PYTHONPATH="${workspace}" \
    python3 -B /proc/self/fd/3 --workspace "${workspace}"

reject_agent_processes
write_reward 1
