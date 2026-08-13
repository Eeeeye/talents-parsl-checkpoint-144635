#!/bin/bash
set -Eeuo pipefail

terminate() {
    if [[ -n "${child_pid:-}" ]]; then
        kill -TERM "${child_pid}" 2>/dev/null || true
        wait "${child_pid}" 2>/dev/null || true
    fi
    exit 0
}
trap terminate TERM INT HUP

if (( $# > 0 )); then
    exec "$@"
fi

sleep infinity &
child_pid=$!
wait "${child_pid}"
