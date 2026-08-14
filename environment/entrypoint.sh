#!/bin/bash
set -Eeuo pipefail

if (( $# > 0 )); then
    exec "$@"
fi

exec python3 -Bc '
import signal

shutdown_signals = {signal.SIGHUP, signal.SIGINT, signal.SIGTERM}
signal.pthread_sigmask(signal.SIG_BLOCK, shutdown_signals)
signal.sigwait(shutdown_signals)
'
