#!/bin/bash
set -Eeuo pipefail

workspace="${PARSL_WORKSPACE:-/workspace/parsl-checkpoint}"
run_root="$(mktemp -d /tmp/parsl-checkpoint-incident.XXXXXX)"

cd "${workspace}"
echo "publication-boundary scenario"
python3 -B incident/reproduce.py visibility --root "${run_root}/visibility"
echo "cross-run recovery scenario"
python3 -B incident/reproduce.py restart --root "${run_root}/restart"
echo "artifacts: ${run_root}"
