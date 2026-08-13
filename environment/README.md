# Parsl checkpoint visibility incident workspace

This repository contains a pinned Parsl source tree and two offline diagnostic
probes for a completion/checkpoint incident in a scientific workflow launcher.
It runs entirely on the local thread executor, so no scheduler allocation or
network service is needed to reproduce the control-plane failure.

Python and all runtime dependencies are preinstalled in the task image. Source
under `parsl/` is imported directly through `PYTHONPATH`.

## Reproduce

```bash
./scripts/reproduce.sh
```

The script creates a fresh directory under `/tmp`, runs the publication-boundary
probe and then runs the same cached task in two successive Parsl runs. It prints
JSON reports and the path holding the run directories and marker files.

You can run either scenario directly:

```bash
python3 -B incident/reproduce.py visibility --root /tmp/parsl-visibility
python3 -B incident/reproduce.py restart --root /tmp/parsl-restart
```

Repair locations are not marked in the source. Use the observable contract in
the task instruction as the authoritative target.
