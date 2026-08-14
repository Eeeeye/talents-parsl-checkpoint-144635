import logging
import os


logger = logging.getLogger(__name__)


def _numbered_directory_ids(path: str) -> list[int]:
    run_ids = []
    with os.scandir(path) as entries:
        for entry in entries:
            name = entry.name
            if (
                name.isascii()
                and name.isdecimal()
                and entry.is_dir(follow_symlinks=False)
            ):
                run_ids.append(int(name))
    return run_ids


def make_rundir(path: str) -> str:
    """Atomically allocate a numbered run directory below *path*."""
    try:
        os.makedirs(path, exist_ok=True)
        run_ids = _numbered_directory_ids(path)
        next_id = max(run_ids, default=-1) + 1

        while True:
            current_rundir = os.path.join(path, f"{next_id:03d}")
            try:
                os.mkdir(current_rundir)
            except FileExistsError:
                next_id += 1
                continue

            logger.debug("Parsl run initializing in rundir: %s", current_rundir)
            return os.path.abspath(current_rundir)

    except Exception:
        logger.exception("Failed to create run directory")
        raise
