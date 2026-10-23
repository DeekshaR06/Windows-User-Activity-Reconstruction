"""Prefetch parser (Member 2).

Contract: one public function, parse(evidence_dir) -> list[Event].
Emits one PROGRAM_EXECUTED event per recorded run time (up to 8 per .pf file).
Never crashes on a bad file: logs a warning and moves on.
"""
import logging
import os

from core.schema import Event
from core.timeutil import filetime_to_utc, to_iso

log = logging.getLogger(__name__)

SOURCE = "Prefetch"


def _find_pf_files(evidence_dir):
    found = []
    for root, _dirs, files in os.walk(evidence_dir):
        for name in files:
            if name.lower().endswith(".pf"):
                found.append(os.path.join(root, name))
    return sorted(found)


def _rel(evidence_dir, path):
    """Path shown as proof, e.g. export/Prefetch/NOTEPAD.EXE-D8414F97.pf"""
    base = os.path.basename(os.path.normpath(evidence_dir))
    return os.path.join(base, os.path.relpath(path, evidence_dir)).replace("\\", "/")


def _full_exe_path(scca_file, exe_name):
    """Best effort: find the loaded-file entry that ends with the exe name."""
    try:
        for i in range(scca_file.get_number_of_filenames()):
            fn = scca_file.get_filename(i)
            if fn and fn.upper().endswith("\\" + exe_name.upper()):
                return fn
    except Exception:  # noqa: BLE001 - optional detail, never fatal
        pass
    return ""


def _parse_one(path, evidence_dir):
    import pyscca  # imported here so a missing library gives a clear warning

    events = []
    f = pyscca.file()
    f.open(path)
    try:
        exe_name = f.get_executable_filename() or os.path.basename(path).split("-")[0]
        run_count = f.get_run_count()
        exe_path = _full_exe_path(f, exe_name)
        try:
            pf_hash = "%08X" % f.get_prefetch_hash()
        except Exception:  # noqa: BLE001
            pf_hash = ""

        for idx in range(8):  # Win 8 and later keep up to 8 run times
            try:
                ft = f.get_last_run_time_as_integer(idx)
            except Exception:  # noqa: BLE001
                break
            run_time = filetime_to_utc(ft)
            if run_time is None:  # 0 / invalid means the slot is empty
                continue
            events.append(
                Event(
                    timestamp_utc=to_iso(run_time),
                    time_meaning="last_run",
                    source=SOURCE,
                    event_type="PROGRAM_EXECUTED",
                    user="",
                    summary="%s was run (run count %s)" % (exe_name, run_count),
                    details={
                        "executable": exe_name,
                        "run_count": run_count,
                        "path": exe_path,
                        "prefetch_hash": pf_hash,
                        "run_slot": idx,
                    },
                    evidence_file=_rel(evidence_dir, path),
                )
            )
    finally:
        f.close()
    return events


def parse(evidence_dir: str) -> list:
    try:
        import pyscca  # noqa: F401
    except ImportError:
        log.warning("Prefetch: libscca-python (pyscca) is not installed; skipping")
        return []

    events = []
    for path in _find_pf_files(evidence_dir):
        try:
            events.extend(_parse_one(path, evidence_dir))
        except Exception as exc:  # noqa: BLE001 - contract: never crash on a bad file
            log.warning("Prefetch: could not parse %s (%s)", path, exc)
    return events
