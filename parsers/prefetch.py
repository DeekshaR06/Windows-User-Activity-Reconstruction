"""parsers/prefetch.py -- owner: Member 2

Reads (from evidence_dir/Prefetch/): *.pf  (C:\\Windows\\Prefetch)
Produces event types: PROGRAM_EXECUTED
Notes: one event per recorded run time; details: run_count, path

Rules (the "parser contract"):
  * One public function: parse(evidence_dir) -> list[Event]
  * Use core.timeutil for EVERY time conversion. Store UTC only.
  * Never crash on a bad or missing file: log a warning and carry on.
  * Fill evidence_file with the exported file the record came from.
"""
from __future__ import annotations

import logging
import os
from typing import List

from core.schema import Event
from core import timeutil  # noqa: F401  (use to_iso(), filetime_to_utc(), ...)

log = logging.getLogger(__name__)

SOURCE = "Prefetch"
FOLDER = "Prefetch"


def parse(evidence_dir: str) -> List[Event]:
    folder = os.path.join(evidence_dir, FOLDER)
    if not os.path.isdir(folder):
        log.warning("%s: folder not found: %s", SOURCE, folder)
        return []
    events: List[Event] = []
    # TODO (Member 2): read the files, build Event(...) objects, append to events.
    #
    # Example of building one event:
    #   Event(
    #       timestamp_utc=timeutil.to_iso(timeutil.filetime_to_utc(raw_value)),
    #       time_meaning="last_run",
    #       source=SOURCE,
    #       event_type="PROGRAM_EXECUTED",
    #       user="",
    #       summary="NOTEPAD.EXE was run (run count 3)",
    #       details={"run_count": 3},
    #       evidence_file="Prefetch/NOTEPAD.EXE-D8414F97.pf",
    #   )
    return events
