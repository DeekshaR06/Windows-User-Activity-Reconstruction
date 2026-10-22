#!/usr/bin/env python3
"""main.py -- run the whole pipeline with one command.

    python main.py --evidence evidence/export --out output     # real evidence
    python main.py --demo --out output                         # fake demo events

Steps: run every parser -> validate + de-duplicate + sort -> write timeline files.
A parser that crashes or is not written yet is skipped with a warning; the rest still run.
"""
from __future__ import annotations

import argparse
import importlib
import logging
import os
import sys
from collections import Counter
from typing import List, Tuple

from core import timeline
from core.schema import Event

log = logging.getLogger("main")

# (module, label shown in the summary)
PARSERS = [
    ("parsers.prefetch", "Prefetch"),
    ("parsers.lnk", "LNK"),
    ("parsers.evtx", "EventLog"),
    ("parsers.recyclebin", "RecycleBin"),
    ("parsers.usb", "USB"),
    ("parsers.browser", "Browser"),
]

DEMO_FILE = os.path.join("demo", "fake_events.csv")


def run_parsers(evidence_dir: str) -> Tuple[List[Event], List[Tuple[str, int, str]]]:
    events: List[Event] = []
    status: List[Tuple[str, int, str]] = []
    for modname, label in PARSERS:
        try:
            module = importlib.import_module(modname)
            found = list(module.parse(evidence_dir))
        except Exception as exc:  # a broken parser must never stop the others
            log.warning("%s FAILED: %s: %s", label, type(exc).__name__, exc)
            status.append((label, 0, "FAILED: %s" % exc))
            continue
        events.extend(found)
        status.append((label, len(found), "ok" if found else "no events (not written yet, or nothing found)"))
    return events, status


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Windows User Activity Reconstruction")
    ap.add_argument("--evidence", default=os.path.join("evidence", "export"),
                    help="folder with the exported artifact files (default: evidence/export)")
    ap.add_argument("--out", default="output", help="folder for timeline.csv / timeline.db")
    ap.add_argument("--demo", action="store_true",
                    help="skip parsers and load demo/fake_events.csv instead")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")

    if args.demo:
        if not os.path.exists(DEMO_FILE):
            log.error("demo file not found: %s", DEMO_FILE)
            return 2
        raw = timeline.read_csv(DEMO_FILE)
        status = [("demo file", len(raw), "ok")]
    else:
        if not os.path.isdir(args.evidence):
            log.error("evidence folder not found: %s", args.evidence)
            return 2
        raw, status = run_parsers(args.evidence)

    events, stats = timeline.build(raw)
    for problem in stats["invalid"]:
        log.warning("INVALID EVENT SKIPPED: %s", problem)

    csv_path = os.path.join(args.out, "timeline.csv")
    db_path = os.path.join(args.out, "timeline.db")
    timeline.write_csv(events, csv_path)
    timeline.write_sqlite(events, db_path)

    print("\n=== Summary ===")
    for label, count, note in status:
        print("  %-12s %5d events   %s" % (label, count, note))
    print("  read %d | invalid %d | duplicates removed %d | written %d"
          % (stats["input"], len(stats["invalid"]), stats["duplicates"], stats["output"]))
    by_type = Counter(e.event_type for e in events)
    if by_type:
        print("  by type: " + ", ".join("%s=%d" % kv for kv in sorted(by_type.items())))
    print("  -> %s\n  -> %s" % (csv_path, db_path))
    return 0


if __name__ == "__main__":
    sys.exit(main())
