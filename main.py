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

from analysis import rules, sessions
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
    ap.add_argument("--working-hours", metavar="START-END",
                    help="switch on rule R7 (off-hours activity); IST hours, e.g. 9-18")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    working_hours = None
    if args.working_hours:
        try:
            a, b = args.working_hours.split("-")
            working_hours = (int(a), int(b))
            if not (0 <= working_hours[0] < working_hours[1] <= 24):
                raise ValueError
        except ValueError:
            ap.error("--working-hours must look like 9-18 (start hour before end hour, 0 to 24)")

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

    # Analysis runs after the timeline is saved, so a rule bug can never lose the timeline.
    sessions_path = os.path.join(args.out, "sessions.csv")
    findings_path = os.path.join(args.out, "findings.csv")
    found_sessions, findings = [], []
    try:
        found_sessions = sessions.build_sessions(events)
        findings = rules.run_all(events, found_sessions, working_hours)
        sessions.write_csv(found_sessions, sessions_path)
        rules.write_csv(findings, findings_path)
    except Exception as exc:
        log.warning("ANALYSIS FAILED (timeline is still saved): %s: %s", type(exc).__name__, exc)

    # The HTML page is built last and on its own, so a viewer bug cannot lose any other output.
    html_path = os.path.join(args.out, "timeline.html")
    try:
        from report import html_timeline
        html_timeline.write(html_path, csv_path,
                            findings_path if findings else None,
                            sessions_path if found_sessions else None)
    except Exception as exc:
        log.warning("HTML VIEWER FAILED (the other outputs are saved): %s: %s", type(exc).__name__, exc)
        html_path = None

    print("\n=== Summary ===")
    for label, count, note in status:
        print("  %-12s %5d events   %s" % (label, count, note))
    print("  read %d | invalid %d | duplicates removed %d | written %d"
          % (stats["input"], len(stats["invalid"]), stats["duplicates"], stats["output"]))
    by_type = Counter(e.event_type for e in events)
    if by_type:
        print("  by type: " + ", ".join("%s=%d" % kv for kv in sorted(by_type.items())))
    print("  -> %s\n  -> %s" % (csv_path, db_path))
    by_sev = Counter(f.severity for f in findings)
    print("  sessions: %d | findings: %d (%s)"
          % (len(found_sessions), len(findings),
             ", ".join("%s=%d" % (k, by_sev[k]) for k in ("High", "Medium", "Low") if by_sev[k]) or "none"))
    for f in findings:
        if f.severity == "High":
            print("    HIGH [%s] %s" % (f.rule_id, f.description))
    if found_sessions or findings:
        print("  -> %s\n  -> %s" % (sessions_path, findings_path))
    if html_path:
        print("  -> %s   (open this in a browser)" % html_path)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
