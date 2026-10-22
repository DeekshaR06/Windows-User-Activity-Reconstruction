"""core/timeline.py -- validate, de-duplicate, sort and save events.

    events, stats = build(all_events)
    write_csv(events, "output/timeline.csv")
    write_sqlite(events, "output/timeline.db")
"""
from __future__ import annotations

import csv
import json
import os
import sqlite3
from typing import Dict, Iterable, List, Tuple

from core.schema import CSV_COLUMNS, Event


def build(events: Iterable[Event]) -> Tuple[List[Event], Dict]:
    """Validate, remove exact duplicates, sort by time.

    Invalid events are NOT silently dropped: they are listed in stats['invalid']
    so the parser owner can fix them.
    """
    stats: Dict = {"input": 0, "invalid": [], "duplicates": 0, "output": 0}
    seen = set()
    good: List[Event] = []
    for ev in events:
        stats["input"] += 1
        if not isinstance(ev, Event):
            stats["invalid"].append("not an Event object: %r" % (ev,))
            continue
        probs = ev.problems()
        if probs:
            stats["invalid"].append("[%s] %s -> %s" % (ev.source, ev.summary[:60], "; ".join(probs)))
            continue
        key = (ev.timestamp_utc, ev.time_meaning, ev.source, ev.event_type, ev.user, ev.summary)
        if key in seen:
            stats["duplicates"] += 1
            continue
        seen.add(key)
        good.append(ev)
    good.sort(key=lambda e: (e.timestamp_utc, e.source, e.event_type, e.summary))
    stats["output"] = len(good)
    return good, stats


def write_csv(events: List[Event], path: str) -> None:
    """Write timeline.csv. utf-8 with BOM so Excel shows every character correctly."""
    _ensure_dir(path)
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(CSV_COLUMNS))
        writer.writeheader()
        for ev in events:
            writer.writerow(ev.to_row())


def read_csv(path: str) -> List[Event]:
    """Read a timeline.csv (or the demo file) back into Event objects."""
    with open(path, newline="", encoding="utf-8-sig") as fh:
        return [Event.from_row(row) for row in csv.DictReader(fh)]


def write_sqlite(events: List[Event], path: str) -> None:
    """Write timeline.db with one table 'events' (easy to query with SQL)."""
    _ensure_dir(path)
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    try:
        con.execute(
            "CREATE TABLE events ("
            "id INTEGER PRIMARY KEY, timestamp_utc TEXT NOT NULL, timestamp_ist TEXT, "
            "time_meaning TEXT, source TEXT, event_type TEXT, user TEXT, summary TEXT, "
            "details TEXT, evidence_file TEXT)"
        )
        con.execute("CREATE INDEX idx_events_time ON events(timestamp_utc)")
        con.execute("CREATE INDEX idx_events_type ON events(event_type)")
        rows = []
        for ev in events:
            r = ev.to_row()
            rows.append(tuple(r[c] for c in CSV_COLUMNS))
        con.executemany(
            "INSERT INTO events (timestamp_utc, timestamp_ist, time_meaning, source, event_type, "
            "user, summary, details, evidence_file) VALUES (?,?,?,?,?,?,?,?,?)", rows)
        con.commit()
    finally:
        con.close()


def _ensure_dir(path: str) -> None:
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
