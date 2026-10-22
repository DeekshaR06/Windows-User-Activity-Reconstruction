"""core/schema.py -- the ONE common event format.  FROZEN at the end of Day 1.

Every parser turns what it finds into a list of Event objects.  Nothing else is
shared between parsers and the merge engine, so if you follow this file your
parser will plug in without anyone reading your code.

To change this file (new event type, new field), ask Member 5 in the group chat.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, List

from core.timeutil import iso_to_ist_text

SOURCES = ("Prefetch", "LNK", "EventLog", "RecycleBin", "USB", "Browser")

EVENT_TYPES = (
    "USER_LOGON",         # Event Log
    "USER_LOGOFF",        # Event Log
    "ACCOUNT_CREATED",    # Event Log
    "SYSTEM_START",       # Event Log
    "SYSTEM_SHUTDOWN",    # Event Log
    "LOG_CLEARED",        # Event Log
    "PROGRAM_EXECUTED",   # Prefetch, Event Log (4688)
    "FILE_OPENED",        # LNK
    "FILE_DELETED",       # Recycle Bin
    "USB_CONNECTED",      # USB
    "USB_REMOVED",        # USB
    "URL_VISITED",        # Browser
    "FILE_DOWNLOADED",    # Browser
)

# Column order of timeline.csv (note: timestamp_ist is added for human readers).
CSV_COLUMNS = (
    "timestamp_utc", "timestamp_ist", "time_meaning", "source",
    "event_type", "user", "summary", "details", "evidence_file",
)

_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


@dataclass
class Event:
    timestamp_utc: str      # ISO 8601 UTC, e.g. "2026-10-22T04:35:10Z"  (use core.timeutil.to_iso)
    time_meaning: str       # what this time means: "last_run", "created", "deleted", "visited" ...
    source: str             # one of SOURCES
    event_type: str         # one of EVENT_TYPES
    user: str               # user name if known, else ""
    summary: str            # one readable sentence for humans
    details: Dict = field(default_factory=dict)   # extra facts: run_count, serial, size ...
    evidence_file: str = ""  # which exported file this came from (for proof)

    def problems(self) -> List[str]:
        """Return a list of reasons this event is invalid (empty list = valid)."""
        out: List[str] = []
        if not isinstance(self.timestamp_utc, str) or not _TS_RE.match(self.timestamp_utc):
            out.append("timestamp_utc must look like 2026-10-22T04:35:10Z (got %r)" % (self.timestamp_utc,))
        if not self.time_meaning:
            out.append("time_meaning is empty")
        if self.source not in SOURCES:
            out.append("source %r not in %s" % (self.source, ", ".join(SOURCES)))
        if self.event_type not in EVENT_TYPES:
            out.append("event_type %r is not an allowed type" % (self.event_type,))
        if not self.summary:
            out.append("summary is empty")
        if not isinstance(self.details, dict):
            out.append("details must be a dict")
        return out

    def is_valid(self) -> bool:
        return not self.problems()

    def to_row(self) -> Dict[str, str]:
        """Flat dict for CSV (details becomes JSON text)."""
        return {
            "timestamp_utc": self.timestamp_utc,
            "timestamp_ist": iso_to_ist_text(self.timestamp_utc),
            "time_meaning": self.time_meaning,
            "source": self.source,
            "event_type": self.event_type,
            "user": self.user,
            "summary": self.summary,
            "details": json.dumps(self.details, ensure_ascii=False, sort_keys=True, default=str),
            "evidence_file": self.evidence_file,
        }

    @classmethod
    def from_row(cls, row: Dict[str, str]) -> "Event":
        raw = (row.get("details") or "").strip()
        try:
            details = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            details = {"raw_details": raw}
        return cls(
            timestamp_utc=(row.get("timestamp_utc") or "").strip(),
            time_meaning=(row.get("time_meaning") or "").strip(),
            source=(row.get("source") or "").strip(),
            event_type=(row.get("event_type") or "").strip(),
            user=(row.get("user") or "").strip(),
            summary=(row.get("summary") or "").strip(),
            details=details if isinstance(details, dict) else {"value": details},
            evidence_file=(row.get("evidence_file") or "").strip(),
        )
