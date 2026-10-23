"""analysis/sessions.py -- group events into logon sessions (owner: Member 5).

A session is the time between a USER_LOGON and the next USER_LOGOFF of the same
user.  It also ends at a SYSTEM_SHUTDOWN, or when a new logon for the same user
appears, or (if nothing ends it) at the last event in the data.

Why: a finding such as "USB copy then deletion" means much more when we can say
"...during ravi's session 2, 10:02 to 10:50".

    sessions = build_sessions(events)          # events from core.timeline.build()
    session_for(sessions, "ravi", "2026-10-22T05:00:00Z")   # -> 1
    write_csv(sessions, "output/sessions.csv")

Events that happen before any logon was recorded do not belong to any session.
"""
from __future__ import annotations

import csv
import os
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional

from core.schema import Event
from core.timeutil import iso_to_ist_text


@dataclass
class Session:
    session_id: int
    user: str
    start_utc: str
    end_utc: str
    ended_by: str          # "logoff", "shutdown", "new logon" or "end of data"
    event_count: int = 0


def build_sessions(events: Iterable[Event]) -> List[Session]:
    evs = sorted(events, key=lambda e: e.timestamp_utc)
    done: List[Session] = []
    open_: Dict[str, Session] = {}

    def close(user: str, ts: str, why: str) -> None:
        s = open_.pop(user)
        s.end_utc = ts
        s.ended_by = why
        done.append(s)

    for e in evs:
        if e.event_type == "USER_LOGON" and e.user:
            if e.user in open_:
                close(e.user, e.timestamp_utc, "new logon")
            open_[e.user] = Session(0, e.user, e.timestamp_utc, "", "")
        elif e.event_type == "USER_LOGOFF" and e.user:
            if e.user in open_:
                close(e.user, e.timestamp_utc, "logoff")
        elif e.event_type == "SYSTEM_SHUTDOWN":
            for u in list(open_):
                close(u, e.timestamp_utc, "shutdown")

    last = evs[-1].timestamp_utc if evs else ""
    for u in list(open_):
        close(u, last, "end of data")

    done.sort(key=lambda s: (s.start_utc, s.user))
    for i, s in enumerate(done, 1):
        s.session_id = i
        s.event_count = sum(
            1 for e in evs
            if s.start_utc <= e.timestamp_utc <= s.end_utc and e.user in ("", s.user)
        )
    return done


def session_for(sessions: Iterable[Session], user: str, ts_utc: str) -> Optional[int]:
    """Id of the session of `user` that contains the time `ts_utc`, or None."""
    for s in sessions:
        if s.user == user and s.start_utc <= ts_utc <= s.end_utc:
            return s.session_id
    return None


def write_csv(sessions: List[Session], path: str) -> None:
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    cols = ["session_id", "user", "start_ist", "end_ist", "start_utc", "end_utc", "ended_by", "event_count"]
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for s in sessions:
            w.writerow({
                "session_id": s.session_id, "user": s.user,
                "start_ist": iso_to_ist_text(s.start_utc), "end_ist": iso_to_ist_text(s.end_utc),
                "start_utc": s.start_utc, "end_utc": s.end_utc,
                "ended_by": s.ended_by, "event_count": s.event_count,
            })
