"""analysis/rules.py -- simple, explainable rules that flag suspicious patterns (owner: Member 5).

Each rule reads the sorted timeline and returns Findings.  Every finding lists
the exact events that triggered it, so a reader can check it by hand.  These
are plain if-statements on purpose: the aim is a believable, checkable story,
not artificial intelligence.

    ID  Name                          Logic                                                     Severity
    R1  Possible data copy via USB    USB connected, then a file opened from a removable        High
                                      drive within 30 min (deletions / log clearing in the
                                      same window are added to the story)
    R2  Deletion after USB use        file deleted within 30 min after a USB connect / remove   Medium
    R3  Download then run             downloaded file is run within 10 min                      Medium
    R4  Run from risky location       program run from Downloads, Temp or a removable drive     Low
    R5  Log cleared                   any LOG_CLEARED event                                     High
    R6  Account created then used     ACCOUNT_CREATED, then logon of that user within 1 day     Low
    R7  Off-hours activity            events outside working hours (OFF by default)             Low

    findings = run_all(events, sessions)
    write_csv(findings, "output/findings.csv")

Parsers differ in how much detail they put in `details`, so the rules look at the
summary text as well as the details (see _text).
"""
from __future__ import annotations

import csv
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Iterable, List, Optional, Tuple

from core.schema import Event
from core.timeutil import IST, iso_to_dt, iso_to_ist_text
from analysis import sessions as sess_mod

USB_WINDOW = timedelta(minutes=30)
DOWNLOAD_RUN_WINDOW = timedelta(minutes=10)
ACCOUNT_USE_WINDOW = timedelta(days=1)
SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}

_DRIVE_RE = re.compile(r"\b[D-Zd-z]:(\\|\s|$)")          # D: ... Z:  (C: is the system drive)
_RISKY_PATH_RE = re.compile(r"\b(downloads|temp)\b", re.IGNORECASE)
# Browsers name a repeat download "name (1).exe", so allow an optional " (n)" before the extension.
_PROGRAM_NAME_RE = re.compile(r"[\w\-.]+(?: \(\d+\))?\.(?:exe|msi|bat|cmd|ps1|scr|jar|vbs)", re.IGNORECASE)
# Windows' own background updaters run from Temp folders: not interesting for R4.
_KNOWN_BENIGN = ("microsoftedgeupdate.exe", "googleupdate.exe", "onedrivesetup.exe")


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str                 # High / Medium / Low
    user: str
    description: str
    evidence: List[Event] = field(default_factory=list)
    session_id: Optional[int] = None
    finding_id: int = 0

    @property
    def start_utc(self) -> str:
        return min(e.timestamp_utc for e in self.evidence) if self.evidence else ""

    @property
    def end_utc(self) -> str:
        return max(e.timestamp_utc for e in self.evidence) if self.evidence else ""


# ---------------------------------------------------------------- helpers
def _t(ev: Event) -> datetime:
    dt = iso_to_dt(ev.timestamp_utc)
    if dt is None:                       # cannot happen for events that passed timeline.build()
        raise ValueError("bad timestamp: %r" % ev.timestamp_utc)
    return dt


def _text(ev: Event) -> str:
    return (ev.summary + " " + json.dumps(ev.details, default=str, ensure_ascii=False)).lower()


def _is_removable(ev: Event) -> bool:
    """True if the event is about a removable (USB) drive."""
    details = ev.details or {}
    if "removable" in details:                    # LNK parser: explicit True / False
        return bool(details["removable"])
    drive_type = str(details.get("drive_type", "")).strip().lower()
    if drive_type:                                # e.g. "DRIVE_REMOVABLE" or "removable"
        return "removable" in drive_type
    return "(removable)" in ev.summary.lower() or "[removable drive]" in ev.summary.lower() \
        or bool(_DRIVE_RE.search(ev.summary))


def _sorted(events: Iterable[Event]) -> List[Event]:
    return sorted(events, key=lambda e: e.timestamp_utc)


def _plural(n: int, word: str) -> str:
    return "%d %s%s" % (n, word, "" if n == 1 else "s")


# ------------------------------------------------------------------ rules
def r1_usb_copy(events: List[Event]) -> List[Finding]:
    out: List[Finding] = []
    for usb in (e for e in events if e.event_type == "USB_CONNECTED"):
        t0 = _t(usb)
        window = [e for e in events if e is not usb and t0 <= _t(e) <= t0 + USB_WINDOW]
        opens = [e for e in window if e.event_type == "FILE_OPENED" and _is_removable(e)]
        if not opens:
            continue
        dels = [e for e in window if e.event_type == "FILE_DELETED"]
        clears = [e for e in window if e.event_type == "LOG_CLEARED"]
        parts = [_plural(len(opens), "file") + " opened from a removable drive"]
        if dels:
            parts.append(_plural(len(dels), "file") + " deleted")
        if clears:
            parts.append("an event log cleared")
        tail = " Possible data copy to USB followed by an attempt to hide it." if (dels or clears) \
            else " Possible data copy to USB."
        desc = "USB device connected, then within 30 minutes: " + ", ".join(parts) + "." + tail
        out.append(Finding("R1", "Possible data copy via USB", "High", usb.user or opens[0].user,
                           desc, _sorted([usb] + opens + dels + clears)))
    return out


def r2_delete_after_usb(events: List[Event]) -> List[Finding]:
    out: List[Finding] = []
    reported = set()
    usb_events = [e for e in events if e.event_type in ("USB_CONNECTED", "USB_REMOVED")]
    for usb in usb_events:
        t0 = _t(usb)
        dels = [e for e in events
                if e.event_type == "FILE_DELETED" and t0 <= _t(e) <= t0 + USB_WINDOW and id(e) not in reported]
        if not dels:
            continue
        reported.update(id(d) for d in dels)
        desc = "%s deleted within 30 minutes after a USB device was %s." % (
            _plural(len(dels), "file"), "connected" if usb.event_type == "USB_CONNECTED" else "removed")
        out.append(Finding("R2", "Deletion after USB use", "Medium", usb.user or dels[0].user,
                           desc, _sorted([usb] + dels)))
    return out


def r3_download_then_run(events: List[Event]) -> List[Finding]:
    out: List[Finding] = []
    for dl in (e for e in events if e.event_type == "FILE_DOWNLOADED"):
        names = {n.lower() for n in _PROGRAM_NAME_RE.findall(_text(dl))}
        if not names:
            continue
        t0 = _t(dl)
        for run in (e for e in events if e.event_type == "PROGRAM_EXECUTED" and t0 <= _t(e) <= t0 + DOWNLOAD_RUN_WINDOW):
            hit = next((n for n in sorted(names) if n in _text(run)), None)
            if hit:
                out.append(Finding("R3", "Download then run", "Medium", dl.user or run.user,
                                   "'%s' was downloaded and then run within 10 minutes." % hit,
                                   _sorted([dl, run])))
    return out


def r4_risky_location(events: List[Event]) -> List[Finding]:
    out: List[Finding] = []
    for run in (e for e in events if e.event_type == "PROGRAM_EXECUTED"):
        if any(name in run.summary.lower() for name in _KNOWN_BENIGN):
            continue
        if _RISKY_PATH_RE.search(_text(run)) or _is_removable(run):
            out.append(Finding("R4", "Run from risky location", "Low", run.user,
                               "A program was run from a Downloads, Temp or removable-drive location: %s" % run.summary,
                               [run]))
    return out


def r5_log_cleared(events: List[Event]) -> List[Finding]:
    return [Finding("R5", "Log cleared", "High", e.user,
                    "An event log was cleared. Clearing logs is a common way to hide activity: %s" % e.summary, [e])
            for e in events if e.event_type == "LOG_CLEARED"]


def r6_account_created_then_used(events: List[Event]) -> List[Finding]:
    out: List[Finding] = []
    for acc in (e for e in events if e.event_type == "ACCOUNT_CREATED" and e.user):
        t0 = _t(acc)
        logon = next((e for e in events if e.event_type == "USER_LOGON" and e.user == acc.user
                      and t0 <= _t(e) <= t0 + ACCOUNT_USE_WINDOW), None)
        if logon:
            out.append(Finding("R6", "Account created then used", "Low", acc.user,
                               "Account '%s' was created and used to log on within 1 day." % acc.user,
                               [acc, logon]))
    return out


def r7_off_hours(events: List[Event], start_hour: int, end_hour: int) -> List[Finding]:
    """Optional. Working hours are in IST (24-hour clock), e.g. 9 and 18."""
    off = [e for e in events
           if e.event_type not in ("SYSTEM_START", "SYSTEM_SHUTDOWN")
           and not (start_hour <= _t(e).astimezone(IST).hour < end_hour)]
    if not off:
        return []
    desc = "%s outside working hours (%02d:00 to %02d:00 IST)." % (_plural(len(off), "event"), start_hour, end_hour)
    return [Finding("R7", "Off-hours activity", "Low", off[0].user, desc, _sorted(off))]


# ------------------------------------------------------------------- run
RULES: List[Callable[[List[Event]], List[Finding]]] = [
    r1_usb_copy, r2_delete_after_usb, r3_download_then_run,
    r4_risky_location, r5_log_cleared, r6_account_created_then_used,
]


def run_all(events: Iterable[Event], sessions: Optional[List[sess_mod.Session]] = None,
            working_hours: Optional[Tuple[int, int]] = None) -> List[Finding]:
    """Run every rule. `working_hours=(9, 18)` also switches on R7."""
    evs = _sorted(events)
    findings: List[Finding] = []
    for rule in RULES:
        findings.extend(rule(evs))
    if working_hours:
        findings.extend(r7_off_hours(evs, working_hours[0], working_hours[1]))
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.start_utc, f.rule_id))
    for i, f in enumerate(findings, 1):
        f.finding_id = i
        if sessions:
            f.session_id = sess_mod.session_for(sessions, f.user, f.start_utc)
    return findings


def write_csv(findings: List[Finding], path: str) -> None:
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    cols = ["finding_id", "severity", "rule_id", "rule_name", "user", "session_id",
            "start_ist", "start_utc", "end_utc", "description", "evidence_count", "evidence"]
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for f in findings:
            w.writerow({
                "finding_id": f.finding_id, "severity": f.severity, "rule_id": f.rule_id,
                "rule_name": f.rule_name, "user": f.user,
                "session_id": "" if f.session_id is None else f.session_id,
                "start_ist": iso_to_ist_text(f.start_utc), "start_utc": f.start_utc, "end_utc": f.end_utc,
                "description": f.description, "evidence_count": len(f.evidence),
                "evidence": " || ".join("%s | %s | %s" % (iso_to_ist_text(e.timestamp_utc), e.source, e.summary)
                                        for e in f.evidence),
            })
