"""Event Log parser (Member 3).

Public function: parse(evidence_dir) -> list[Event]

Reads Security.evtx and System.evtx found anywhere under evidence_dir and
returns Events for: logon/logoff, account created, process created,
log cleared, system start/stop.

Needs:  pip install python-evtx
"""
import logging
import ntpath
import os
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from Evtx.Evtx import Evtx

from core.schema import Event

log = logging.getLogger(__name__)

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

# Only real "a person sat at the PC" logon types (plan, Member 3 section)
LOGON_TYPES = {2: "Interactive", 7: "Unlock", 10: "RemoteInteractive", 11: "CachedInteractive"}

# Service / system accounts that would flood the timeline with noise
SKIP_USERS = {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON", "-", ""}
SKIP_PREFIXES = ("DWM-", "UMFD-")
SKIP_DOMAINS = {"Window Manager", "Font Driver Host"}

LOG_FILES = {"security.evtx": "security", "system.evtx": "system"}


# ----------------------------------------------------------------- helpers
def _iso(stamp: str) -> str:
    """'2026-10-22 04:35:10.123456' or '2026-10-22T04:35:10.1234567Z' -> '2026-10-22T04:35:10Z' (UTC)."""
    s = stamp.strip().replace(" ", "T").rstrip("Z")
    if "." in s:
        head, frac = s.split(".", 1)
        frac = "".join(c for c in frac if c.isdigit())[:6].ljust(6, "0")
        s = f"{head}.{frac}"
    dt = datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _text(el) -> str:
    return el.text.strip() if el is not None and el.text else ""


def _flatten(root) -> dict:
    """Collect <Data Name="x">value</Data> (EventData) and simple UserData children into one dict."""
    data = {}
    for el in root.iter():
        if el.tag.split("}")[-1] == "Data" and el.get("Name"):
            data[el.get("Name")] = (el.text or "").strip()
    ud = root.find(NS + "UserData")
    if ud is not None:
        for el in ud.iter():
            if el is not ud and len(el) == 0 and el.text and el.text.strip():
                data.setdefault(el.tag.split("}")[-1], el.text.strip())
    return data


def _is_noise_user(name: str, domain: str = "") -> bool:
    n = (name or "").strip()
    return (
        n.upper() in SKIP_USERS
        or n.endswith("$")  # machine accounts
        or n.upper().startswith(SKIP_PREFIXES)
        or domain in SKIP_DOMAINS
    )


# ------------------------------------------------------ one record -> Event
def _event_from_xml(xml_text: str, log_name: str, rel_file: str):
    """Turn one event's XML into an Event, or None if we do not care about it."""
    root = ET.fromstring(xml_text)
    system = root.find(NS + "System")
    if system is None:
        return None
    eid = int(_text(system.find(NS + "EventID")))
    prov_el = system.find(NS + "Provider")
    provider = prov_el.get("Name", "") if prov_el is not None else ""
    tc = system.find(NS + "TimeCreated")
    if tc is None or not tc.get("SystemTime"):
        return None
    ts = _iso(tc.get("SystemTime"))
    rec_id = _text(system.find(NS + "EventRecordID"))
    d = _flatten(root)

    def make(event_type, meaning, user, summary, extra=None):
        details = {"event_id": eid, "record_id": rec_id, "log": log_name}
        details.update(extra or {})
        return Event(
            timestamp_utc=ts,
            time_meaning=meaning,
            source="EventLog",
            event_type=event_type,
            user=user,
            summary=summary,
            details=details,
            evidence_file=rel_file,
        )

    if log_name == "security":
        if eid in (4624, 4634):
            user, dom = d.get("TargetUserName", ""), d.get("TargetDomainName", "")
            try:
                ltype = int(d.get("LogonType", "0"))
            except ValueError:
                return None
            if ltype not in LOGON_TYPES or _is_noise_user(user, dom):
                return None
            extra = {"logon_type": ltype, "logon_type_name": LOGON_TYPES[ltype],
                     "domain": dom, "logon_id": d.get("TargetLogonId", ""),
                     "linked_logon_id": d.get("TargetLinkedLogonId", "")}
            if eid == 4624:
                return make("USER_LOGON", "logon", user,
                            f"User {user} logged on ({LOGON_TYPES[ltype].lower()})", extra)
            return make("USER_LOGOFF", "logoff", user, f"User {user} logged off", extra)

        if eid == 4647:  # user-initiated logoff
            user, dom = d.get("TargetUserName", ""), d.get("TargetDomainName", "")
            if _is_noise_user(user, dom):
                return None
            return make("USER_LOGOFF", "logoff", user, f"User {user} logged off (user-initiated)",
                        {"domain": dom, "logon_id": d.get("TargetLogonId", "")})

        if eid == 4720:
            new_user, by = d.get("TargetUserName", ""), d.get("SubjectUserName", "")
            return make("ACCOUNT_CREATED", "created", new_user,
                        f"Local user {new_user} was created by {by}",
                        {"created_by": by, "new_user_sid": d.get("TargetSid", ""),
                         "created_by_machine": by.endswith("$")})

        if eid == 4688:
            user = d.get("SubjectUserName", "")
            if _is_noise_user(user, d.get("SubjectDomainName", "")):
                return None
            proc = d.get("NewProcessName", "")
            return make("PROGRAM_EXECUTED", "process_created", user,
                        f"{ntpath.basename(proc) or proc} was started by {user}",
                        {"path": proc, "command_line": d.get("CommandLine", ""),
                         "parent": d.get("ParentProcessName", ""), "pid": d.get("NewProcessId", "")})

        if eid == 1102:
            user = d.get("SubjectUserName", "")
            return make("LOG_CLEARED", "cleared", user,
                        f"The Security log was cleared by {user}", {"channel": "Security"})

    elif log_name == "system":
        if eid == 104 and "eventlog" in provider.lower():
            user, chan = d.get("SubjectUserName", ""), d.get("Channel", "")
            return make("LOG_CLEARED", "cleared", user,
                        f"The {chan} log was cleared by {user}", {"channel": chan})

        if eid in (6005, 6006) and provider.lower() == "eventlog":
            if eid == 6005:
                return make("SYSTEM_START", "started", "", "Windows started (Event Log service started)")
            return make("SYSTEM_SHUTDOWN", "stopped", "", "Windows shut down (Event Log service stopped)")

    return None


# ---------------------------------------------- linked logon pairs (Win 10/11)
NULL_LOGON_ID = "0x0000000000000000"


def _drop_linked_logons(events: list) -> list:
    """Windows 10/11 writes TWO 4624 records for one admin logon (a limited and an elevated token,
    microseconds apart, each pointing at the other with TargetLinkedLogonId). Keep the first only."""
    seen, out = set(), []
    for e in events:
        if e.event_type == "USER_LOGON":
            linked = e.details.get("linked_logon_id", "")
            if linked and linked != NULL_LOGON_ID and linked in seen:
                continue
            seen.add(e.details.get("logon_id", ""))
        out.append(e)
    return out


# ------------------------------------------------------------- public API
def _find_logs(evidence_dir: str):
    for root, _dirs, files in os.walk(evidence_dir):
        for f in files:
            if f.lower() in LOG_FILES:
                yield os.path.join(root, f), LOG_FILES[f.lower()]


def parse(evidence_dir: str) -> list:
    events = []
    found_any = False
    for path, log_name in _find_logs(evidence_dir):
        found_any = True
        rel = os.path.relpath(path, evidence_dir).replace("\\", "/")
        count = bad = 0
        try:
            with Evtx(path) as evtx:
                for record in evtx.records():
                    try:
                        ev = _event_from_xml(record.xml(), log_name, rel)
                    except Exception as exc:  # never crash on one bad record
                        bad += 1
                        log.warning("Skipping bad record in %s: %s", rel, exc)
                        continue
                    if ev:
                        events.append(ev)
                        count += 1
        except Exception as exc:  # never crash on a bad file
            log.warning("Could not read %s: %s", rel, exc)
        log.info("%s: %d events kept, %d bad records", rel, count, bad)
    if not found_any:
        log.warning("No Security.evtx / System.evtx found under %s", evidence_dir)
    events.sort(key=lambda e: e.timestamp_utc)
    return _drop_linked_logons(events)


def main(argv=None) -> int:
    """Command line use:  python -m parsers.evtx evidence/export --csv evtx_events.csv"""
    import argparse
    import csv
    import json

    ap = argparse.ArgumentParser(
        prog="python -m parsers.evtx",
        description="Parse Security.evtx and System.evtx from an exported evidence folder.",
    )
    ap.add_argument("evidence_dir", help="folder with the exported evidence (searched recursively)")
    ap.add_argument("--csv", metavar="FILE", help="also save the events to this CSV file")
    ap.add_argument("-v", "--verbose", action="store_true", help="show parser progress and warnings")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)
    events = parse(args.evidence_dir)
    for e in events:
        print(e.timestamp_utc, e.event_type, e.user, "|", e.summary)
    print(f"{len(events)} events")

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["timestamp_utc", "time_meaning", "source", "event_type", "user",
                        "summary", "details", "evidence_file"])
            for e in events:
                w.writerow([e.timestamp_utc, e.time_meaning, e.source, e.event_type, e.user,
                            e.summary, json.dumps(e.details, ensure_ascii=False), e.evidence_file])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())