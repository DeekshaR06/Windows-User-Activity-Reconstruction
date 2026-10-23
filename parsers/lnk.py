"""LNK (Recent files) parser (Member 2).

Contract: one public function, parse(evidence_dir) -> list[Event].
Emits one FILE_OPENED event per .lnk shortcut, with target path, size and
drive type. Removable drives are flagged clearly in the summary.
Never crashes on a bad file: logs a warning and moves on.

TIME NOTE: the timestamp used is the target file's last-accessed time stored
inside the shortcut (falling back to modified, then created). Check this
against LECmd on Day 6; if the team prefers the .lnk file's own modified time,
only _pick_time() needs to change.
"""
import logging
import os
from datetime import datetime, timezone

from core.schema import Event
from core.timeutil import to_iso

log = logging.getLogger(__name__)

SOURCE = "LNK"


def _find_lnk_files(evidence_dir):
    found = []
    for root, _dirs, files in os.walk(evidence_dir):
        for name in files:
            if name.lower().endswith(".lnk"):
                found.append(os.path.join(root, name))
    return sorted(found)


def _rel(evidence_dir, path):
    base = os.path.basename(os.path.normpath(evidence_dir))
    return os.path.join(base, os.path.relpath(path, evidence_dir)).replace("\\", "/")


def _find(obj, key):
    """Find the first value stored under `key` anywhere in nested dicts/lists."""
    if isinstance(obj, dict):
        if key in obj and obj[key] not in (None, ""):
            return obj[key]
        for v in obj.values():
            r = _find(v, key)
            if r not in (None, ""):
                return r
    elif isinstance(obj, list):
        for v in obj:
            r = _find(v, key)
            if r not in (None, ""):
                return r
    return None


def _to_dt(value):
    """LnkParse3 gives datetimes or text depending on version; accept both."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00").strip())
        except ValueError:
            return None
    # Shortcut times are FILETIMEs, i.e. already UTC; to_iso() needs a zone attached
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _pick_time(header):
    for key in ("accessed_time", "modified_time", "creation_time"):
        dt = _to_dt(header.get(key))
        # Unset FILETIMEs decode to the year 1601: ignore them
        if dt and dt.year > 1601:
            return dt, key
    return None, ""


def _target_path(info):
    base = _find(info, "local_base_path")
    suffix = _find(info, "common_path_suffix")
    if base and suffix:
        return str(base).rstrip("\\") + "\\" + str(suffix)
    if base:
        return str(base)
    for key in ("relative_path", "working_directory", "name"):
        val = _find(info, key)
        if val:
            return str(val)
    return ""


def _parse_one(path, evidence_dir):
    from LnkParse3 import lnk_file

    with open(path, "rb") as fh:
        info = lnk_file(fh).get_json()

    header = info.get("header", {}) if isinstance(info, dict) else {}
    dt, time_meaning = _pick_time(header)
    if dt is None:
        log.warning("LNK: no usable timestamp in %s; skipped", path)
        return []

    target = _target_path(info)
    drive_type = str(_find(info, "drive_type") or "")
    removable = "REMOVABLE" in drive_type.upper()
    size = header.get("file_size")
    name = os.path.basename(target) if target else os.path.basename(path)

    summary = "%s opened" % name
    if target:
        summary += " from %s" % target
    if removable:
        summary += " [REMOVABLE DRIVE]"

    return [
        Event(
            timestamp_utc=to_iso(dt),
            time_meaning="target_" + time_meaning,
            source=SOURCE,
            event_type="FILE_OPENED",
            user="",
            summary=summary,
            details={
                "target_path": target,
                "file_size": size,
                "drive_type": drive_type,
                "removable": removable,
                "drive_serial": str(_find(info, "drive_serial_number") or ""),
                "lnk_file": os.path.basename(path),
            },
            evidence_file=_rel(evidence_dir, path),
        )
    ]


def parse(evidence_dir: str) -> list:
    try:
        import LnkParse3  # noqa: F401
    except ImportError:
        log.warning("LNK: LnkParse3 is not installed; skipping")
        return []

    events = []
    for path in _find_lnk_files(evidence_dir):
        try:
            events.extend(_parse_one(path, evidence_dir))
        except Exception as exc:  # noqa: BLE001 - contract: never crash on a bad file
            log.warning("LNK: could not parse %s (%s)", path, exc)
    return events
