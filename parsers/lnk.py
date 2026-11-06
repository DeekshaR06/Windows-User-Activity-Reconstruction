"""LNK (Recent files) parser (Member 2).

Contract: one public function, parse(evidence_dir) -> list[Event].
Emits one FILE_OPENED event per .lnk shortcut, with target path, size and
drive type. Removable drives are flagged clearly in the summary.
Never crashes on a bad file: logs a warning and moves on.

TIME NOTE: the timestamp used is the target file's last-accessed time stored
inside the shortcut, with two exceptions found on the real evidence:
  * placeholder dates (year 1601 = unset, 1980-01-01 = FAT "zero" date) are
    not real times and are ignored;
  * USB sticks (FAT/exFAT) keep only the DATE for "last accessed", which shows
    up as exactly midnight local time. When that happens the target's
    modified time is used instead (time_meaning says which one was used).
All three target times are also kept in details for checking against LECmd.
If the team prefers the .lnk file's own modified time (not stored inside the
file, so it needs the original file timestamps), only _pick_time() changes.
"""
import logging
import ntpath
import os
from datetime import datetime, timezone

from core.schema import Event
from core.timeutil import IST, to_iso

log = logging.getLogger(__name__)

SOURCE = "LNK"
FOLDER = "Recent"
MIN_YEAR = 1990  # earlier years (1601, 1980) are "no time recorded" placeholders
TIME_KEYS = ("accessed_time", "modified_time", "creation_time")


def _find_lnk_files(folder):
    found = []
    for root, _dirs, files in os.walk(folder):
        for name in files:
            if name.lower().endswith(".lnk"):
                found.append(os.path.join(root, name))
    return sorted(found)


def _rel(evidence_dir, path):
    """Path shown as proof, e.g. Recent/client_list.csv.lnk"""
    folder = os.path.join(evidence_dir, FOLDER)
    return (FOLDER + "/" + os.path.relpath(path, folder)).replace("\\", "/")


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


def _usable(dt):
    return dt is not None and dt.year >= MIN_YEAR


def _is_date_only(dt):
    """FAT/exFAT drives store only the date for 'last accessed'. Windows shows
    it as exactly 00:00:00 local time (IST on our VM)."""
    local = dt.astimezone(IST)
    return (local.hour, local.minute, local.second, local.microsecond) == (0, 0, 0, 0)


def _pick_time(header):
    """Return (datetime, key) for the best real time in the shortcut, or (None, "")."""
    times = {key: _to_dt(header.get(key)) for key in TIME_KEYS}
    for key in TIME_KEYS:
        dt = times[key]
        if not _usable(dt):
            continue
        if key == "accessed_time" and _is_date_only(dt):
            continue  # date-only: a more precise time is tried next
        return dt, key
    # Nothing better: a date-only accessed time still beats no time at all
    if _usable(times["accessed_time"]):
        return times["accessed_time"], "accessed_time"
    return None, ""


def _iso_or_blank(value):
    dt = _to_dt(value)
    return to_iso(dt) if _usable(dt) else ""


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
        log.warning("LNK: no usable timestamp in %s (blank or 1980/1601 placeholder dates); skipped", path)
        return []

    target = _target_path(info)
    drive_type = str(_find(info, "drive_type") or "")
    removable = "REMOVABLE" in drive_type.upper()
    size = header.get("file_size")
    # ntpath: target paths are Windows paths (backslashes) whatever OS we run on
    name = ntpath.basename(target) if target else ""
    if not name:  # drive root such as F:\ has no file name
        name = target or os.path.splitext(os.path.basename(path))[0]

    summary = "%s opened" % name
    if target and target != name:
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
                "target_created": _iso_or_blank(header.get("creation_time")),
                "target_accessed": _iso_or_blank(header.get("accessed_time")),
                "target_modified": _iso_or_blank(header.get("modified_time")),
                "accessed_date_only": bool(
                    _usable(_to_dt(header.get("accessed_time")))
                    and _is_date_only(_to_dt(header.get("accessed_time")))
                ),
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

    folder = os.path.join(evidence_dir, FOLDER)
    if not os.path.isdir(folder):
        log.warning("%s: folder not found: %s", SOURCE, folder)
        return []

    events = []
    for path in _find_lnk_files(folder):
        try:
            events.extend(_parse_one(path, evidence_dir))
        except Exception as exc:  # noqa: BLE001 - contract: never crash on a bad file
            log.warning("LNK: could not parse %s (%s)", path, exc)
    return events
