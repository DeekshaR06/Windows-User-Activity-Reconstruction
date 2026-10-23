"""Recycle Bin parser (Member 3).

Public function: parse(evidence_dir) -> list[Event]

Parses every $I file (the small "info" file Windows writes when a file is
deleted). No external library needed, only struct.

$I layout (little endian):
  0-7    version (1 = Win7/8, 2 = Win10/11)
  8-15   original file size
  16-23  deletion time (FILETIME, UTC)
  v1: 24..543  original path, UTF-16, fixed 520 bytes
  v2: 24-27    path length in characters (incl. terminating null)
      28..     original path, UTF-16

Optional: put a file sid_map.json in the evidence folder to turn SIDs into
names, e.g. {"S-1-5-21-111-222-333-1001": "ravi"}.
"""
import json
import logging
import ntpath
import os
import struct
from datetime import datetime, timedelta, timezone
from core.timeutil import filetime_to_utc, to_iso
from core.schema import Event

log = logging.getLogger(__name__)

EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _filetime_to_iso(ft: int) -> str:
    return to_iso(filetime_to_utc(ft))


def parse_i_bytes(data: bytes):
    """Return (version, size_bytes, deletion_filetime, original_path). Raises ValueError if invalid."""
    if len(data) < 24:
        raise ValueError("file too short for a $I header")
    version, size, ft = struct.unpack_from("<QQQ", data, 0)
    if version == 1:
        raw = data[24:24 + 520]
    elif version == 2:
        if len(data) < 28:
            raise ValueError("truncated v2 header")
        (nchars,) = struct.unpack_from("<I", data, 24)
        if nchars > 32768:
            raise ValueError("unreasonable path length")
        raw = data[28:28 + nchars * 2]
    else:
        raise ValueError(f"unknown $I version {version}")
    year = (EPOCH + timedelta(microseconds=ft // 10)).year if ft else 0
    if not 2000 <= year <= 2100:
        raise ValueError(f"deletion time out of range (FILETIME={ft})")
    path = raw.decode("utf-16-le", errors="replace").split("\x00")[0]
    return version, size, ft, path


def _load_sid_map(evidence_dir: str) -> dict:
    p = os.path.join(evidence_dir, "sid_map.json")
    if os.path.isfile(p):
        try:
            with open(p, encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            log.warning("Could not read sid_map.json: %s", exc)
    return {}


def parse(evidence_dir: str) -> list:
    events = []
    sid_map = _load_sid_map(evidence_dir)
    for root, _dirs, files in os.walk(evidence_dir):
        for name in files:
            if not name.upper().startswith("$I"):
                continue
            path = os.path.join(root, name)
            rel = os.path.relpath(path, evidence_dir).replace("\\", "/")
            sid = os.path.basename(root)
            if not sid.upper().startswith("S-1-"):
                sid = ""
            try:
                with open(path, "rb") as f:
                    data = f.read()
                version, size, ft, orig = parse_i_bytes(data)
            except Exception as exc:  # never crash on a bad file
                log.warning("Skipping %s: %s", rel, exc)
                continue

            r_name = "$R" + name[2:]
            r_present = os.path.isfile(os.path.join(root, r_name))
            filename = ntpath.basename(orig) or orig
            user = sid_map.get(sid, sid)
            events.append(Event(
                timestamp_utc=_filetime_to_iso(ft),
                time_meaning="deleted",
                source="RecycleBin",
                event_type="FILE_DELETED",
                user=user,
                summary=f"{filename} deleted from {ntpath.dirname(orig) or orig}",
                details={"original_path": orig, "size_bytes": size, "sid": sid,
                         "recycle_name": name, "i_version": version, "r_file_present": r_present},
                evidence_file=rel,
            ))
    events.sort(key=lambda e: e.timestamp_utc)
    return events


if __name__ == "__main__":  # python -m parsers.recyclebin evidence/export
    import sys

    logging.basicConfig(level=logging.INFO)
    for e in parse(sys.argv[1]):
        print(e.timestamp_utc, e.user, "|", e.summary, e.details["size_bytes"])
