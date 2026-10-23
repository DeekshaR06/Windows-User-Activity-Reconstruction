"""Extra tests for parsers/recyclebin.py: bad headers, ordering, SID mapping, unicode, contract."""
import json
import re
import struct
from datetime import datetime, timezone

import pytest

from parsers.recyclebin import parse, parse_i_bytes

SID = "S-1-5-21-1-2-3-1001"
ISO_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _ft(dt):
    return int((dt - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds()) * 10_000_000


def _v2(path, size=10, when=datetime(2026, 10, 22, 5, 11, 9, tzinfo=timezone.utc)):
    raw = (path + "\x00").encode("utf-16-le")
    return struct.pack("<QQQI", 2, size, _ft(when), len(path) + 1) + raw


def _put(tmp_path, name, content, sid=SID):
    d = tmp_path / "$Recycle.Bin" / sid
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_bytes(content)
    return d


# ------------------------------------------------------------- header checks
def test_unknown_version_rejected():
    with pytest.raises(ValueError):
        parse_i_bytes(struct.pack("<QQQ", 5, 1, _ft(datetime(2026, 1, 1, tzinfo=timezone.utc))) + b"\x00" * 600)


def test_zero_deletion_time_rejected():
    with pytest.raises(ValueError):
        parse_i_bytes(struct.pack("<QQQI", 2, 1, 0, 2) + "a\x00".encode("utf-16-le"))


def test_huge_path_length_rejected(tmp_path):
    _put(tmp_path, "$IBIG000.txt",
         struct.pack("<QQQI", 2, 1, _ft(datetime(2026, 1, 1, tzinfo=timezone.utc)), 100000))
    assert parse(str(tmp_path)) == []


def test_parse_i_bytes_values():
    version, size, ft, path = parse_i_bytes(_v2(r"C:\a\b.txt", size=4096))
    assert (version, size, path) == (2, 4096, r"C:\a\b.txt")


# ------------------------------------------------------------------ parse()
def test_non_i_files_ignored(tmp_path):
    _put(tmp_path, "$RABC123.txt", b"file content")
    _put(tmp_path, "desktop.ini", b"x")
    assert parse(str(tmp_path)) == []


def test_missing_r_file_flagged(tmp_path):
    _put(tmp_path, "$IABC123.txt", _v2(r"C:\Users\ravi\Documents\a.txt"))
    assert parse(str(tmp_path))[0].details["r_file_present"] is False


def test_events_sorted_by_time(tmp_path):
    late = datetime(2026, 10, 22, 6, 0, 0, tzinfo=timezone.utc)
    early = datetime(2026, 10, 22, 5, 0, 0, tzinfo=timezone.utc)
    _put(tmp_path, "$ILATE01.txt", _v2(r"C:\late.txt", when=late))
    _put(tmp_path, "$IEARLY1.txt", _v2(r"C:\early.txt", when=early))
    ev = parse(str(tmp_path))
    assert [e.details["original_path"] for e in ev] == [r"C:\early.txt", r"C:\late.txt"]


def test_sid_map_gives_user_name(tmp_path):
    _put(tmp_path, "$IABC123.txt", _v2(r"C:\Users\ravi\Documents\a.txt"))
    (tmp_path / "sid_map.json").write_text(json.dumps({SID: "ravi"}))
    assert parse(str(tmp_path))[0].user == "ravi"


def test_unicode_file_name(tmp_path):
    _put(tmp_path, "$IUNI001.txt", _v2("C:\\Users\\ravi\\Documents\\ವರದಿ.txt"))
    assert parse(str(tmp_path))[0].summary.startswith("ವರದಿ.txt deleted from")


def test_event_follows_contract(tmp_path):
    _put(tmp_path, "$IABC123.txt", _v2(r"C:\Users\ravi\Documents\salary_report.txt", size=1234))
    e = parse(str(tmp_path))[0]
    assert ISO_RE.match(e.timestamp_utc)
    assert (e.source, e.event_type, e.time_meaning) == ("RecycleBin", "FILE_DELETED", "deleted")
    assert e.summary == r"salary_report.txt deleted from C:\Users\ravi\Documents"
    assert e.evidence_file.endswith("$IABC123.txt")
