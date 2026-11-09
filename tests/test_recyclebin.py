import struct
from datetime import datetime, timezone

from parsers.recyclebin import parse

SID = "S-1-5-21-1-2-3-1001"
WHEN = datetime(2026, 10, 22, 5, 11, 9, tzinfo=timezone.utc)


def _ft(dt):
    return int((dt - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds()) * 10_000_000


def _v2(path, size):
    raw = (path + "\x00").encode("utf-16-le")
    return struct.pack("<QQQI", 2, size, _ft(WHEN), len(path) + 1) + raw


def _v1(path, size):
    raw = (path + "\x00").encode("utf-16-le").ljust(520, b"\x00")
    return struct.pack("<QQQ", 1, size, _ft(WHEN)) + raw


def _setup(tmp_path, name, content):
    d = tmp_path / "$Recycle.Bin" / SID
    d.mkdir(parents=True)
    (d / name).write_bytes(content)
    return d


def test_version2(tmp_path):
    d = _setup(tmp_path, "$IABC123.txt", _v2(r"C:\Users\ravi\Documents\salary_report.txt", 1234))
    (d / "$RABC123.txt").write_text("x")
    ev = parse(str(tmp_path))
    assert len(ev) == 1
    e = ev[0]
    assert e.event_type == "FILE_DELETED" and e.source == "RecycleBin"
    assert e.timestamp_utc == "2026-10-22T05:11:09Z"
    assert e.details["size_bytes"] == 1234
    assert e.details["original_path"].endswith("salary_report.txt")
    assert e.details["r_file_present"] is True
    assert e.user == SID


def test_version1(tmp_path):
    _setup(tmp_path, "$IXYZ999.csv", _v1(r"C:\Users\ravi\Documents\client_list.csv", 99))
    ev = parse(str(tmp_path))
    assert len(ev) == 1 and ev[0].details["i_version"] == 1


def test_corrupt_file_does_not_crash(tmp_path):
    _setup(tmp_path, "$IBAD000.txt", b"junk")
    assert parse(str(tmp_path)) == []