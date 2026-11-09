"""Tests for the --help / --csv command line of both parsers."""
import csv
import struct
from datetime import datetime, timezone

import pytest

from parsers import evtx, recyclebin


def _ft(dt):
    return int((dt - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds()) * 10_000_000


@pytest.mark.parametrize("module", [evtx, recyclebin])
def test_help_exits_cleanly(module, capsys):
    with pytest.raises(SystemExit) as exc:
        module.main(["--help"])
    assert exc.value.code == 0
    assert "evidence_dir" in capsys.readouterr().out


def test_recyclebin_cli_writes_csv(tmp_path, capsys):
    d = tmp_path / "$Recycle.Bin" / "S-1-5-21-1-2-3-1001"
    d.mkdir(parents=True)
    path = r"C:\Users\ravi\Documents\salary_report.txt"
    raw = (path + "\x00").encode("utf-16-le")
    when = datetime(2026, 10, 22, 5, 11, 9, tzinfo=timezone.utc)
    (d / "$IABC123.txt").write_bytes(struct.pack("<QQQI", 2, 1234, _ft(when), len(path) + 1) + raw)

    out = tmp_path / "deleted.csv"
    assert recyclebin.main([str(tmp_path), "--csv", str(out)]) == 0
    assert "1 deleted files" in capsys.readouterr().out
    rows = list(csv.DictReader(out.open(encoding="utf-8")))
    assert rows[0]["deleted_utc"] == "2026-10-22T05:11:09Z"
    assert rows[0]["size_bytes"] == "1234"


def test_evtx_cli_on_empty_folder(tmp_path, capsys):
    out = tmp_path / "events.csv"
    assert evtx.main([str(tmp_path), "--csv", str(out)]) == 0
    assert "0 events" in capsys.readouterr().out
    assert out.read_text(encoding="utf-8").startswith("timestamp_utc,")
