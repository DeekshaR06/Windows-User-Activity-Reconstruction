import csv
import os
import sqlite3
import tempfile
import unittest

from core import timeline
from core.schema import Event


def ev(ts, summary="x", source="Prefetch", etype="PROGRAM_EXECUTED", meaning="last_run"):
    return Event(timestamp_utc=ts, time_meaning=meaning, source=source,
                 event_type=etype, user="ravi", summary=summary)


class TimelineTests(unittest.TestCase):
    def test_sorted_by_time(self):
        out, _ = timeline.build([ev("2026-10-22T05:00:00Z", "b"), ev("2026-10-22T04:00:00Z", "a")])
        self.assertEqual([e.summary for e in out], ["a", "b"])

    def test_exact_duplicates_removed(self):
        a = ev("2026-10-22T04:00:00Z", "same")
        b = ev("2026-10-22T04:00:00Z", "same")
        out, stats = timeline.build([a, b])
        self.assertEqual(len(out), 1)
        self.assertEqual(stats["duplicates"], 1)

    def test_same_time_different_meaning_kept(self):
        a = ev("2026-10-22T04:00:00Z", "same", meaning="created")
        b = ev("2026-10-22T04:00:00Z", "same", meaning="modified")
        out, _ = timeline.build([a, b])
        self.assertEqual(len(out), 2)

    def test_invalid_events_reported_not_hidden(self):
        bad_time = ev("22/10/2026 10:00")
        bad_type = ev("2026-10-22T04:00:00Z", etype="DID_STUFF")
        bad_source = ev("2026-10-22T04:00:00Z", source="Registry")
        out, stats = timeline.build([bad_time, bad_type, bad_source, "not an event"])
        self.assertEqual(out, [])
        self.assertEqual(len(stats["invalid"]), 4)

    def test_csv_roundtrip_and_ist_column(self):
        e = ev("2026-10-22T04:30:00Z", "Notepad, with comma and ಕನ್ನಡ")
        e.details = {"run_count": 3}
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.csv")
            timeline.write_csv([e], p)
            with open(p, newline="", encoding="utf-8-sig") as fh:
                row = next(csv.DictReader(fh))
            self.assertEqual(row["timestamp_ist"], "2026-10-22 10:00:00")
            back = timeline.read_csv(p)[0]
            self.assertEqual(back.summary, e.summary)
            self.assertEqual(back.details, {"run_count": 3})
            self.assertTrue(back.is_valid())

    def test_sqlite_written(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "t.db")
            timeline.write_sqlite([ev("2026-10-22T04:00:00Z", "a"), ev("2026-10-22T05:00:00Z", "b")], p)
            con = sqlite3.connect(p)
            n = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            first = con.execute("SELECT summary FROM events ORDER BY timestamp_utc LIMIT 1").fetchone()[0]
            con.close()
            self.assertEqual((n, first), (2, "a"))


if __name__ == "__main__":
    unittest.main()
