import csv
import os
import tempfile
import unittest

from analysis import evidence_check, validate

TEMPLATE = os.path.join(os.path.dirname(__file__), "..", "validation", "detection_table_template.csv")


def tl(ist, etype, source, summary="x"):
    return {"timestamp_ist": ist, "event_type": etype, "source": source, "summary": summary}


def step(sid, ist, etype, source):
    return {"step": sid, "time_ist": ist, "action": "a", "expected_event_type": etype, "expected_source": source}


class CompareTests(unittest.TestCase):
    def test_found_within_window_with_signed_difference(self):
        r = validate.compare([step("S05", "2026-10-23 10:31:22", "USB_CONNECTED", "USB")],
                             [tl("2026-10-23 10:31:47", "USB_CONNECTED", "USB")])[0]
        self.assertEqual((r["found_yes_no"], r["time_difference_seconds"]), ("Yes", "25"))

    def test_wrong_source_is_not_a_match(self):
        r = validate.compare([step("S08", "2026-10-23 10:41:09", "FILE_DELETED", "RecycleBin")],
                             [tl("2026-10-23 10:41:09", "FILE_DELETED", "Browser")])[0]
        self.assertEqual(r["found_yes_no"], "No")

    def test_closest_event_wins_and_others_are_counted(self):
        r = validate.compare([step("S08", "2026-10-23 10:41:09", "FILE_DELETED", "RecycleBin")],
                             [tl("2026-10-23 10:41:30", "FILE_DELETED", "RecycleBin"),
                              tl("2026-10-23 10:41:10", "FILE_DELETED", "RecycleBin")])[0]
        self.assertEqual(r["time_in_timeline_ist"], "2026-10-23 10:41:10")
        self.assertIn("1 more", r["notes"])

    def test_no_event_of_that_type(self):
        r = validate.compare([step("S10", "2026-10-23 10:44:30", "LOG_CLEARED", "EventLog")], [])[0]
        self.assertEqual(r["found_yes_no"], "No")
        self.assertIn("no LOG_CLEARED", r["notes"])

    def test_timezone_mistake_is_hinted(self):
        r = validate.compare([step("S10", "2026-10-23 10:44:30", "LOG_CLEARED", "EventLog")],
                             [tl("2026-10-23 16:14:30", "LOG_CLEARED", "EventLog")])[0]
        self.assertEqual(r["found_yes_no"], "No")
        self.assertIn("time-zone", r["notes"])

    def test_blank_time_is_skipped_not_failed(self):
        r = validate.compare([step("S01", "", "USER_LOGON", "EventLog")], [])[0]
        self.assertEqual(r["found_yes_no"], "")
        self.assertIn("not checked", r["notes"])
        self.assertEqual(validate.summary([r]), "0 of 0 checked steps found (0%); 1 skipped (no time)")

    def test_summary_counts(self):
        rows = validate.compare([step("A", "2026-10-23 10:00:00", "USER_LOGON", "EventLog"),
                                 step("B", "2026-10-23 11:00:00", "USER_LOGOFF", "EventLog"),
                                 step("C", "", "SYSTEM_START", "EventLog")],
                                [tl("2026-10-23 10:00:05", "USER_LOGON", "EventLog")])
        self.assertEqual(validate.summary(rows), "1 of 2 checked steps found (50%); 1 skipped (no time)")

    def test_output_columns_match_the_detection_table_template(self):
        with open(TEMPLATE, newline="", encoding="utf-8-sig") as fh:
            self.assertEqual(next(csv.reader(fh)), validate.COLUMNS)

    def test_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            truth, timeline, out = (os.path.join(d, n) for n in ("t.csv", "tl.csv", "o.csv"))
            with open(truth, "w", newline="", encoding="utf-8-sig") as fh:
                w = csv.DictWriter(fh, fieldnames=["step", "time_ist", "action", "expected_event_type", "expected_source"])
                w.writeheader()
                w.writerow(step("S05", "2026-10-23 10:31:22", "USB_CONNECTED", "USB"))
            with open(timeline, "w", newline="", encoding="utf-8-sig") as fh:
                w = csv.DictWriter(fh, fieldnames=["timestamp_ist", "event_type", "source", "summary"])
                w.writeheader()
                w.writerow(tl("2026-10-23 10:31:22", "USB_CONNECTED", "USB"))
            self.assertEqual(validate.main(["--truth", truth, "--timeline", timeline, "--out", out]), 0)
            with open(out, newline="", encoding="utf-8-sig") as fh:
                rows = list(csv.DictReader(fh))
            self.assertEqual(rows[0]["found_yes_no"], "Yes")
            self.assertEqual(validate.main(["--truth", os.path.join(d, "nope.csv"), "--timeline", timeline]), 2)


class EvidenceCheckTests(unittest.TestCase):
    def test_missing_empty_and_ok(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "prefetch"))                 # lower-case folder name still counts
            open(os.path.join(d, "prefetch", "NOTEPAD.EXE-1.PF"), "w").close()
            os.makedirs(os.path.join(d, "Logs"))                     # empty
            res = {r["folder"]: r for r in evidence_check.check(d)}
        self.assertEqual(res["Prefetch"]["status"], "ok")
        self.assertEqual(res["Logs"]["status"], "empty")
        self.assertEqual(res["Browser"]["status"], "missing")

    def test_recycle_bin_files_inside_a_sid_subfolder_are_found(self):
        with tempfile.TemporaryDirectory() as d:
            sid = os.path.join(d, "RecycleBin", "S-1-5-21-1")
            os.makedirs(sid)
            open(os.path.join(sid, "$IABC123.txt"), "w").close()
            res = {r["folder"]: r for r in evidence_check.check(d)}
        self.assertEqual(res["RecycleBin"]["count"], 1)

    def test_registry_notes_missing_setupapi_log(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "Registry"))
            open(os.path.join(d, "Registry", "SYSTEM"), "w").close()
            res = {r["folder"]: r for r in evidence_check.check(d)}
        self.assertEqual(res["Registry"]["status"], "ok")
        self.assertIn("setupapi", res["Registry"]["extra"])

    def test_report_lines_name_the_owner(self):
        with tempfile.TemporaryDirectory() as d:
            text = "\n".join(evidence_check.report_lines(evidence_check.check(d)))
        self.assertIn("MISSING", text)
        self.assertIn("Member 3", text)

    def test_missing_evidence_folder_returns_error_code(self):
        self.assertEqual(evidence_check.main([os.path.join(tempfile.gettempdir(), "no-such-folder-xyz")]), 2)


if __name__ == "__main__":
    unittest.main()
