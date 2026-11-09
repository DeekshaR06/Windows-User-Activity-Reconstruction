import os
import tempfile
import unittest
from datetime import datetime, timezone

from parsers import lnk
from tests.lnk_builder import DRIVE_FIXED, DRIVE_REMOVABLE, build_lnk


class LnkParserTest(unittest.TestCase):
    def test_empty_folder_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(lnk.parse(d), [])

    def test_corrupt_file_does_not_crash(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "Recent"))
            with open(os.path.join(d, "Recent", "bad.lnk"), "wb") as f:
                f.write(b"not a shortcut")
            self.assertEqual(lnk.parse(d), [])

    def test_unset_time_is_ignored(self):
        header = {"accessed_time": datetime(1601, 1, 1), "modified_time": datetime(2026, 10, 22, 5, 1, 20, tzinfo=timezone.utc)}
        dt, meaning = lnk._pick_time(header)
        self.assertEqual(meaning, "modified_time")
        self.assertEqual(dt.year, 2026)

    def test_target_path_is_joined(self):
        info = {"data": {"location_info": {"local_base_path": "E:\\", "common_path_suffix": "client_list.csv"}}}
        self.assertEqual(lnk._target_path(info), "E:\\client_list.csv")

    def _parse_built(self, base, suffix, drive_type):
        when = datetime(2026, 10, 22, 5, 1, 20, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "Recent"))
            with open(os.path.join(d, "Recent", "x.lnk"), "wb") as f:
                f.write(build_lnk(base, suffix, when, drive_type=drive_type))
            return lnk.parse(d)

    def test_pen_drive_shortcut_is_flagged_removable(self):
        events = self._parse_built("E:\\", "client_list.csv", DRIVE_REMOVABLE)
        self.assertEqual(len(events), 1)
        e = events[0]
        self.assertTrue(e.is_valid(), e.problems())
        self.assertEqual(e.event_type, "FILE_OPENED")
        self.assertEqual(e.timestamp_utc, "2026-10-22T05:01:20Z")
        self.assertEqual(e.details["target_path"], "E:\\client_list.csv")
        self.assertTrue(e.details["removable"])
        self.assertIn("REMOVABLE", e.summary)
        self.assertEqual(e.evidence_file, "Recent/x.lnk")
        self.assertEqual(e.summary.count("client_list.csv"), 2)  # name + path, no more

    def _parse_times(self, base, suffix, drive_type, accessed, created=None, modified=None,
                     shortcut_time=None):
        """shortcut_time pins the .lnk file's OWN modified time (what Windows writes when
        the file is opened). None = leave it as 'now' (time of the test)."""
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "Recent"))
            path = os.path.join(d, "Recent", "x.lnk")
            with open(path, "wb") as f:
                f.write(build_lnk(base, suffix, accessed, drive_type=drive_type,
                                  created=created, modified=modified))
            if shortcut_time is not None:
                ts = shortcut_time.timestamp()
                os.utime(path, (ts, ts))
            return lnk.parse(d)

    def test_usb_shortcut_uses_the_shortcut_files_own_time(self):
        # FAT/exFAT: "accessed" is the date only (midnight IST) and "modified" is when the
        # file was last SAVED on the stick. The real moment of opening is the time Windows
        # wrote the shortcut in Recent (here 14:11 IST = 08:41 UTC).
        accessed = datetime(2026, 10, 30, 18, 30, 0, tzinfo=timezone.utc)
        modified = datetime(2026, 11, 1, 8, 27, 18, tzinfo=timezone.utc)
        opened = datetime(2026, 11, 1, 8, 41, 0, tzinfo=timezone.utc)
        events = self._parse_times("F:\\", "client_list.csv", DRIVE_REMOVABLE, accessed,
                                   modified=modified, shortcut_time=opened)
        e = events[0]
        self.assertEqual(e.timestamp_utc, "2026-11-01T08:41:00Z")
        self.assertEqual(e.time_meaning, "shortcut_file_modified")
        self.assertTrue(e.details["accessed_date_only"])
        self.assertEqual(e.details["target_accessed"], "2026-10-30T18:30:00Z")  # kept for checking
        self.assertEqual(e.details["target_modified"], "2026-11-01T08:27:18Z")

    def test_usb_date_only_accessed_time_falls_back_to_modified(self):
        # If the shortcut file's own time is unusable (1980 placeholder), fall back to the
        # target's modified time as before.
        accessed = datetime(2026, 10, 30, 18, 30, 0, tzinfo=timezone.utc)
        modified = datetime(2026, 11, 1, 8, 27, 18, tzinfo=timezone.utc)
        placeholder = datetime(1980, 1, 1, tzinfo=timezone.utc)
        events = self._parse_times("F:\\", "client_list.csv", DRIVE_REMOVABLE, accessed,
                                   modified=modified, shortcut_time=placeholder)
        e = events[0]
        self.assertEqual(e.timestamp_utc, "2026-11-01T08:27:18Z")
        self.assertEqual(e.time_meaning, "target_modified_time")
        self.assertTrue(e.details["accessed_date_only"])

    def test_precise_accessed_time_is_used_on_normal_disk(self):
        accessed = datetime(2026, 11, 1, 8, 26, 30, 225960, tzinfo=timezone.utc)
        events = self._parse_times("C:\\Users\\ravi\\Documents\\", "salary_report.txt", DRIVE_FIXED, accessed)
        self.assertEqual(events[0].timestamp_utc, "2026-11-01T08:26:30Z")
        self.assertEqual(events[0].time_meaning, "target_accessed_time")
        self.assertFalse(events[0].details["accessed_date_only"])

    def test_1980_placeholder_time_is_not_a_real_time(self):
        # no usable time anywhere (target times and the shortcut file's own time) -> skipped
        zero = datetime(1979, 12, 31, 18, 30, 0, tzinfo=timezone.utc)  # 1980-01-01 00:00 IST
        placeholder = datetime(1980, 1, 1, tzinfo=timezone.utc)
        self.assertEqual(self._parse_times("F:\\", "", DRIVE_REMOVABLE, zero,
                                           shortcut_time=placeholder), [])

    def test_usb_drive_shortcut_with_blank_target_times_uses_shortcut_time(self):
        # like "USB Drive (F).lnk": blank target dates, but Windows wrote the shortcut at 14:11 IST
        zero = datetime(1979, 12, 31, 18, 30, 0, tzinfo=timezone.utc)
        opened = datetime(2026, 11, 1, 8, 41, 0, tzinfo=timezone.utc)
        events = self._parse_times("F:\\", "", DRIVE_REMOVABLE, zero, shortcut_time=opened)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].timestamp_utc, "2026-11-01T08:41:00Z")
        self.assertEqual(events[0].time_meaning, "shortcut_file_modified")

    def test_drive_root_summary_has_no_empty_name(self):
        accessed = datetime(2026, 11, 1, 8, 30, 1, 500000, tzinfo=timezone.utc)
        e = self._parse_times("F:\\", "", DRIVE_REMOVABLE, accessed)[0]
        self.assertTrue(e.summary.startswith("F:\\ opened"), e.summary)
        self.assertIn("REMOVABLE", e.summary)

    def test_normal_disk_shortcut_is_not_flagged(self):
        events = self._parse_built("C:\\Users\\ravi\\Documents\\", "notes.txt", DRIVE_FIXED)
        self.assertFalse(events[0].details["removable"])
        self.assertNotIn("REMOVABLE", events[0].summary)


if __name__ == "__main__":
    unittest.main()