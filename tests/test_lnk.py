import os
import tempfile
import unittest
from datetime import datetime, timezone

from parsers import lnk


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

    # TODO (Day 4+): add a test on a real .lnk from the pen-drive step (S06)
    # that checks details["removable"] is True.


if __name__ == "__main__":
    unittest.main()
