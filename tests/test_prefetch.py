import os
import tempfile
import unittest

from parsers import prefetch


class PrefetchParserTest(unittest.TestCase):
    def test_empty_folder_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(prefetch.parse(d), [])

    def test_corrupt_file_does_not_crash(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "Prefetch"))
            with open(os.path.join(d, "Prefetch", "BAD.EXE-00000000.pf"), "wb") as f:
                f.write(b"this is not a prefetch file")
            self.assertEqual(prefetch.parse(d), [])

    # TODO (Day 3+): once you have real .pf files from Member 1's export, add a
    # test that parses one and checks the event_type, run_count and UTC time.


if __name__ == "__main__":
    unittest.main()
